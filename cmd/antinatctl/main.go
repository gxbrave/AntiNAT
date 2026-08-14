// antinatctl is the minimal admin CLI (P10 Story 4).
//
// Secret-safe by construction (docs/protocol.md §4.4.7): passwords are read
// from a hidden TTY prompt or a strict-ACL --password-file; the session
// cookie is stored in a 0600 file; enrollment tokens are printed exactly
// once and never logged.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

const sessionFile = "session"

// client is a minimal API client with cookie persistence.
type client struct {
	baseURL string
	jar     map[string][]*http.Cookie
	hc      *http.Client
	state   string // session storage dir
}

func newClient(baseURL, stateDir string) *client {
	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		jar:     map[string][]*http.Cookie{},
		hc:      &http.Client{Timeout: 15 * time.Second},
		state:   stateDir,
	}
}

func (c *client) do(method, path string, body any, headers map[string]string) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, cookie := range c.jar[c.baseURL] {
		req.AddCookie(cookie)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if set := resp.Cookies(); len(set) > 0 {
		c.jar[c.baseURL] = set
		c.saveSession()
	}
	return resp.StatusCode, data, nil
}

// saveSession persists cookies to a 0600 file.
func (c *client) saveSession() {
	if c.state == "" {
		return
	}
	if err := os.MkdirAll(c.state, 0o700); err != nil {
		return
	}
	var buf bytes.Buffer
	for _, cookie := range c.jar[c.baseURL] {
		fmt.Fprintf(&buf, "%s=%s\n", cookie.Name, cookie.Value)
	}
	path := filepath.Join(c.state, sessionFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// loadSession restores cookies from the 0600 file.
func (c *client) loadSession() {
	if c.state == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(c.state, sessionFile))
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			c.jar[c.baseURL] = append(c.jar[c.baseURL], &http.Cookie{Name: parts[0], Value: parts[1]})
		}
	}
}

// readPassword reads a password from a hidden TTY prompt or a 0600 file.
func readPassword(prompt, passwordFile string) (string, error) {
	if passwordFile != "" {
		info, err := os.Stat(passwordFile)
		if err != nil {
			return "", fmt.Errorf("password file: %w", err)
		}
		if info.Mode().Perm() != 0o600 {
			return "", errors.New("password file must have mode 0600")
		}
		raw, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	defer fmt.Fprintln(os.Stderr)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "antinatctl: %v\n", err)
	os.Exit(1)
}

func main() {
	baseURL := flag.String("endpoint", "http://127.0.0.1:3111", "controller base URL")
	stateDir := flag.String("state", envOr("ANTINATCTL_STATE", defaultStateDir()), "session storage dir")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "antinatctl — AntiNAT minimal admin CLI\n\nUsage: antinatctl [--endpoint URL] <command> [args]\n\nCommands:\n  admin init [--username U] [--password-file F]   create the first admin\n  login --username U [--password-file F]           store a session\n  node create [--name N]                           create a node\n  node token <node-id>                             issue a one-time enrollment token\n  node list                                        list nodes\n  forward create --node N --name X --protocol tcp --target H:PORT --strategy S\n  forward list                                     list forwards\n  forward status <forward-id>                      show one forward\n  forward update <forward-id> --target H:PORT      hot-update target (If-Match)\n  forward delete <forward-id>                      online delete (If-Match)\n  status                                           controller healthz/readyz\n\nSecrets: passwords come from a hidden TTY prompt or a 0600 --password-file;\nthe session cookie is stored 0600; tokens are printed once.\n")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	c := newClient(*baseURL, *stateDir)
	c.loadSession()
	if err := run(c, args); err != nil {
		fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return os.TempDir()
	}
	return filepath.Join(home, ".antinat")
}

func run(c *client, args []string) error {
	switch args[0] {
	case "admin":
		return runAdmin(c, args[1:])
	case "login":
		return runLogin(c, args[1:])
	case "node":
		return runNode(c, args[1:])
	case "forward":
		return runForward(c, args[1:])
	case "status":
		return runStatus(c)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// --- admin ---

func runAdmin(c *client, args []string) error {
	if len(args) == 0 {
		return errors.New("admin requires a subcommand (init)")
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("admin init", flag.ExitOnError)
		username := fs.String("username", "admin", "admin username")
		passwordFile := fs.String("password-file", "", "0600 file with the password (default: generate)")
		fs.Parse(args[1:])
		if *passwordFile != "" {
			password, err := readPassword("", *passwordFile)
			if err != nil {
				return err
			}
			return c.adminInit(*username, password)
		}
		password := randomSecret(24)
		if err := c.adminInit(*username, password); err != nil {
			return err
		}
		fmt.Printf("admin %q created. One-time password (shown once):\n%s\n", *username, password)
		return nil
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func (c *client) adminInit(username, password string) error {
	status, body, err := c.do(http.MethodPost, "/api/v1/auth/init", map[string]string{
		"username": username, "password": password,
	}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("admin init failed (status %d): %s", status, body)
	}
	return nil
}

// --- login ---

func runLogin(c *client, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	username := fs.String("username", "", "admin username")
	passwordFile := fs.String("password-file", "", "0600 file with the password")
	fs.Parse(args)
	if *username == "" {
		return errors.New("login requires --username")
	}
	password, err := readPassword("Password: ", *passwordFile)
	if err != nil {
		return err
	}
	status, body, err := c.do(http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": *username, "password": password,
	}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("login failed (status %d): %s", status, body)
	}
	fmt.Println("logged in")
	return nil
}

// --- node ---

func runNode(c *client, args []string) error {
	if len(args) == 0 {
		return errors.New("node requires a subcommand (create|token|list)")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("node create", flag.ExitOnError)
		name := fs.String("name", "", "node name (default: generated)")
		fs.Parse(args[1:])
		status, body, err := c.do(http.MethodPost, "/api/v1/nodes", map[string]any{"name": *name}, map[string]string{
			"Idempotency-Key": "cli-" + randomSecret(12),
		})
		if err != nil {
			return err
		}
		if status != http.StatusCreated {
			return fmt.Errorf("node create failed (status %d): %s", status, body)
		}
		fmt.Println(string(body))
		return nil
	case "token":
		if len(args) != 2 {
			return errors.New("node token requires <node-id>")
		}
		status, body, err := c.do(http.MethodPost, "/api/v1/nodes/"+args[1]+"/enrollment-token", nil, nil)
		if err != nil {
			return err
		}
		if status != http.StatusCreated {
			return fmt.Errorf("token failed (status %d): %s", status, body)
		}
		var tok struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(body, &tok)
		fmt.Printf("One-time enrollment token (shown once):\n%s\n", tok.Token)
		return nil
	case "list":
		status, body, err := c.do(http.MethodGet, "/api/v1/nodes", nil, nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("node list failed (status %d): %s", status, body)
		}
		fmt.Println(string(body))
		return nil
	default:
		return fmt.Errorf("unknown node subcommand %q", args[0])
	}
}

// --- forward ---

func runForward(c *client, args []string) error {
	if len(args) == 0 {
		return errors.New("forward requires a subcommand (create|list|status|update|delete)")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("forward create", flag.ExitOnError)
		nodeID := fs.String("node", "", "node id")
		name := fs.String("name", "", "forward name")
		protocol := fs.String("protocol", "tcp", "protocol (tcp)")
		target := fs.String("target", "", "target IPv4:port")
		strategy := fs.String("strategy", "direct-v4", "strategy")
		fs.Parse(args[1:])
		if *nodeID == "" || *name == "" || *target == "" {
			return errors.New("forward create requires --node --name --target")
		}
		status, body, err := c.do(http.MethodPost, "/api/v1/forwards", map[string]any{
			"node_id": *nodeID, "name": *name, "protocol": *protocol,
			"target": *target, "strategy": *strategy,
		}, map[string]string{"Idempotency-Key": "cli-" + randomSecret(12)})
		if err != nil {
			return err
		}
		if status != http.StatusCreated {
			return fmt.Errorf("forward create failed (status %d): %s", status, body)
		}
		fmt.Println(string(body))
		return nil
	case "list":
		status, body, err := c.do(http.MethodGet, "/api/v1/forwards", nil, nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("forward list failed (status %d): %s", status, body)
		}
		fmt.Println(string(body))
		return nil
	case "status":
		if len(args) != 2 {
			return errors.New("forward status requires <forward-id>")
		}
		status, body, err := c.do(http.MethodGet, "/api/v1/forwards/"+args[1], nil, nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("forward status failed (status %d): %s", status, body)
		}
		fmt.Println(string(body))
		return nil
	case "update":
		if len(args) < 2 {
			return errors.New("forward update requires <forward-id> --target H:PORT")
		}
		fs := flag.NewFlagSet("forward update", flag.ExitOnError)
		target := fs.String("target", "", "new target IPv4:port")
		fs.Parse(args[2:])
		if *target == "" {
			return errors.New("forward update requires --target")
		}
		etag, err := c.forwardETag(args[1])
		if err != nil {
			return err
		}
		status, body, err := c.do(http.MethodPatch, "/api/v1/forwards/"+args[1],
			map[string]any{"target": *target}, map[string]string{"If-Match": etag})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("forward update failed (status %d): %s", status, body)
		}
		fmt.Println(string(body))
		return nil
	case "delete":
		if len(args) != 2 {
			return errors.New("forward delete requires <forward-id>")
		}
		etag, err := c.forwardETag(args[1])
		if err != nil {
			return err
		}
		status, body, err := c.do(http.MethodDelete, "/api/v1/forwards/"+args[1], nil, map[string]string{"If-Match": etag})
		if err != nil {
			return err
		}
		if status != http.StatusAccepted {
			return fmt.Errorf("forward delete failed (status %d): %s", status, body)
		}
		var op struct {
			OperationID string `json:"operation_id"`
		}
		_ = json.Unmarshal(body, &op)
		fmt.Printf("delete accepted: %s\n", op.OperationID)
		return nil
	default:
		return fmt.Errorf("unknown forward subcommand %q", args[0])
	}
}

func (c *client) forwardETag(forwardID string) (string, error) {
	status, body, err := c.do(http.MethodGet, "/api/v1/forwards/"+forwardID, nil, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("forward read failed (status %d): %s", status, body)
	}
	var fwd struct {
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal(body, &fwd); err != nil || fwd.ETag == "" {
		return "", fmt.Errorf("forward etag missing: %s", body)
	}
	return fwd.ETag, nil
}

// --- status ---

func runStatus(c *client) error {
	for _, path := range []string{"/healthz", "/readyz"} {
		status, body, err := c.do(http.MethodGet, path, nil, nil)
		if err != nil {
			return err
		}
		fmt.Printf("%s -> %d %s\n", path, status, body)
	}
	return nil
}

func randomSecret(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err == nil {
		return hex.EncodeToString(raw)[:n]
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(sum[:])[:n]
}
