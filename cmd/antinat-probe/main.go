// antinat-probe is the operator-owned WAN probe vantage service (P10).
//
// It receives controller-signed probe requests, performs the WAN1/ACK1
// exchange against the exact global IPv4 literal, and returns a
// provider-signed result. It holds no persistent business state: only a TTL
// nonce replay cache, a concurrency bound, and an audit summary.
//
// Config (strict JSON, mirrors internal/config conventions):
//
//	{
//	  "listen_address": "0.0.0.0:3120",
//	  "controller_public_key": "<hex ed25519>",   // REQUIRED pin
//	  "provider_key_file": "/etc/antinat/probe.key", // REQUIRED 0600
//	  "max_concurrent": 8
//	}
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gxbrave/AntiNAT/internal/controller/probe"
)

// providerConfig is the strict-JSON provider config.
type providerConfig struct {
	ListenAddress    string `json:"listen_address"`
	ControllerPubKey string `json:"controller_public_key"`
	ProviderKeyFile  string `json:"provider_key_file"`
	MaxConcurrent    int    `json:"max_concurrent"`
}

func (c *providerConfig) validate() error {
	if c.ListenAddress == "" {
		c.ListenAddress = "0.0.0.0:3120"
	}
	if c.ControllerPubKey == "" {
		return errors.New("config: controller_public_key is required")
	}
	if c.ProviderKeyFile == "" {
		return errors.New("config: provider_key_file is required")
	}
	return nil
}

func main() {
	configPath := flag.String("config", "", "provider config file (strict JSON)")
	flag.Parse()
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "antinat-probe: -config is required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "antinat-probe: read config: %v\n", err)
		os.Exit(1)
	}
	var cfg providerConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-probe: config: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-probe: %v\n", err)
		os.Exit(1)
	}
	ctrlPub, err := hex.DecodeString(cfg.ControllerPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "antinat-probe: controller_public_key is not hex: %v\n", err)
		os.Exit(1)
	}
	provKey, err := loadProviderPrivateKey(cfg.ProviderKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "antinat-probe: provider key: %v\n", err)
		os.Exit(1)
	}

	provider, err := probe.NewProvider(probe.ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provKey,
		MaxConcurrent:       cfg.MaxConcurrent,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "antinat-probe: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{Addr: cfg.ListenAddress, Handler: provider.Handler()}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	fmt.Printf("antinat-probe: listening on %s\n", cfg.ListenAddress)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		fmt.Println("antinat-probe: shutting down")
		_ = srv.Close()
	case err := <-errCh:
		fmt.Fprintf(os.Stderr, "antinat-probe: serve: %v\n", err)
		os.Exit(1)
	}
}

// loadProviderPrivateKey loads the exact operator-configured key file. The
// file uses the same ANKC envelope as the security keyring, but unlike the
// controller helper this function never substitutes a directory default.
func loadProviderPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("key file must be a regular non-symlink file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("key file mode %o is not 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if len(raw) != 4+8+ed25519.PrivateKeySize || string(raw[:4]) != "ANKC" {
		return nil, errors.New("key file has invalid ANKC format")
	}
	if generation := binary.BigEndian.Uint64(raw[4:12]); generation != 1 {
		return nil, fmt.Errorf("key file generation %d is unsupported", generation)
	}
	return ed25519.PrivateKey(append([]byte(nil), raw[12:]...)), nil
}
