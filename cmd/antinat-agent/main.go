// antinat-agent is the composed Agent process (P10 Story 5).
//
// Flags and environment (all optional; the walking skeleton and real
// deployments set them explicitly):
//
//	-state      ANTINAT_STATE      agent localstate dir (default ./var/agent)
//	-endpoint   ANTINAT_ENDPOINT   controller base URL (required)
//	-node       ANTINAT_NODE       node id (required)
//	-token-file ANTINAT_TOKEN      one-time enrollment token file (0600; omit when already enrolled)
//	-pin        ANTINAT_PIN        pinned controller public key hex (required for enrollment)
//
// SIGINT/SIGTERM trigger an ordered graceful shutdown (control client,
// data plane, store).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent"
	"github.com/gxbrave/AntiNAT/internal/buildinfo"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("antinat-agent %s\n", buildinfo.Format(buildinfo.Current()))
		return
	}
	stateDir := flag.String("state", envOr("ANTINAT_STATE", filepath.Join("var", "agent")), "agent state dir")
	endpoint := flag.String("endpoint", envOr("ANTINAT_ENDPOINT", ""), "controller base URL")
	nodeID := flag.String("node", envOr("ANTINAT_NODE", ""), "node id")
	tokenFile := flag.String("token-file", envOr("ANTINAT_TOKEN_FILE", ""), "one-time enrollment token file (0600)")
	pinHex := flag.String("pin", envOr("ANTINAT_PIN", ""), "pinned controller public key (hex)")
	flag.Parse()

	if *endpoint == "" || *nodeID == "" {
		fmt.Fprintln(os.Stderr, "antinat-agent: --endpoint and --node are required")
		os.Exit(2)
	}
	cfg := agent.Config{
		StateDir:  *stateDir,
		Endpoint:  *endpoint,
		NodeID:    *nodeID,
		Heartbeat: 30 * time.Second,
	}
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "antinat-agent: token file: %v\n", err)
			os.Exit(1)
		}
		cfg.Token = strings.TrimSpace(string(raw))
		if *pinHex != "" {
			pin, err := hex.DecodeString(*pinHex)
			if err != nil || len(pin) != ed25519.PublicKeySize {
				fmt.Fprintln(os.Stderr, "antinat-agent: --pin must be a 32-byte hex ed25519 public key")
				os.Exit(2)
			}
			cfg.ControllerPublicKey = ed25519.PublicKey(pin)
		}
	}

	app, err := agent.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "antinat-agent: %v\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-agent: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "antinat-agent: control session established for node %s\n", *nodeID)

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.Shutdown(shutCtx); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-agent: shutdown: %v\n", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
