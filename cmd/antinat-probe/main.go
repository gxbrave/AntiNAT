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
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/gxbrave/AntiNAT/internal/controller/probe"
	"github.com/gxbrave/AntiNAT/internal/security"
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
	provKey, err := security.LoadOrCreateKeyring(filepath.Dir(cfg.ProviderKeyFile), 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "antinat-probe: provider key: %v\n", err)
		os.Exit(1)
	}

	provider, err := probe.NewProvider(probe.ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provKey.PrivateKey(),
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
