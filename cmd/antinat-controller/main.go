// antinat-controller is the composed Controller process (P10 Story 5).
//
// Flags and environment (all optional; the walking skeleton and real
// deployments set them explicitly):
//
//	-listen     ANTINAT_LISTEN     HTTP listen address (default 127.0.0.1:3111)
//	-store      ANTINAT_STORE      controller SQLite path (default ./var/controller.db)
//	-keydir     ANTINAT_KEYDIR     controller keyring dir (default ./var/keys)
//
// SIGINT/SIGTERM trigger an ordered graceful shutdown (HTTP server first,
// store last).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gxbrave/AntiNAT/internal/buildinfo"
	"github.com/gxbrave/AntiNAT/internal/controller"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "provision-local-agent" {
		if err := provisionLocalAgent(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "antinat-controller: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("antinat-controller %s\n", buildinfo.Format(buildinfo.Current()))
		return
	}
	listen := flag.String("listen", envOr("ANTINAT_LISTEN", "127.0.0.1:3111"), "HTTP listen address")
	storePath := flag.String("store", envOr("ANTINAT_STORE", filepath.Join("var", "controller.db")), "controller SQLite path")
	keyDir := flag.String("keydir", envOr("ANTINAT_KEYDIR", filepath.Join("var", "keys")), "controller keyring dir")
	flag.Parse()

	app, err := controller.New(controller.Config{
		ListenAddress: *listen,
		StorePath:     *storePath,
		KeyDir:        *keyDir,
		Clock:         time.Now,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "antinat-controller: %v\n", err)
		os.Exit(1)
	}
	if err := app.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-controller: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "antinat-controller: listening on %s\n", app.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.Shutdown(shutCtx); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-controller: shutdown: %v\n", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Provisioning is a privileged local operation, not a public enrollment bypass.
func provisionLocalAgent(args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("provision-local-agent requires root")
	}
	flags := flag.NewFlagSet("provision-local-agent", flag.ContinueOnError)
	cfg := controller.LocalAgentConfig{}
	flags.StringVar(&cfg.StorePath, "store", envOr("ANTINAT_STORE", filepath.Join("var", "controller.db")), "existing controller SQLite path")
	flags.StringVar(&cfg.KeyDir, "keydir", envOr("ANTINAT_KEYDIR", filepath.Join("var", "keys")), "existing controller keyring directory")
	flags.StringVar(&cfg.Endpoint, "endpoint", "", "local controller URL, http://127.0.0.1:PORT")
	flags.StringVar(&cfg.InstallDir, "install-dir", "/opt/antinat", "agent installation directory")
	flags.StringVar(&cfg.GitHubProxy, "github-proxy", "", "optional GitHub download proxy")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected provisioning arguments")
	}
	result, err := controller.ProvisionLocalAgent(cfg)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
