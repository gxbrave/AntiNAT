package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func TestProvisionLocalAgent(t *testing.T) {
	dir := t.TempDir()
	cfg := LocalAgentConfig{StorePath: filepath.Join(dir, "controller.db"), KeyDir: filepath.Join(dir, "keys"), Endpoint: "http://127.0.0.1:4321"}
	st, err := store.Open(cfg.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = security.LoadOrCreateKeyring(cfg.KeyDir, 1); err != nil {
		t.Fatal(err)
	}
	result, err := ProvisionLocalAgent(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ControllerPin) != 64 || result.EnrollmentToken == "" || !strings.Contains(result.InstallCommand, cfg.Endpoint) {
		t.Fatalf("missing enrollment material")
	}
	if len(result.NodeID) > 16 || !strings.Contains(result.InstallerURL, "/AntiNAT-Agent/") || !strings.Contains(strings.Join(result.InstallArgv, " "), cfg.Endpoint) {
		t.Fatal("invalid structured installer invocation")
	}
	profile, err := st.GetDeploymentProfile(result.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile.JSON, result.EnrollmentToken) || !strings.Contains(profile.JSON, cfg.Endpoint) {
		t.Fatal("invalid persisted profile")
	}
	again, err := ProvisionLocalAgent(cfg)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := st.ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || again.NodeID != result.NodeID || again.EnrollmentToken == result.EnrollmentToken {
		t.Fatal("retry must reuse node and issue fresh token")
	}
	_, _, err = st.ConsumeEnrollmentToken(store.EnrollmentRequest{NodeID: result.NodeID, TokenHash: localTestTokenHash(again.EnrollmentToken), AgentPublicKeyHash: strings.Repeat("a", 64), CredentialVersion: 1, ControllerKeyID: "controller", ResultID: "test-result", ResultExpiryUnix: 9999999999})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := ProvisionLocalAgent(cfg)
	if err != nil || !bound.AlreadyEnrolled || bound.EnrollmentToken != "" {
		t.Fatal("must skip bound node without issuing token")
	}
}

func TestProvisionLocalAgentRejectsRemoteOrMissingController(t *testing.T) {
	for _, endpoint := range []string{"http://example.com:3111", "http://127.0.0.1:3111/path", "http://user@127.0.0.1:3111", "http://127.0.0.1", "http://127.0.0.1:0"} {
		if _, err := ProvisionLocalAgent(LocalAgentConfig{Endpoint: endpoint}); err == nil {
			t.Errorf("accepted %q", endpoint)
		}
	}
	if _, err := ProvisionLocalAgent(LocalAgentConfig{StorePath: filepath.Join(t.TempDir(), "missing.db"), KeyDir: t.TempDir(), Endpoint: "http://127.0.0.1:3111"}); err == nil {
		t.Fatal("created a new controller")
	}
}

func localTestTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestProvisionLocalAgentLiveEnrollment(t *testing.T) {
	dir := t.TempDir()
	cfg := LocalAgentConfig{StorePath: filepath.Join(dir, "controller.db"), KeyDir: filepath.Join(dir, "keys")}
	app, err := New(Config{ListenAddress: "127.0.0.1:0", StorePath: cfg.StorePath, KeyDir: cfg.KeyDir, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Start(); err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown(context.Background())
	cfg.Endpoint = "http://" + app.Addr()
	provision, err := ProvisionLocalAgent(cfg)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := app.Store().GetDeploymentProfile(provision.NodeID)
	if err != nil || !strings.Contains(profile.JSON, cfg.Endpoint) {
		t.Fatal("live controller cannot see local deployment")
	}
	pin, err := hex.DecodeString(provision.ControllerPin)
	if err != nil {
		t.Fatal(err)
	}
	state, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key, err := control.Enroll(ctx, state, control.EnrollOptions{Endpoint: cfg.Endpoint, NodeID: provision.NodeID, Token: provision.EnrollmentToken, ControllerPublicKey: ed25519.PublicKey(pin), KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := app.Store().NodeCredentialByNode(provision.NodeID)
	if err != nil || cred.CredentialVersion != key.CredentialVersion() {
		t.Fatal("live enrollment did not bind local credential")
	}
	retry, err := ProvisionLocalAgent(cfg)
	if err != nil || !retry.AlreadyEnrolled || retry.EnrollmentToken != "" {
		t.Fatal("enrolled local agent was not recognized")
	}
}

func TestProvisionLocalAgentRejectsDecommissionAndNameCollision(t *testing.T) {
	for _, scenario := range []string{"decommission", "name-collision"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			cfg := LocalAgentConfig{StorePath: filepath.Join(dir, "controller.db"), KeyDir: filepath.Join(dir, "keys"), Endpoint: "http://127.0.0.1:3111"}
			st, err := store.Open(cfg.StorePath)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, err = security.LoadOrCreateKeyring(cfg.KeyDir, 1); err != nil {
				t.Fatal(err)
			}
			if scenario == "decommission" {
				err = st.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{NodeID: "local-agent", OperationID: "removed-local", Force: true})
			} else {
				err = st.CreateNode(store.Node{ID: "other", Name: "local-agent"})
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ProvisionLocalAgent(cfg); err == nil {
				t.Fatal("must not revive decommissioned identity or overwrite another node")
			}
			if _, err = st.GetNode("local-agent"); !errors.Is(err, store.ErrNodeNotFound) {
				t.Fatal("failed provisioning created a node")
			}
		})
	}
}
