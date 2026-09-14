package controller

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gxbrave/AntiNAT/internal/controller/deployment"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// LocalAgentConfig refers to an existing local controller. Access to these
// private files is the authorization boundary; this is never an HTTP API.
type LocalAgentConfig struct{ StorePath, KeyDir, Endpoint, InstallDir, GitHubProxy string }

// LocalAgentProvision contains a one-time secret. Callers must protect its
// output as credentials and must never log it.
type LocalAgentProvision struct {
	NodeID          string   `json:"node_id"`
	ControllerPin   string   `json:"controller_pin,omitempty"`
	EnrollmentToken string   `json:"enrollment_token,omitempty"`
	InstallCommand  string   `json:"install_command,omitempty"`
	InstallerURL    string   `json:"installer_url,omitempty"`
	InstallArgv     []string `json:"install_argv,omitempty"`
	AlreadyEnrolled bool     `json:"already_enrolled"`
}

// ProvisionLocalAgent uses the same profile validation, token issuance and
// command builder as controller-managed remote nodes. A stable node identity
// allows an interrupted installer to retry without orphaning duplicate nodes.
func ProvisionLocalAgent(cfg LocalAgentConfig) (LocalAgentProvision, error) {
	result := LocalAgentProvision{NodeID: "local-agent"}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return result, fmt.Errorf("local agent endpoint must be http://127.0.0.1:PORT")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return result, fmt.Errorf("local agent endpoint requires a valid port")
	}
	profile := deployment.DefaultProfile(cfg.Endpoint)
	if cfg.InstallDir != "" {
		profile.InstallDir = cfg.InstallDir
	}
	profile.GitHubProxy = cfg.GitHubProxy
	raw, err := deployment.EncodeProfileJSON(profile)
	if err != nil {
		return result, err
	}
	// Refuse to initialize a different controller due to a mistyped path.
	for _, path := range []string{cfg.StorePath, filepath.Join(cfg.KeyDir, security.KeyringFile)} {
		info, err := os.Stat(path)
		if err != nil {
			return result, fmt.Errorf("existing controller file %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return result, fmt.Errorf("controller file is not regular: %s", path)
		}
	}
	keys, err := security.LoadOrCreateKeyring(cfg.KeyDir, 1)
	if err != nil {
		return result, err
	}
	st, err := store.Open(cfg.StorePath)
	if err != nil {
		return result, err
	}
	defer st.Close()
	// A terminal decommission fact survives node deletion. Never resurrect
	// that identity, even if its credential row has already been removed.
	if _, err = st.NodeCleanupTombstone(result.NodeID); err == nil {
		return result, fmt.Errorf("local agent has been decommissioned; create a new agent through the controller")
	} else if !errors.Is(err, store.ErrNotFound) {
		return result, err
	}
	if _, err = st.NodeCredentialByNode(result.NodeID); err == nil {
		result.AlreadyEnrolled = true
		return result, nil
	} else if !errors.Is(err, store.ErrNodeNotFound) {
		return result, err
	}
	if _, err = st.GetNode(result.NodeID); errors.Is(err, store.ErrNodeNotFound) {
		err = st.CreateNode(store.Node{ID: result.NodeID, Name: "local-agent", Revision: 1})
	}
	if err != nil {
		return result, err
	}
	current, err := st.GetDeploymentProfile(result.NodeID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return result, err
	}
	if _, err = st.PutDeploymentProfile(result.NodeID, current.Revision, raw); err != nil {
		return result, err
	}
	result.ControllerPin = hex.EncodeToString(keys.PublicKey())
	result.InstallCommand, err = deployment.BuildInstallCommand(profile, deployment.InstallCommandContext{NodeID: result.NodeID, ControllerPin: result.ControllerPin})
	if err != nil {
		return result, err
	}
	result.InstallArgv, err = deployment.BuildAgentArguments(profile)
	if err != nil {
		return result, err
	}
	result.InstallerURL = deployment.LinuxInstallerURL(profile)
	result.EnrollmentToken, err = st.CreateEnrollmentToken(result.NodeID, 3600)
	return result, err
}
