package install

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Layout is the path contract consumed by platform installers. Logical Linux
// paths are frozen; a non-empty Prefix is only for isolated test roots and is
// never exposed as an installer flag.
type Layout struct {
	Platform string
	Prefix   string

	InstallDir          string
	BinDir              string
	AgentBinary         string
	ControllerBinary    string
	HookRunnerBinary    string
	DataDir             string
	ConfigFile          string
	StateMarker         string
	AgentTerminalMarker string
	LogDir              string
	ServiceDir          string
	AgentService        string
	ControllerService   string
	OwnershipManifest   string
	OwnershipKey        string
	BackupDir           string
}

// LinuxLayout returns the frozen Linux systemd layout. Prefixing preserves
// the suffixes while allowing tests to run without touching /opt, /etc or
// /var.
func LinuxLayout(prefix string) Layout {
	return Layout{
		Platform:            PlatformLinux,
		Prefix:              prefix,
		InstallDir:          withPrefix(prefix, "/opt/antinat"),
		BinDir:              withPrefix(prefix, "/opt/antinat/bin"),
		AgentBinary:         withPrefix(prefix, "/opt/antinat/bin/antinat-agent"),
		ControllerBinary:    withPrefix(prefix, "/opt/antinat/bin/antinat-controller"),
		HookRunnerBinary:    withPrefix(prefix, "/opt/antinat/bin/antinat-hook-runner"),
		DataDir:             withPrefix(prefix, "/var/lib/antinat"),
		ConfigFile:          withPrefix(prefix, "/etc/antinat/agent.conf"),
		StateMarker:         withPrefix(prefix, "/var/lib/antinat/agent.marker"),
		AgentTerminalMarker: withPrefix(prefix, "/var/lib/antinat/terminal.marker"),
		LogDir:              withPrefix(prefix, "/var/log/antinat"),
		ServiceDir:          withPrefix(prefix, "/etc/systemd/system"),
		AgentService:        withPrefix(prefix, "/etc/systemd/system/antinat-agent.service"),
		ControllerService:   withPrefix(prefix, "/etc/systemd/system/antinat-controller.service"),
		OwnershipManifest:   withPrefix(prefix, "/var/lib/antinat/ownership-manifest.json"),
		OwnershipKey:        withPrefix(prefix, "/var/lib/antinat/ownership.key"),
		BackupDir:           withPrefix(prefix, "/var/lib/antinat/backups"),
	}
}

// WindowsLayout returns the documented Windows layout. Prefix is useful for
// unit tests and is normally empty; environment expansion is performed by the
// PowerShell entry point, not by this package.
func WindowsLayout(prefix string) Layout {
	return Layout{
		Platform:            PlatformWindows,
		Prefix:              prefix,
		InstallDir:          withPrefix(prefix, `C:\Program Files\AntiNAT`),
		BinDir:              withPrefix(prefix, `C:\Program Files\AntiNAT\bin`),
		AgentBinary:         withPrefix(prefix, `C:\Program Files\AntiNAT\bin\antinat-agent.exe`),
		ControllerBinary:    withPrefix(prefix, `C:\Program Files\AntiNAT\bin\antinat-controller.exe`),
		HookRunnerBinary:    withPrefix(prefix, `C:\Program Files\AntiNAT\bin\antinat-hook-runner.exe`),
		DataDir:             withPrefix(prefix, `C:\ProgramData\AntiNAT`),
		ConfigFile:          withPrefix(prefix, `C:\ProgramData\AntiNAT\agent.conf`),
		StateMarker:         withPrefix(prefix, `C:\ProgramData\AntiNAT\agent.marker`),
		AgentTerminalMarker: withPrefix(prefix, `C:\ProgramData\AntiNAT\terminal.marker`),
		LogDir:              withPrefix(prefix, `C:\ProgramData\AntiNAT\log`),
		ServiceDir:          withPrefix(prefix, `C:\ProgramData\AntiNAT\services`),
		AgentService:        withPrefix(prefix, `C:\ProgramData\AntiNAT\services\antinat-agent.xml`),
		ControllerService:   withPrefix(prefix, `C:\ProgramData\AntiNAT\services\antinat-controller.xml`),
		OwnershipManifest:   withPrefix(prefix, `C:\ProgramData\AntiNAT\ownership-manifest.json`),
		OwnershipKey:        withPrefix(prefix, `C:\ProgramData\AntiNAT\ownership.key`),
		BackupDir:           withPrefix(prefix, `C:\ProgramData\AntiNAT\backups`),
	}
}

// DockerLayout models the paths mounted into the OCI images.
func DockerLayout(prefix string) Layout {
	l := LinuxLayout(prefix)
	l.Platform = PlatformDocker
	return l
}

func withPrefix(prefix, logical string) string {
	if prefix == "" {
		return logical
	}
	return filepath.Join(prefix, filepath.FromSlash(strings.ReplaceAll(logical, `\`, "/")))
}

// Validate checks the frozen Linux values when no test prefix is active.
func (l Layout) Validate() error {
	if l.Platform == "" {
		return errors.New("install: layout platform is required")
	}
	if l.Platform != PlatformLinux && l.Platform != PlatformWindows && l.Platform != PlatformDocker {
		return fmt.Errorf("install: unsupported layout platform %q", l.Platform)
	}
	if l.InstallDir == "" || l.BinDir == "" || l.AgentBinary == "" || l.DataDir == "" || l.ConfigFile == "" {
		return errors.New("install: layout has missing required paths")
	}
	if l.Platform == PlatformLinux && l.Prefix == "" {
		want := LinuxLayout("")
		for name, got := range map[string]string{
			"install_dir":  l.InstallDir,
			"binary":       l.AgentBinary,
			"data_dir":     l.DataDir,
			"config":       l.ConfigFile,
			"state_marker": l.StateMarker,
			"log_dir":      l.LogDir,
			"service":      filepath.Base(l.AgentService),
			"user":         "antinat",
			"group":        "antinat",
		} {
			var expected string
			switch name {
			case "service", "user", "group":
				// Values above are the frozen literal names.
				expected = map[string]string{"service": "antinat-agent.service", "user": "antinat", "group": "antinat"}[name]
			default:
				expected = map[string]string{
					"install_dir":  want.InstallDir,
					"binary":       want.AgentBinary,
					"data_dir":     want.DataDir,
					"config":       want.ConfigFile,
					"state_marker": want.StateMarker,
					"log_dir":      want.LogDir,
				}[name]
			}
			if got != expected {
				return fmt.Errorf("install: frozen Linux %s is %q, want %q", name, got, expected)
			}
		}
	}
	return nil
}
