package deployment

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

func decodePowerShellCommand(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw)%2 != 0 {
		return "", fmt.Errorf("odd UTF-16LE byte count")
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(units)), nil
}

func TestQuoteShellArgProtectsShellSyntax(t *testing.T) {
	got := QuoteShellArg("$(touch /tmp/pwned); 'quoted' && $HOME")
	want := "'$(touch /tmp/pwned); '\"'\"'quoted'\"'\"' && $HOME'"
	if got != want {
		t.Fatalf("QuoteShellArg() = %q, want %q", got, want)
	}
}

func TestQuotePowerShellArgProtectsPowerShellSyntax(t *testing.T) {
	got := QuotePowerShellArg("$(Remove-Item -Recurse C:\\); 'quoted'")
	want := "'$(Remove-Item -Recurse C:\\); ''quoted'''"
	if got != want {
		t.Fatalf("QuotePowerShellArg() = %q, want %q", got, want)
	}
}

func TestNormalizeOptionalServiceURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "adds https and removes slash", in: "ghfast.top/", want: "https://ghfast.top"},
		{name: "preserves explicit scheme", in: "http://proxy.example/path///", want: "http://proxy.example/path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeOptionalServiceURL(tc.in)
			if err != nil {
				t.Fatalf("NormalizeOptionalServiceURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeOptionalServiceURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBuildAgentArgumentsValidatesBoundaries(t *testing.T) {
	profile := Profile{
		Platform:           PlatformLinux,
		ControllerEndpoint: "https://ctl.example.test:3111/base/",
		BindInterface:      "eth0; echo injected",
		DetectionScheduler: "parallel",
		GitHubProxy:        "https://ghfast.top/",
		InstallDir:         "/opt/anti nat",
		ServiceName:        "antinat-agent.service",
		LogLevel:           "info",
		AutoUpdate:         "disabled",
	}
	args, err := BuildAgentArguments(profile)
	if err != nil {
		t.Fatalf("BuildAgentArguments: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--controller-endpoint", "https://ctl.example.test:3111/base",
		"--bind-interface", "eth0; echo injected", "--detection-scheduler", "parallel",
		"--log-level", "info", "--auto-update", "disabled",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("arguments %q do not contain %q", joined, want)
		}
	}
}

func TestBuildAgentArgumentsRejectsInvalidProfile(t *testing.T) {
	cases := []Profile{
		{Platform: "solaris", ControllerEndpoint: "https://ctl.example.test"},
		{Platform: PlatformLinux, ControllerEndpoint: "javascript:alert(1)"},
		{Platform: PlatformLinux, ControllerEndpoint: "https://ctl.example.test/?x=1"},
		{Platform: PlatformLinux, ControllerEndpoint: "https://ctl.example.test", DetectionScheduler: "parallel;touch /tmp/x"},
	}
	for i, profile := range cases {
		if _, err := BuildAgentArguments(profile); err == nil {
			t.Errorf("case %d: BuildAgentArguments accepted invalid profile", i)
		}
	}
}

func TestBuildInstallCommandSeparatesTokenAndFiltersDockerInstallerFlags(t *testing.T) {
	profile := Profile{
		Platform:           PlatformDocker,
		ControllerEndpoint: "https://ctl.example.test:3111",
		BindInterface:      "eth0",
		DetectionScheduler: "sequential",
		GitHubProxy:        "https://ghfast.top",
		InstallDir:         "/custom/dir",
		ServiceName:        "custom-agent",
		LogLevel:           "warn",
		AutoUpdate:         "disabled",
	}
	command, err := BuildInstallCommand(profile)
	if err != nil {
		t.Fatalf("BuildInstallCommand: %v", err)
	}
	forbiddenWords := []string{"--install-dir", "--service-name", "--github-proxy", "--token", "token-value", "--rm"}
	for _, forbidden := range forbiddenWords {
		if strings.Contains(command, forbidden) {
			t.Errorf("Docker command %q contains forbidden %q", command, forbidden)
		}
	}
	for _, required := range []string{"docker run", "--network host", "--restart=always", "--controller-endpoint", "--platform docker"} {
		if !strings.Contains(command, required) {
			t.Errorf("Docker command %q does not contain %q", command, required)
		}
	}
}

func TestBuildInstallCommandUsesPlatformSpecificDownloadAndNoSecret(t *testing.T) {
	for _, platform := range []string{PlatformLinux, PlatformWindows} {
		profile := Profile{Platform: platform, ControllerEndpoint: "https://ctl.example.test", GitHubProxy: "https://ghfast.top/", LogLevel: "info", AutoUpdate: "disabled"}
		command, err := BuildInstallCommand(profile)
		if err != nil {
			t.Fatalf("BuildInstallCommand(%s): %v", platform, err)
		}
		if platform == PlatformLinux && !strings.Contains(command, "https://ghfast.top/https://github.com/gxbrave/AntiNAT/releases/latest/download/") {
			t.Errorf("Linux command did not apply the normalized GitHub proxy: %q", command)
		}
		if strings.Contains(command, "--token") || strings.Contains(command, "TOKEN") {
			t.Errorf("%s command contains a token channel: %q", platform, command)
		}
		if platform == PlatformLinux && (!strings.Contains(command, "curl") || !strings.Contains(command, "sudo bash")) {
			t.Errorf("Linux command is not a curl/sudo bash flow: %q", command)
		}
		if platform == PlatformWindows && (!strings.Contains(command, "powershell") || !strings.Contains(command, "ExecutionPolicy Bypass")) {
			t.Errorf("Windows command is not a PowerShell bypass flow: %q", command)
		}
	}
}

func TestPowerShellInstallCommandEncodesCompleteScript(t *testing.T) {
	sentinel := `eth0"; $(Remove-Item C:\\); & Write-Output pwned`
	profile := Profile{Platform: PlatformWindows, ControllerEndpoint: "https://ctl.example.test", BindInterface: sentinel, LogLevel: "info", AutoUpdate: "disabled"}
	command, err := BuildInstallCommand(profile)
	if err != nil {
		t.Fatalf("BuildInstallCommand: %v", err)
	}
	if !strings.Contains(command, "-EncodedCommand ") {
		t.Fatalf("PowerShell command is not encoded: %q", command)
	}
	if strings.Contains(command, sentinel) || strings.Contains(command, "Remove-Item") {
		t.Fatalf("PowerShell command exposes raw script/user input: %q", command)
	}
	encoded := command[strings.Index(command, "-EncodedCommand ")+len("-EncodedCommand "):]
	decoded, err := decodePowerShellCommand(encoded)
	if err != nil {
		t.Fatalf("decode encoded command: %v", err)
	}
	if !strings.Contains(decoded, sentinel) || !strings.Contains(decoded, "Invoke-WebRequest") {
		t.Fatalf("decoded PowerShell script lost expected values: %q", decoded)
	}
}
