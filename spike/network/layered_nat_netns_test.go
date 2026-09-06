//go:build linux && netns

package network

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLayeredNATWithRealUPnPDaemonAndUpstreamSTUN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("netns evidence requires root; run with sudo -E")
	}
	for _, command := range []string{"ip", "nft", "miniupnpd", "upnpc", "turnserver", "turnutils_stunclient"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("real-network prerequisite %s unavailable: %v", command, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", "scripts/layered_nat_lab.sh")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("layered NAT lab timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("layered NAT lab: %v\n%s", err, output)
	}
	text := string(output)
	t.Logf("layered NAT lab assertions:\n%s", text)
	for _, assertion := range []string{
		"TOPOLOGY=CPE_TO_CGN",
		"UPNP_DAEMON=miniupnpd",
		"UPNP_MAPPING=BLOCKED_RESTRICTIVE_CGN",
		"UPSTREAM_STUN=coturn",
		"STUN_OBSERVED=11.0.0.2:",
		"FIRST_HOP=100.64.0.2",
		"LAYERED_ENDPOINTS_DIFFER=PASS",
	} {
		if !strings.Contains(text, assertion) {
			t.Fatalf("missing assertion %q in lab output:\n%s", assertion, text)
		}
	}

	namespaces, err := exec.Command("ip", "netns", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("list namespaces after cleanup: %v\n%s", err, namespaces)
	}
	if strings.Contains(string(namespaces), "antinat-p02-") {
		t.Fatalf("lab namespace leaked after cleanup:\n%s", namespaces)
	}
}
