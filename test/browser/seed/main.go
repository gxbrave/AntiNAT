// Command seed populates a Controller SQLite store with the deterministic
// browser-test fixture used by scripts/test-browser.sh. It is test tooling
// only: it opens the already-migrated store (the controller applies the
// migrations), inserts nodes/forwards/navigation/settings through the public
// store API, and writes orthogonal activation snapshots through
// SetForwardRuntimeStatus so the home page has real evidence to derive risk
// states from. It never starts the HTTP server and never touches a real store.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

const (
	adminUser = "admin"
)

func main() {
	storePath := flag.String("store", "", "controller SQLite path")
	scenario := flag.String("scenario", "public", "public|private")
	flag.Parse()
	if *storePath == "" {
		fmt.Fprintln(os.Stderr, "seed: -store is required")
		os.Exit(2)
	}
	st, err := store.Open(*storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: open store: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	if err := seedAdmin(st); err != nil {
		fmt.Fprintf(os.Stderr, "seed: admin: %v\n", err)
		os.Exit(1)
	}
	if err := seedNetworkFixture(st); err != nil {
		fmt.Fprintf(os.Stderr, "seed: fixture: %v\n", err)
		os.Exit(1)
	}
	private := *scenario == "private"
	if err := seedSettings(st, private); err != nil {
		fmt.Fprintf(os.Stderr, "seed: settings: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("seed: %s fixture ready (private=%v)\n", *scenario, private)
}

func seedAdmin(st *store.Store) error {
	if count, err := st.CountUsers(); err == nil && count > 0 {
		return nil
	}
	password := os.Getenv("ANTINAT_TEST_PASSWORD")
	if password == "" {
		return fmt.Errorf("ANTINAT_TEST_PASSWORD is required")
	}
	enc, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	return st.CreateUser(store.UserRecord{ID: "u-admin", Username: adminUser, PasswordHash: enc.Hash, PasswordAlgorithm: enc.Algorithm})
}

func seedNetworkFixture(st *store.Store) error {
	nodes := []store.Node{
		{ID: "node-online", Name: "node-online", ControlState: "ONLINE", Revision: 1},
		{ID: "node-offline", Name: "node-offline", ControlState: "OFFLINE", Revision: 1},
	}
	for _, n := range nodes {
		if _, err := st.GetNode(n.ID); err != nil {
			if err := st.CreateNode(n); err != nil {
				return err
			}
		}
	}

	type fwdFixture struct {
		id     string
		name   string
		nodeID string
		host   string
		axes   protocol.ActivationStates
	}
	good := protocol.ActivationStates{
		ControlState:         "ONLINE",
		ListenerState:        "READY",
		MappingState:         "PUBLIC_CANDIDATE",
		KeepaliveState:       "HEALTHY",
		WanReachabilityState: "PROBING",
		ReturnPathState:      "NOT_TESTED",
		TargetHealthState:    "PASS",
		PublicationState:     "NONE",
		DataPlaneState:       "READY",
	}
	verified := good
	verified.WanReachabilityState = "OPEN_FROM_VANTAGE"
	verified.ReturnPathState = "VERIFIED"
	verified.PublicationState = "PUBLISHED_VERIFIED"

	unverified := good
	unverified.WanReachabilityState = "NO_INDEPENDENT_VANTAGE"
	unverified.PublicationState = "PUBLISHED_UNVERIFIED"

	stale := good
	stale.WanReachabilityState = "OPEN_FROM_VANTAGE"
	stale.ReturnPathState = "VERIFIED"
	stale.PublicationState = "STALE"

	offline := unverified // node is OFFLINE; the card must read offline, not verified

	fixtures := []fwdFixture{
		{id: "fwd-verified", name: "Web", nodeID: "node-online", host: "web.example.com", axes: verified},
		{id: "fwd-unverified", name: "Files", nodeID: "node-online", host: "files.example.com", axes: unverified},
		{id: "fwd-stale", name: "Camera", nodeID: "node-online", host: "cam.example.com", axes: stale},
		{id: "fwd-offline", name: "NAS", nodeID: "node-offline", host: "nas.example.com", axes: offline},
	}
	for _, fx := range fixtures {
		if _, err := st.GetForward(fx.id); err != nil {
			act := protocol.ActivationID(fx.id, 1)
			fwd, err := st.CreateForward(store.Forward{
				ID: fx.id, NodeID: fx.nodeID, Name: fx.name, Protocol: "tcp",
				CurrentActivationID: hexencode(act[:]), Revision: 1,
			})
			if err != nil {
				return fmt.Errorf("create forward %s: %w", fx.id, err)
			}
			spec := protocol.ForwardSpec{
				ForwardID: fx.id, Name: fx.name, Protocol: protocol.ProtocolTCP,
				Target: "192.0.2.10:8080", Strategy: protocol.StrategyAuto,
				PublishedHost: fx.host, PublishScheme: "https", DesiredRevision: 1,
				Presence: protocol.PresencePresent,
			}
			raw, _ := json.Marshal(spec)
			if err := st.CreateForwardSpec(store.ForwardSpec{ID: "spec-" + fx.id, ForwardID: fx.id, Revision: 1, SpecJSON: string(raw)}); err != nil {
				return fmt.Errorf("create spec %s: %w", fx.id, err)
			}
			snap, err := json.Marshal(fx.axes)
			if err != nil {
				return err
			}
			if err := st.SetForwardRuntimeStatus(fwd.ID, fwd.CurrentActivationID, fwd.Revision, string(snap)); err != nil {
				return fmt.Errorf("set runtime status %s: %w", fx.id, err)
			}
		}
	}

	cats := []store.NavigationCategory{
		{ID: "cat-work", Name: "工作 Work", OrderIndex: 0},
		{ID: "cat-media", Name: "媒体 Media", OrderIndex: 1},
	}
	items := []store.NavigationItem{
		{ID: "item-web", Name: "Web 面板", Description: "已发布的管理 Web 服务", Protocol: "tcp", CategoryID: "cat-work", ForwardID: "fwd-verified", OrderIndex: 0},
		{ID: "item-files", Name: "Files 文件", Description: "未验证的文件服务", Protocol: "tcp", CategoryID: "cat-work", ForwardID: "fwd-unverified", OrderIndex: 1},
		{ID: "item-cam", Name: "Camera 摄像头", Description: "过期状态的摄像头流", Protocol: "tcp", CategoryID: "cat-media", ForwardID: "fwd-stale", OrderIndex: 0},
		{ID: "item-nas", Name: "NAS 存储", Description: "离线节点的 NAS 入口", Protocol: "tcp", CategoryID: "cat-media", ForwardID: "fwd-offline", OrderIndex: 1},
	}
	for _, c := range cats {
		if _, err := st.GetNavigationCategory(c.ID); err != nil {
			if _, err := st.CreateNavigationCategory(c); err != nil {
				return err
			}
		}
	}
	for _, it := range items {
		if _, err := st.GetNavigationItem(it.ID); err != nil {
			if _, err := st.CreateNavigationItem(it); err != nil {
				return err
			}
		}
	}
	return nil
}

func seedSettings(st *store.Store, private bool) error {
	expected := uint64(0)
	if rec, err := st.GetSettingsRecord(); err == nil {
		expected = rec.Revision
	}
	raw := fmt.Sprintf(`{"private_site":%v,"language":"zh","controller_endpoint":"https://ctl.example.com:3111"}`, private)
	_, err := st.PutSettingsRecord(expected, raw)
	return err
}

func hexencode(b []byte) string {
	const hexc = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexc[c>>4]
		out[i*2+1] = hexc[c&0x0f]
	}
	return string(out)
}
