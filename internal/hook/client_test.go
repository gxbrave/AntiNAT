package hook_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

// stubDialer dials a captured local target while recording the pinned IP the
// transport supplied, so a test asserts the SSRF pin happened.
type stubDialer struct {
	mu      sync.Mutex
	target  string
	pinned  []net.IP
	dialErr error
}

func (d *stubDialer) dial(ctx context.Context, network, addr string, ip net.IP) (net.Conn, error) {
	d.mu.Lock()
	d.pinned = append(d.pinned, ip)
	err := d.dialErr
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return net.Dial("tcp", d.target)
}

func (d *stubDialer) pins() []net.IP {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]net.IP(nil), d.pinned...)
}

func publicResolver(host string) func(ctx context.Context, host string) ([]netip.Addr, error) {
	return func(ctx context.Context, h string) ([]netip.Addr, error) {
		if h != host {
			return nil, fmt.Errorf("unexpected host %q", h)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
}

func newSSRFClient(t *testing.T, dial *stubDialer, resolver func(context.Context, string) ([]netip.Addr, error)) *hook.Client {
	t.Helper()
	return hook.NewClient(hook.ClientConfig{
		Resolver:       resolver,
		Dial:           dial.dial,
		AllowPlainHTTP: true,
		Timeout:        5 * time.Second,
	})
}

// RED P16 Story 2 (f): a valid webhook is sent to the pinned public address;
// the transport does NOT re-resolve at dial time; the delivered host header /
// SNI target stays the original hostname.
func TestClientSendsToPinnedPublicAddress(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer stub.Close()
	dial := &stubDialer{target: stub.Listener.Addr().String()}
	client := newSSRFClient(t, dial, publicResolver("hooks.example.com"))

	req := &hook.SignedRequest{
		Method: "POST",
		URL:    "http://hooks.example.com/endpoint",
		Headers: func() http.Header {
			h := http.Header{}
			h.Set("Content-Type", "application/json")
			h.Set("X-Event-ID", "evt-42")
			return h
		}(),
		Body: []byte(`{"a":1}`),
	}
	res, err := client.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	pins := dial.pins()
	if len(pins) != 1 || pins[0].String() != "93.184.216.34" {
		t.Fatalf("dialed pins = %v, want the pinned public IP", pins)
	}
}

// RED P16 Story 2 (g): a hostname whose ANY record is private is refused before
// any dial.
func TestClientRejectsPrivateAddressMixed(t *testing.T) {
	dial := &stubDialer{target: "127.0.0.1:1"}
	client := newSSRFClient(t, dial, func(ctx context.Context, h string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.5")}, nil
	})
	_, err := client.Send(context.Background(), &hook.SignedRequest{Method: "GET", URL: "http://evil.example.com/"})
	if err == nil || !strings.Contains(err.Error(), "global routable") {
		t.Fatalf("expected SSRF rejection, got %v", err)
	}
	if len(dial.pins()) != 0 {
		t.Fatal("dialed despite blocked address")
	}
}

// RED P16 Story 2 (h): proxy environment variables are ignored and metadata /
// loopback literals are refused.
func TestClientIgnoresProxyEnvAndBlocksLiteral(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9999")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:9999")
	dial := &stubDialer{target: "127.0.0.1:1"}
	client := newSSRFClient(t, dial, publicResolver("hook.example"))
	for _, url := range []string{"http://127.0.0.1:8080/x", "http://169.254.169.254/latest", "http://[::1]/x"} {
		if _, err := client.Send(context.Background(), &hook.SignedRequest{Method: "GET", URL: url}); err == nil {
			t.Fatalf("literal %s was not blocked", url)
		}
	}
}

// RED P16 Story 2 (i): userinfo, ambiguous ip literals, forbidden hop-by-hop
// headers and CRLF are all rejected without any dial.
func TestClientRejectsDangerousRequestShapes(t *testing.T) {
	dial := &stubDialer{target: "127.0.0.1:1"}
	client := newSSRFClient(t, dial, publicResolver("hook.example"))
	cases := []*hook.SignedRequest{
		{Method: "GET", URL: "http://user:pass@hook.example/"},
		{Method: "GET", URL: "http://127.1/"},
		{Method: "GET", URL: "http://0x7f000001/"},
		{Method: "GET", URL: "http://2130706433/"},
		{Method: "POST", URL: "http://hook.example/", Headers: headerWith("Connection", "close")},
		{Method: "POST", URL: "http://hook.example/", Headers: headerWith("Transfer-Encoding", "chunked")},
		{Method: "POST", URL: "http://hook.example/", Headers: headerWith("Content-Length", "5")},
		{Method: "POST", URL: "http://hook.example/", Headers: headerWith("X-Bad", "a\r\nInjected: 1")},
	}
	for i, c := range cases {
		if _, err := client.Send(context.Background(), c); err == nil {
			t.Fatalf("case %d (%s) was not rejected", i, c.URL)
		}
	}
	if len(dial.pins()) != 0 {
		t.Fatal("dialed despite dangerous request")
	}
}

func headerWith(key, value string) http.Header {
	h := http.Header{}
	h.Set(key, value)
	return h
}

// RED P16 Story 2 (j): redirects are OFF by default — a 302 is surfaced as a
// normal response, never followed.
func TestClientRedirectsOffByDefault(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer stub.Close()
	dial := &stubDialer{target: stub.Listener.Addr().String()}
	client := newSSRFClient(t, dial, publicResolver("hooks.example.com"))
	res, err := client.Send(context.Background(), &hook.SignedRequest{
		Method: "GET", URL: "http://hooks.example.com/a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 surfaced", res.StatusCode)
	}
}

// RED P16 Story 2 (k): with redirects enabled, a cross-origin hop strips
// Authorization / signature headers before the next RoundTrip.
func TestClientRedirectCrossOriginStripsCredentials(t *testing.T) {
	var target *httptest.Server
	var mu sync.Mutex
	var gotAuth, gotSignature string
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotSignature = r.Header.Get("X-Signature")
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://target.example/dst", http.StatusFound)
	}))
	defer source.Close()
	// Dialer maps the pinned public src/target IPs to the real listeners.
	client := &redirectClient{
		src:    source.Listener.Addr().String(),
		target: target.Listener.Addr().String(),
	}
	inner := hook.NewClient(hook.ClientConfig{
		Resolver: func(ctx context.Context, h string) ([]netip.Addr, error) {
			if h == "src.example" {
				return []netip.Addr{netip.MustParseAddr("93.184.216.1")}, nil
			}
			if h == "target.example" {
				return []netip.Addr{netip.MustParseAddr("93.184.216.2")}, nil
			}
			return nil, fmt.Errorf("unexpected host %q", h)
		},
		Dial:            client.dial,
		AllowPlainHTTP:  true,
		FollowRedirects: true,
		Timeout:         5 * time.Second,
	})
	req := &hook.SignedRequest{
		Method: "GET",
		URL:    "http://src.example/start",
		Headers: func() http.Header {
			h := http.Header{}
			h.Set("Authorization", "Bearer secret")
			h.Set("X-Signature", "sig-1")
			return h
		}(),
	}
	res, err := inner.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after redirect", res.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "" || gotSignature != "" {
		t.Fatalf("credentials not stripped: auth=%q signature=%q", gotAuth, gotSignature)
	}
}

type redirectClient struct {
	src, target string
}

func (r *redirectClient) dial(ctx context.Context, network, addr string, ip net.IP) (net.Conn, error) {
	dest := r.target
	if ip.String() == "93.184.216.1" {
		dest = r.src
	}
	return net.Dial("tcp", dest)
}

// RED P16 Story 2 (l): response bytes are bounded pre- and post-decompression
// (gzip-bomb safe).
func TestClientBoundsGzipBomb(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A small gzip stream expanding far beyond the decoded cap (100 MiB).
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		_, _ = io.Copy(zw, strings.NewReader(strings.Repeat("x", 100<<20)))
		_ = zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(compressed.Bytes())
	}))
	defer stub.Close()
	dial := &stubDialer{target: stub.Listener.Addr().String()}
	client := hook.NewClient(hook.ClientConfig{
		Resolver:             publicResolver("hook.example"),
		Dial:                 dial.dial,
		AllowPlainHTTP:       true,
		MaxResponseBytes:     1 << 20,
		MaxDecompressedBytes: 1 << 20,
		Timeout:              10 * time.Second,
	})
	_, err := client.Send(context.Background(), &hook.SignedRequest{Method: "GET", URL: "http://hook.example/"})
	if err == nil {
		t.Fatal("gzip bomb was not refused")
	}
}

// RED P16 Story 2 (m): a normal response body is readable and bounded.
func TestClientReadsNormalBoundedBody(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"delivered"}`)
	}))
	defer stub.Close()
	dial := &stubDialer{target: stub.Listener.Addr().String()}
	client := newSSRFClient(t, dial, publicResolver("hook.example"))
	res, err := client.Send(context.Background(), &hook.SignedRequest{Method: "POST", URL: "http://hook.example/x", Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
}
