package hook

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ResolveFunc resolves a hostname to all A/AAAA records. Injectable for tests.
type ResolveFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// DialFunc connects to the pinned, validated address. The production dialer
// dials net.JoinHostPort(ip.String(), port); tests inject an in-memory dialer
// that asserts the pinned address and connects to a local stub.
type DialFunc func(ctx context.Context, network, addr string, ip net.IP) (net.Conn, error)

// SSRFDefaults are the frozen transport bounds.
const (
	defaultMaxResponseBytes       = 1 << 20 // 1 MiB raw response
	defaultMaxDecompressedBytes   = 4 << 20 // 4 MiB after decompression
	defaultMaxResponseHeaderBytes = 64 << 10
	defaultClientTimeout          = 30 * time.Second
	maxRedirectHops               = 5
)

// ClientConfig configures the SSRF-safe sender.
type ClientConfig struct {
	// Resolver resolves hostnames (default: net.DefaultResolver).
	Resolver ResolveFunc
	// Dial connects to the pinned validated address (default: net.Dialer).
	Dial DialFunc
	// AllowPlainHTTP permits http:// webhook URLs (off by default; webhooks
	// default to HTTPS + TLS verification).
	AllowPlainHTTP bool
	// MaxResponseBytes bounds the raw (pre-decompression) response body.
	MaxResponseBytes int64
	// MaxDecompressedBytes bounds the post-decompression response body.
	MaxDecompressedBytes int64
	// MaxResponseHeaderBytes bounds the response headers.
	MaxResponseHeaderBytes int64
	// Timeout is the whole-request budget (default 30s).
	Timeout time.Duration
	// FollowRedirects enables per-hop redirects (default off). When enabled,
	// every hop re-resolves + re-validates, and hop-by-hop headers plus any
	// Authorization/signature headers are stripped on every hop.
	FollowRedirects bool
}

// Client is the SSRF-safe webhook sender. It never follows proxy environment
// variables, validates every resolved address, pins the resolved IP while
// preserving SNI/Host, and bounds response bytes before and after
// decompression (gzip-bomb safe).
type Client struct {
	cfg    ClientConfig
	inner  *http.Transport
	client *http.Client
}

// NewClient builds the SSRF-safe client.
func NewClient(cfg ClientConfig) *Client {
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultMaxResponseBytes
	}
	if cfg.MaxDecompressedBytes <= 0 {
		cfg.MaxDecompressedBytes = defaultMaxDecompressedBytes
	}
	if cfg.MaxResponseHeaderBytes <= 0 {
		cfg.MaxResponseHeaderBytes = defaultMaxResponseHeaderBytes
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultClientTimeout
	}
	resolve := cfg.Resolver
	if resolve == nil {
		resolve = defaultResolver
	}
	dial := cfg.Dial
	if dial == nil {
		dial = defaultDialer
	}
	transport := &ssrfTransport{
		resolve:    resolve,
		dial:       dial,
		allowPlain: cfg.AllowPlainHTTP,
		maxHeader:  cfg.MaxResponseHeaderBytes,
		maxRaw:     cfg.MaxResponseBytes,
		maxDecoded: cfg.MaxDecompressedBytes,
	}
	inner := &http.Transport{
		// Never inherit the process proxy environment (HTTP_PROXY etc.).
		Proxy:                  nil,
		DialContext:            transport.dialContext,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: cfg.MaxResponseHeaderBytes,
		// We decompress ourselves so pre- and post-decompression bytes are both
		// bounded (gzip bombs cannot exhaust the controller).
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	transport.inner = inner
	c := &Client{cfg: cfg, inner: inner}
	c.client = &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}
	if !cfg.FollowRedirects {
		// Redirects are OFF by default; a Location response is surfaced as a
		// normal response (the dispatcher records its status).
		c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirectHops {
				return errors.New("hook: too many redirects")
			}
			return stripRedirectCredentials(req, via)
		}
	}
	return c
}

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func defaultDialer(ctx context.Context, network, addr string, ip net.IP) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = 10 * time.Second
	return d.DialContext(ctx, network, addr)
}

// Send delivers a fully prepared signed request.
func (c *Client) Send(ctx context.Context, req *SignedRequest) (*SendResult, error) {
	if req == nil {
		return nil, errors.New("hook: nil signed request")
	}
	if err := validateSignedRequest(req); err != nil {
		return nil, err
	}
	body := bytes.NewReader(req.Body)
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("hook: build request: %w", err)
	}
	for key, values := range req.Headers {
		for _, v := range values {
			httpReq.Header.Add(key, v)
		}
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("hook: send: %w", err)
	}
	defer resp.Body.Close()
	return &SendResult{StatusCode: resp.StatusCode}, nil
}

// validateSignedRequest rejects header/URL forms the transport must never see.
func validateSignedRequest(req *SignedRequest) error {
	u, err := url.Parse(req.URL)
	if err != nil {
		return fmt.Errorf("hook: invalid url: %w", err)
	}
	if u.User != nil {
		return errors.New("hook: userinfo in webhook url is rejected")
	}
	return validateHeaders(req.Headers)
}

// validateHeaders rejects forbidden hop-by-hop headers on the wire.
func validateHeaders(h http.Header) error {
	for _, forbidden := range []string{"Host", "Content-Length", "Transfer-Encoding", "Connection"} {
		if v := h.Get(forbidden); v != "" {
			return fmt.Errorf("hook: forbidden hop-by-hop header %s is set", forbidden)
		}
	}
	for key, values := range h {
		if strings.ContainsAny(key, "\r\n") {
			return errors.New("hook: CRLF in header name is rejected")
		}
		for _, v := range values {
			if strings.ContainsAny(v, "\r\n") {
				return errors.New("hook: CRLF in header value is rejected")
			}
		}
	}
	return nil
}

// ssrfTransport is the RoundTripper that resolves, validates, pins, dials,
// and bounds every response. It is also the Sender's transport.
type ssrfTransport struct {
	resolve    ResolveFunc
	dial       DialFunc
	allowPlain bool
	maxHeader  int64
	maxRaw     int64
	maxDecoded int64
	inner      *http.Transport
}

func (t *ssrfTransport) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("hook: split address: %w", err)
	}
	pinned, err := t.resolveAndPin(ctx, host)
	if err != nil {
		return nil, err
	}
	dialAddr := net.JoinHostPort(pinned.String(), port)
	return t.dial(ctx, network, dialAddr, net.IP(pinned.AsSlice()))
}

// resolveAndPin resolves the host and returns the first permitted address. For
// an IP-literal host it validates the literal directly; ambiguous/zone/
// non-canonical IP spellings are rejected. Every A/AAAA record must be global.
func (t *ssrfTransport) resolveAndPin(ctx context.Context, host string) (netip.Addr, error) {
	if lit, ok := canonicalIPLiteral(host); ok {
		if addressBlocked(lit) {
			return netip.Addr{}, errBlockedAddress
		}
		return lit, nil
	}
	if ambiguousIPLiteral(host) {
		return netip.Addr{}, errors.New("hook: ambiguous ip-literal host is rejected")
	}
	if err := hostnameIssues(host); err != nil {
		return netip.Addr{}, err
	}
	addrs, err := t.resolve(ctx, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("hook: resolve %s: %w", host, err)
	}
	if err := validateAddresses(addrs); err != nil {
		return netip.Addr{}, fmt.Errorf("hook: %s: %w", host, err)
	}
	// Deterministic pick: prefer the first v4, then the first global v6, so a
	// hostname with both families still resolves to a single pinned address.
	for _, a := range addrs {
		if a.Is4() {
			return a, nil
		}
	}
	return addrs[0], nil
}

// RoundTrip validates the request shape, lets the inner transport dial the
// pinned address, and returns a response whose body is bounded pre- and
// post-decompression.
func (t *ssrfTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.validateRequest(req); err != nil {
		return nil, err
	}
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := t.readBounded(resp)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

func (t *ssrfTransport) validateRequest(req *http.Request) error {
	if req == nil || req.URL == nil {
		return errors.New("hook: nil request")
	}
	switch req.URL.Scheme {
	case "https":
	case "http":
		if !t.allowPlain {
			return errors.New("hook: http webhook url is rejected (https required)")
		}
	default:
		return fmt.Errorf("hook: unsupported scheme %q", req.URL.Scheme)
	}
	if req.URL.User != nil {
		return errors.New("hook: userinfo in webhook url is rejected")
	}
	if strings.Contains(req.URL.RawQuery, "\r") || strings.Contains(req.URL.RawQuery, "\n") ||
		strings.Contains(req.URL.Path, "\r") || strings.Contains(req.URL.Path, "\n") {
		return errors.New("hook: CRLF in request target is rejected")
	}
	return validateHeaders(req.Header)
}

// readBounded reads the response body up to the raw cap, decompresses gzip up
// to the decoded cap, and returns nil error only when both bounds held.
func (t *ssrfTransport) readBounded(resp *http.Response) ([]byte, error) {
	rawLimited := io.LimitReader(resp.Body, t.maxRaw+1)
	raw, err := io.ReadAll(rawLimited)
	if err != nil {
		return nil, fmt.Errorf("hook: read response: %w", err)
	}
	if int64(len(raw)) > t.maxRaw {
		return nil, fmt.Errorf("hook: response exceeds %d bytes", t.maxRaw)
	}
	if !strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		return raw, nil
	}
	if len(raw) == 0 {
		return nil, errors.New("hook: declared gzip body is empty")
	}
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("hook: invalid gzip response")
	}
	defer reader.Close()
	decodedLimited := io.LimitReader(reader, t.maxDecoded+1)
	decoded, err := io.ReadAll(decodedLimited)
	if err != nil {
		return nil, fmt.Errorf("hook: decompress response: %w", err)
	}
	if int64(len(decoded)) > t.maxDecoded {
		return nil, fmt.Errorf("hook: decompressed response exceeds %d bytes", t.maxDecoded)
	}
	return decoded, nil
}

// stripRedirectCredentials removes Authorization / signature headers on every
// redirect hop so credentials never travel to a different origin (per-hop
// re-validation happens in the next RoundTrip).
func stripRedirectCredentials(req *http.Request, via []*http.Request) error {
	prev := via[len(via)-1]
	if prev == nil || req == nil || !sameOrigin(prev.URL, req.URL) {
		req.Header.Del("Authorization")
		req.Header.Del("X-Signature")
		req.Header.Del("Signature")
		for key := range req.Header {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "authorization") || strings.Contains(lower, "signature") {
				req.Header.Del(key)
			}
		}
	}
	return nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}
