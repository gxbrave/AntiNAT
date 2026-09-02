package hook

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// SignatureAlgorithm is the frozen secret algorithm set (api/openapi.yaml
// HookSecret.algorithm is a free string; the broker accepts only these).
type SignatureAlgorithm string

const (
	AlgorithmHMACSHA1   SignatureAlgorithm = "HMAC-SHA1"
	AlgorithmHMACSHA256 SignatureAlgorithm = "HMAC-SHA256"

	// SignaturePlacementHeader signs the webhook body into X-Hook-Signature.
	SignaturePlacementHeader = "header"
	// SignaturePlacementQuery appends a Signature query param (provider-style,
	// e.g. the AliDNS fixture).
	SignaturePlacementQuery = "query"

	// maxCapabilityCalls bounds an explicit sign request (a delivery signs at
	// most once; the bound exists so a runner-requested call count cannot turn
	// the broker into an unlimited HMAC oracle).
	maxCapabilityCalls = 8
)

// ValidateAlgorithm reports whether an algorithm string is supported.
func ValidateAlgorithm(s string) bool {
	return SignatureAlgorithm(s) == AlgorithmHMACSHA1 || SignatureAlgorithm(s) == AlgorithmHMACSHA256
}

// SignIntent is the ONE validated, normalized, final allowlisted request the
// broker may sign. It is bound to {hook id, secret id, algorithm, method,
// scheme/host/port/path, final params, max calls}. The runner may request
// arbitrary bytes, but the broker builds and signs only this canonical intent.
type SignIntent struct {
	HookID    string
	SecretID  string
	Algorithm string
	Method    string
	Scheme    string
	Host      string
	Port      int
	Path      string
	Query     map[string]string // final allowlisted params (canonicalized)
	Body      []byte
	Placement string // SignaturePlacementHeader | SignaturePlacementQuery
	MaxCalls  int
}

// Capability is the signed capability bound the broker returns. MaxCalls is
// enforced with a single-call-per-capability counter: a delivery signs exactly
// once; the fixture may request a higher count and the broker refuses past it.
type Capability struct {
	HookID    string
	SecretID  string
	Algorithm string
	Method    string
	Scheme    string
	Host      string
	Port      int
	Path      string
	QueryHash string
	// MaxCalls is the signing-call bound set by the broker per Sign.
	MaxCalls int32
	calls    atomic.Int32
}

// ErrCapabilityExhausted refuses a signature past the capability call bound.
var ErrCapabilityExhausted = errors.New("hook: signing capability call bound exceeded")

// ErrContributionMismatch refuses to sign a runner contribution that does not
// match the broker's own canonical normalization (never an arbitrary HMAC
// oracle).
var ErrContributionMismatch = errors.New("hook: runner contribution does not match the canonical request")

// Broker signs exactly one normalized final allowlisted request per delivery,
// decrypting the secret value in-process; the plaintext never enters the
// runner, logs, error strings, or the delivery payload.
type Broker struct {
	store *Store
	keys  *SecretKeystore
}

// NewBroker builds the signing broker.
func NewBroker(store *Store, keys *SecretKeystore) *Broker {
	return &Broker{store: store, keys: keys}
}

// Sign validates and signs one intent, returning the final SignedRequest and
// the bound capability. The plaintext secret value never leaves Sign.
func (b *Broker) Sign(ctx context.Context, intent SignIntent) (*SignedRequest, Capability, error) {
	if b == nil || b.store == nil || b.keys == nil {
		return nil, Capability{}, errors.New("hook: broker is not configured")
	}
	if err := validateIntent(intent); err != nil {
		return nil, Capability{}, err
	}
	row, err := b.store.GetSecretRow(intent.SecretID)
	if err != nil {
		return nil, Capability{}, fmt.Errorf("hook: bound secret: %w", err)
	}
	if !strings.EqualFold(row.Algorithm, intent.Algorithm) {
		return nil, Capability{}, fmt.Errorf("hook: secret algorithm %s does not match requested %s", row.Algorithm, intent.Algorithm)
	}
	secret, err := b.keys.Decrypt(row.KeyID, row.Ciphertext)
	if err != nil {
		return nil, Capability{}, err
	}
	defer zeroize(secret)

	canonical := CanonicalQuery(intent.Query)
	sts := StringToSign(intent.Method, intent.Path, canonical)
	encoded := base64.StdEncoding.EncodeToString(signBytes(intent.Algorithm, secret, []byte(sts)))

	maxCalls := intent.MaxCalls
	if maxCalls <= 0 {
		maxCalls = 1
	}
	if maxCalls > maxCapabilityCalls {
		return nil, Capability{}, fmt.Errorf("hook: requested %d signing calls exceeds the bound %d", maxCalls, maxCapabilityCalls)
	}
	cap := Capability{
		HookID: intent.HookID, SecretID: intent.SecretID, Algorithm: intent.Algorithm,
		Method: intent.Method, Scheme: intent.Scheme, Host: intent.Host, Port: intent.Port,
		Path: intent.Path, QueryHash: sha256Hex(canonical), MaxCalls: int32(maxCalls),
	}

	req := &SignedRequest{
		Method:  intent.Method,
		URL:     buildURL(intent, ""),
		Headers: make(map[string][]string, 4),
		Body:    append([]byte(nil), intent.Body...),
	}
	switch intent.Placement {
	case SignaturePlacementQuery:
		req.URL = buildURL(intent, encoded)
	case SignaturePlacementHeader:
		setSignedHeader(req, "X-Hook-Signature", signHeaderValue(intent.Algorithm, secret, intent.Body))
	}
	return req, cap, nil
}

// VerifyContribution is the "not an arbitrary HMAC oracle" gate: the broker
// accepts a runner-produced canonical contribution only when it matches the
// broker's own normalization of the SAME final allowlisted request.
func VerifyContribution(intent SignIntent, contribution []byte) error {
	var got struct {
		CanonicalQuery string `json:"canonical_query"`
		StringToSign   string `json:"string_to_sign"`
	}
	if err := protocol.DecodeStrictJSONInto(contribution, &got); err != nil {
		return fmt.Errorf("hook: contribution schema: %w", err)
	}
	canonical := CanonicalQuery(intent.Query)
	if got.CanonicalQuery != canonical {
		return fmt.Errorf("%w: canonical query differs", ErrContributionMismatch)
	}
	if got.StringToSign != StringToSign(intent.Method, intent.Path, canonical) {
		return fmt.Errorf("%w: string-to-sign differs", ErrContributionMismatch)
	}
	return nil
}

// CanSign consumes one signing call and reports whether the capability has
// remaining calls (fail closed past MaxCalls). It is atomic (concurrent-safe).
func (c *Capability) CanSign() bool {
	if c == nil {
		return false
	}
	max := c.MaxCalls
	if max <= 0 {
		max = 1
	}
	return c.calls.Add(1) <= max
}

func setSignedHeader(req *SignedRequest, key, value string) {
	req.Headers[http.CanonicalHeaderKey(key)] = []string{value}
}

func validateIntent(intent SignIntent) error {
	switch strings.ToUpper(intent.Method) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD":
	default:
		return fmt.Errorf("hook: unsupported method %q", intent.Method)
	}
	switch intent.Scheme {
	case "https":
	case "http":
		return errors.New("hook: http signing intent is rejected (https required)")
	default:
		return fmt.Errorf("hook: unsupported scheme %q", intent.Scheme)
	}
	if intent.Host == "" {
		return errors.New("hook: host is required")
	}
	if lit, ok := canonicalIPLiteral(intent.Host); ok {
		if addressBlocked(lit) {
			return errBlockedAddress
		}
	} else if ambiguousIPLiteral(intent.Host) {
		return errors.New("hook: ambiguous ip-literal host is rejected")
	} else if err := hostnameIssues(intent.Host); err != nil {
		return err
	}
	if intent.Port < 1 || intent.Port > 65535 {
		return fmt.Errorf("hook: invalid port %d", intent.Port)
	}
	if !strings.HasPrefix(intent.Path, "/") || strings.ContainsAny(intent.Path, "\r\n") {
		return errors.New("hook: invalid path")
	}
	if intent.SecretID == "" || intent.HookID == "" {
		return errors.New("hook: hook and secret ids are required")
	}
	if !ValidateAlgorithm(intent.Algorithm) {
		return fmt.Errorf("hook: unsupported algorithm %q", intent.Algorithm)
	}
	if intent.Placement != SignaturePlacementQuery && intent.Placement != SignaturePlacementHeader {
		return errors.New("hook: invalid signature placement")
	}
	return nil
}

// PercentEncode implements RFC 3986 percent-encoding (uppercase hex; the
// unreserved set A-Z a-z 0-9 - _ . ~ is left intact). It is the canonical
// encoder shared by the broker and the runner runtime so both sides agree.
func PercentEncode(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0xf])
		}
	}
	return b.String()
}

// CanonicalQuery sorts the params by name (byte order) and builds
// name=value&... with RFC3986 encoding.
func CanonicalQuery(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(PercentEncode(k))
		b.WriteByte('=')
		b.WriteString(PercentEncode(params[k]))
	}
	return b.String()
}

// StringToSign is the canonical signed string (AliDNS v1 convention):
// METHOD&PercentEncode(path)&PercentEncode(canonicalQuery).
func StringToSign(method, path, canonicalQuery string) string {
	return strings.ToUpper(method) + "&" + PercentEncode(path) + "&" + PercentEncode(canonicalQuery)
}

func signBytes(algorithm string, secret []byte, msg []byte) []byte {
	mac := hmac.New(digest(algorithm), append(secret, '&'))
	mac.Write(msg)
	return mac.Sum(nil)
}

func signHeaderValue(algorithm string, secret, body []byte) string {
	mac := hmac.New(digest(algorithm), secret)
	mac.Write(body)
	lower := strings.ToLower(strings.TrimPrefix(algorithm, "HMAC-"))
	return lower + "=" + hex.EncodeToString(mac.Sum(nil))
}

func digest(algorithm string) func() hash.Hash {
	if SignatureAlgorithm(algorithm) == AlgorithmHMACSHA1 {
		return sha1.New
	}
	return sha256.New
}

// buildURL renders scheme://host[:port]/path. When signature is non-empty the
// Signature query param is added to the canonical query (provider-style).
func buildURL(intent SignIntent, signature string) string {
	u := url.URL{Scheme: intent.Scheme, Host: joinHostPort(intent.Host, intent.Port), Path: intent.Path}
	if signature == "" {
		return u.String()
	}
	query := make(map[string]string, len(intent.Query)+1)
	for k, v := range intent.Query {
		query[k] = v
	}
	query["Signature"] = signature
	u.RawQuery = CanonicalQuery(query)
	return u.String()
}

func joinHostPort(host string, port int) string {
	if port == 80 || port == 443 {
		return host
	}
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		return "[" + host + "]:" + itoa(port)
	}
	return host + ":" + itoa(port)
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
