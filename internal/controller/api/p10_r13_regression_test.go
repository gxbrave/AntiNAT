package api_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// R13 RED: the unauthenticated bootstrap boundary must apply the same frozen
// strict JSON rules as signed control payloads before any administrator side
// effect occurs. Duplicate keys plus a trailing object were accepted by the
// pre-repair decoder and selected the attacker's last value.
func TestR13AdminBootstrapRejectsAmbiguousJSON(t *testing.T) {
	srv, st := newTestServer(t)
	raw := []byte(`{"username":"first","username":"second","password":"operator-password"} {}`)
	resp, err := http.Post(srv.URL+"/api/v1/auth/init", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("ambiguous bootstrap status = %d (%s), want 400", resp.StatusCode, body)
	}
	if count, err := st.CountUsers(); err != nil || count != 0 {
		t.Fatalf("ambiguous bootstrap created %d users (err=%v), want zero", count, err)
	}
}

// R13 RED: REST ingress uses protocol.MaxPayloadBytes, not a separate 1 MiB
// limit. The body is syntactically valid so this specifically exercises the
// protocol payload cap rather than malformed JSON handling.
func TestR13AdminBootstrapUsesProtocolPayloadLimit(t *testing.T) {
	srv, st := newTestServer(t)
	raw := []byte(`{"username":"` + strings.Repeat("u", protocol.MaxPayloadBytes) + `","password":"operator-password"}`)
	resp, err := http.Post(srv.URL+"/api/v1/auth/init", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("oversize bootstrap status = %d (%s), want 413", resp.StatusCode, body)
	}
	if count, err := st.CountUsers(); err != nil || count != 0 {
		t.Fatalf("oversize bootstrap created %d users (err=%v), want zero", count, err)
	}
}

// R13 RED: node creation and its idempotency response are one transaction.
// Concurrent identical requests must replay the winner's exact response,
// never create one node while returning a conflict from the loser's gap.
func TestR13ConcurrentNodeCreateReplaysAtomicResponse(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	type result struct {
		status int
		body   string
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/nodes", strings.NewReader(`{"name":"node-r13"}`))
			if err != nil {
				results <- result{err: err}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "node-r13-same-key")
			req.AddCookie(cookie)
			resp, err := srv.Client().Do(req)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			results <- result{status: resp.StatusCode, body: string(body), err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var first string
	for got := range results {
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.status != http.StatusCreated {
			t.Fatalf("concurrent node create status = %d (%s), want replayed 201", got.status, got.body)
		}
		if first == "" {
			first = got.body
		} else if got.body != first {
			t.Fatalf("idempotent responses differ:\nfirst=%s\nsecond=%s", first, got.body)
		}
	}
	nodes, err := st.ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "node-r13" {
		t.Fatalf("nodes after concurrent idempotent create = %+v, want one node-r13", nodes)
	}
}
