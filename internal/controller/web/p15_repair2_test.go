package web_test

// P15 repair cycle-2 RED P1-A: the SSE subscriber gate was lazily initialized
// inside ServeHTTP (`if h.subMu == nil { h.subMu = make(...) }`). A handler
// built with subMu == nil faces its first concurrent burst of /api/v1/events
// with an unsynchronized first touch — a DATA RACE (the 200-concurrent-request
// review repro pointed at sse.go L76-77). NewSSEHandler now initializes the
// gate during construction and ServeHTTP only reads it. This file pins that
// behaviour with a -race oracle and keeps the 503 cap semantics.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/web"
)

// RED P1-A oracle: a *freshly constructed* handler (the App path) serves a
// concurrent burst of first-time streams. Run with -race; pre-fix the
// lazy-init write in ServeHTTP raced with concurrent reads.
func TestP15Repair2SSEHandlerFirstConcurrentBurstRaceFree(t *testing.T) {
	for round := 0; round < 3; round++ {
		handler := web.NewSSEHandler(&eventStoreStub{}, 5*time.Millisecond, 10, 32, 0)
		ts := httptest.NewServer(handler)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				resp.Body.Close()
			}()
		}
		wg.Wait()
		ts.Close()
	}
}

// The gate capacity still holds after the constructor change: with
// MaxSubscribers=1 the second concurrent stream is refused 503 UNAVAILABLE
// (backpressure, no unbounded buffering).
func TestP15Repair2SSEHandlerCapStillRefusesOverCapacity(t *testing.T) {
	stub := &eventStoreStub{}
	handler := web.NewSSEHandler(stub, 10*time.Millisecond, 10, 1, 0)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	ctx := t.Context()
	req1, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if resp1.StatusCode == http.StatusOK && resp1.Header.Get("Content-Type") == "text/event-stream" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("first stream never started: status=%d", resp1.StatusCode)
		}
		time.Sleep(5 * time.Millisecond)
	}

	resp2, err := http.DefaultClient.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second subscriber status = %d body=%s, want 503", resp2.StatusCode, body)
	}
}

// A zero-value handler (constructed without NewSSEHandler) never initializes
// subMu, so every stream fails closed with 503 rather than racing on a first
// touch. This documents the construction contract: build via NewSSEHandler.
func TestP15Repair2SSEHandlerZeroValueFailsClosed(t *testing.T) {
	var handler web.SSEHandler // subMu == nil
	ts := httptest.NewServer(&handler)
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "UNAVAILABLE") {
		t.Fatalf("zero-value handler status = %d body=%s, want 503 UNAVAILABLE", resp.StatusCode, body)
	}
}