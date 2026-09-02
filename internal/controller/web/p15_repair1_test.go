package web_test

// P15 repair cycle-1 focused web tests for the durable bounded SSE handler
// (H8): subscriber capacity is bounded (a new stream beyond the cap is refused
// 503 instead of consuming unbounded memory) and Last-Event-ID + redaction
// still work on the canonical handler.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/controller/web"
)

type eventStoreStub struct{ events []store.AdminEvent }

func (s *eventStoreStub) AdminEventsAfter(cursor int64, limit int) ([]store.AdminEvent, error) {
	out := make([]store.AdminEvent, 0)
	for _, e := range s.events {
		if e.ID > cursor {
			out = append(out, e)
		}
	}
	return out, nil
}

// RED H8: before the bounded subscriber gate, every concurrent stream ran
// without a cap, so a flood of clients could consume unbounded memory. The
// gate now refuses a stream beyond MaxSubscribers with 503 UNAVAILABLE.
func TestP15Repair1H8SSEBoundedSubscribers(t *testing.T) {
	stub := &eventStoreStub{}
	handler := &web.SSEHandler{Store: stub, PollInterval: 10 * time.Millisecond, Batch: 10, MaxSubscribers: 1}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// The first stream stays open (polling, no terminal events).
	ctx := t.Context()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	resp1, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()

	// Give the first handler synchronous acquisition a chance to hold the slot.
	var slow io.Reader
	_ = slow
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

	// First stream already holds the single slot: a second stream must be 503.
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

// RED H8: the canonical handler replays from Last-Event-ID and redacts
// secret-shaped payload fields.
func TestP15Repair1H8SSEReplayAndRedaction(t *testing.T) {
	stub := &eventStoreStub{events: []store.AdminEvent{
		{ID: 1, EventType: "test", Payload: `{"safe":"yes","token":"top-secret"}`},
	}}
	handler := &web.SSEHandler{Store: stub, PollInterval: 10 * time.Millisecond, Batch: 10}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header.Set("Last-Event-ID", "0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	buf := make([]byte, 512)
	done := make(chan struct{})
	var n int
	go func() {
		n, _ = resp.Body.Read(buf)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out reading SSE stream")
	}
	text := string(buf[:n])
	if !strings.Contains(text, "id: 1") || strings.Contains(text, "top-secret") || !strings.Contains(text, `"safe":"yes"`) {
		t.Fatalf("stream payload=%q", text)
	}
}
