package hook

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SignedRequest is a fully prepared outbound webhook request. It is built only
// by the broker/preparer after the final allowlisted request is validated and
// normalized; never by the runner and never from raw secret material.
type SignedRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

// SendResult is the minimal transport outcome the dispatcher records.
type SendResult struct {
	StatusCode int
}

// Sender delivers one SignedRequest. The production sender is the SSRF-safe
// client (internal/hook/client.go); tests inject a fake transport.
type Sender interface {
	Send(ctx context.Context, req *SignedRequest) (*SendResult, error)
}

// DeliveryPreparer converts a claimed delivery into the final SignedRequest.
// The production preparer composes the broker and the isolated runner; tests
// inject a fixed preparer to exercise dispatcher semantics.
type DeliveryPreparer interface {
	Prepare(ctx context.Context, d Delivery) (*SignedRequest, error)
}

// DispatcherConfig configures the at-least-once delivery pump.
type DispatcherConfig struct {
	// Interval is the polling cadence (default 250ms).
	Interval time.Duration
	// Batch bounds the deliveries claimed per pump (default 16).
	Batch int
}

// Dispatcher is the async at-least-once pump. It claims due deliveries,
// prepares+sends them, and records success/failure with bounded backoff.
type Dispatcher struct {
	store    *Store
	sender   Sender
	preparer DeliveryPreparer
	interval time.Duration
	batch    int

	runOnce sync.Once
}

// NewDispatcher builds the pump. Store, sender and preparer are required; a
// nil sender/preparer fail closed at pump time.
func NewDispatcher(store *Store, sender Sender, preparer DeliveryPreparer, cfg DispatcherConfig) *Dispatcher {
	if cfg.Interval <= 0 {
		cfg.Interval = 250 * time.Millisecond
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 16
	}
	return &Dispatcher{
		store: store, sender: sender, preparer: preparer,
		interval: cfg.Interval, batch: cfg.Batch,
	}
}

// Run starts the pump and blocks until ctx is cancelled (exactly one Run per
// Dispatcher).
func (d *Dispatcher) Run(ctx context.Context) {
	d.runOnce.Do(func() {
		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()
		d.pumpOnce()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.pumpOnce()
			}
		}
	})
}

// PumpOnce runs one claim+deliver batch synchronously (test/operational hook;
// Run calls pumpOnce on its ticker).
func (d *Dispatcher) PumpOnce() int { return d.pumpOnce() }

// pumpOnce claims one batch and delivers each item. It returns the number of
// deliveries handled (0 when the store/sender/preparer is not ready).
func (d *Dispatcher) pumpOnce() int {
	if d.store == nil || d.sender == nil || d.preparer == nil {
		return 0
	}
	claimed, err := d.store.ClaimDue(d.batch)
	if err != nil {
		return 0
	}
	for _, delivery := range claimed {
		d.deliver(delivery)
	}
	return len(claimed)
}

// deliver prepares and sends one claimed delivery, then records the outcome.
// The error passed to MarkFailed is scrubbed (preparer/sender errors are
// already secret-free; scrubError is the last control-character line).
func (d *Dispatcher) deliver(delivery Delivery) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := d.preparer.Prepare(ctx, delivery)
	if err != nil {
		_ = d.store.MarkFailed(delivery.ID, scrubError(err))
		return
	}
	res, err := d.sender.Send(ctx, req)
	if err != nil {
		_ = d.store.MarkFailed(delivery.ID, scrubError(err))
		return
	}
	if res != nil && res.StatusCode >= 400 {
		_ = d.store.MarkFailed(delivery.ID, "webhook responded status="+itoa(res.StatusCode))
		return
	}
	_ = d.store.MarkDelivered(delivery.ID)
}

// ScrubError exposes scrubError for verification.
func ScrubError(err error) string { return scrubError(err) }

// scrubError bounds the stored error message and removes control characters so
// a hostile preparer/sender error can never inject log lines or secret
// material into the durable last_error column.
func scrubError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 256 {
		s = s[:256]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
