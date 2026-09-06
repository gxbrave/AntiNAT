//go:build linux

package datapath

import (
	"bytes"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCPUAllocationAndRSSBaselineIsEvidenceOnly(t *testing.T) {
	payload := bytes.Repeat([]byte("baseline"), 128*1024)
	for _, spliceEligible := range []bool{true, false} {
		name := "buffered"
		if spliceEligible {
			name = "eligible"
		}
		t.Run(name, func(t *testing.T) {
			runtime.GC()
			beforeRSS := residentBytes(t)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			var total int64
			for range 8 {
				got, copied := exerciseTCPPath(t, payload, spliceEligible)
				if !bytes.Equal(got, payload) {
					t.Fatal("baseline payload mismatch")
				}
				total += copied
			}
			duration := time.Since(started)
			runtime.ReadMemStats(&after)
			afterRSS := residentBytes(t)
			if total != int64(8*len(payload)) {
				t.Fatalf("total bytes = %d", total)
			}
			t.Logf(
				"host=%s/%s path=%s bytes=%d duration=%s total_alloc_delta=%d rss_before=%d rss_after=%d rss_delta=%d label_only=true",
				runtime.GOOS,
				runtime.GOARCH,
				Classify(spliceEligible).DataPath,
				total,
				duration,
				after.TotalAlloc-before.TotalAlloc,
				beforeRSS,
				afterRSS,
				afterRSS-beforeRSS,
			)
		})
	}
}

func residentBytes(t *testing.T) int64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		t.Fatalf("invalid /proc/self/statm: %q", data)
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return pages * int64(os.Getpagesize())
}
