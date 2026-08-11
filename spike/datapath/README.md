# TCP data-path observability and budget spike

Question: can AntiNAT use the standard Go TCP copy path without falsely claiming exact runtime splice activity or under-budgeting buffered fallback?

The spike compares:

- raw `*net.TCPConn` to `*net.TCPConn` through `io.Copy`, labeled `go_tcp_copy_splice_eligible`;
- wrapped reader/writer interfaces with an explicit 32 KiB buffer, labeled `go_tcp_copy_buffered`.

Both paths transfer and hash-check the same payload. The evidence model exposes only `eligible`, never `zero_copy_active`, exact `splice_bytes`, or exact `buffered_fallback_bytes`. It reserves two 32 KiB directional buffers (64 KiB per bidirectional connection) even for an eligible connection because standard-library fallback is not under AntiNAT's pool control.

`TestCPUAllocationAndRSSBaselineIsEvidenceOnly` records monotonic duration, Go total-allocation delta, and Linux RSS before/after for both paths. Those values are observations, not pass/fail performance claims or release SLOs.

Verdict: SUPPORTED_WITH_LIMITS.

The standard path is eligible on Linux, but no runtime exact-splice claim is supportable from `io.Copy` alone. P04 should freeze the eligibility labels and 64 KiB pessimistic fallback reservation. Any future exact byte accounting requires a separate ADR, custom data path, benchmarks, and strace/eBPF lab evidence. Windows remains buffered unless native evidence proves another path.
