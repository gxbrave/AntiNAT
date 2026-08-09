# AntiNAT v1.0-beta Master Orchestration Plan

> **For the orchestration AI:** This is the only plan allowed to schedule, integrate, promote, or reject Coding sub-plans. Do not implement production features directly from this file. Dispatch one coding context per child plan, then use separate spec and quality reviewers before integration.

**Goal:** Coordinate 19 isolated Coding plans into one reproducible, secure, usable AntiNAT v1.0-beta without cross-agent file races, hidden scope changes, unverifiable network claims, or self-approved code.

**Architecture:** Work proceeds on an `integration/v1-beta` branch in dependency waves. Every Coding AI receives one child plan, an exact base SHA, and only the handoffs from its dependencies. Each child has exclusive file ownership for its wave, uses strict RED→GREEN→REFACTOR, emits a machine-readable handoff, and is reviewed by fresh contexts before the orchestrator cherry-picks it.

**Tech Stack:** Go, SQLite, bbolt, Go templates + vanilla HTML/CSS/JS, Linux/Windows networking, STUN/PCP/NAT-PMP/UPnP, systemd/OpenRC/Windows Service, GitHub Actions.

---

## 1. Sources of truth and precedence

1. This orchestration plan.
2. Child plan being executed.
3. `/root/AntiNAT/.hermes/plans/2026-08-09_055007-antinat-v1-reviewed-execution-plan.md`.
4. `docs/protocol.md`, `docs/state-model.md`, `api/openapi.yaml`, fixtures created by P04 after they are frozen.
5. `/root/AntiNAT/antinat.txt` for product intent only.
6. The old v0.7 plan is background and cannot override v0.8 or a frozen contract.

Conflict rule: stop the child; create `.hermes/handoffs/Pxx-contract-change.md`; do not silently reinterpret a contract.

## 2. Definition of v1.0-beta

The beta is a real installable product, not a collection of packages. Required beta core:

- Controller and Agent start cleanly, reconnect, persist state, and expose health/readiness.
- Linux amd64 direct/manual TCP and UDP are end-to-end usable.
- STUN-only and gateway adapters exist behind truthful capability/evidence states; an adapter lacking real-device evidence is marked experimental rather than falsely supported.
- WAN publication uses provider-hidden challenge, same-path ACK, Agent control receipt, and `OPEN_FROM_VANTAGE` semantics.
- Public navigation home and authenticated four-tab admin UI work in Chinese and English.
- Forward creation, target hot update, online/offline deletion, node normal/force decommission, rate/statistics semantics, hooks, deployment profile, install/upgrade/purge work as documented.
- Linux systemd package path passes fresh install, restart, upgrade rollback, and purge. OpenRC/arm64/Windows/Docker are promoted only to the evidence level actually achieved.
- No Critical/High security findings; all required tests and release evidence validate against the exact artifact digest.

Beta does not claim arbitrary-NAT reachability, IPv6 Forward data plane, Controller relay, exact runtime splice bytes, universal Windows mode support, or formal GA performance SLOs.

## 3. Human inputs that must be recorded before execution

Create `.hermes/handoffs/project-inputs.json` with:

```json
{
  "module_path": "REQUIRED",
  "repository_owner": "REQUIRED",
  "controller_endpoint_for_real_tests": "REQUIRED_BEFORE_P19",
  "remote_probe_vantage": "REQUIRED_BEFORE_P10_REAL_WAN",
  "windows_test_host": "OPTIONAL_UNTIL_P18",
  "arm64_openrc_hosts": "OPTIONAL_UNTIL_P18",
  "router_inventory": [],
  "release_approver": "REQUIRED_BEFORE_P19",
  "docker_scope": "beta-or-experimental"
}
```

P01 may start only after `module_path` is set. Missing later hardware downgrades a capability; it must not be replaced with fabricated evidence.

## 4. Multi-agent execution contract

### 4.1 Branch and worktree isolation

The orchestrator owns `integration/v1-beta`. Each Coding AI works in a separate branch/worktree:

```bash
git worktree add /root/AntiNAT-worktrees/PXX -b ai/PXX-<slug> <exact-base-sha>
```

Rules:

- Never let two Coding AIs use `/root/AntiNAT/` as the same writable working tree.
- A child starts from the exact integrated SHA listed in its dispatch brief.
- No child merges/rebases/cherry-picks another child itself.
- No force-push, remote push, release, or destructive cleanup without orchestrator approval.
- Dependencies are consumed from integrated commits, not copied patches.

### 4.2 TDD and commits

For every behavior Story:

1. Write one focused failing test.
2. Run it and capture the expected RED reason.
3. Implement the minimum GREEN code.
4. Run focused test, affected package, then repository regression subset.
5. Refactor while green.
6. Commit one coherent Story.

No production code before its failing test. Spikes are allowed only in P02/P03; spike conclusions require assertions and evidence rather than production-quality APIs.

### 4.3 Handoff artifact

Every child writes `.hermes/handoffs/PXX.json` before review:

```json
{
  "plan": "PXX",
  "base_sha": "...",
  "head_sha": "...",
  "commits": ["..."],
  "files_changed": ["..."],
  "tests": [{"command":"...","exit_code":0,"summary":"..."}],
  "evidence": ["relative/path"],
  "contracts_consumed": [{"path":"...","sha256":"..."}],
  "contracts_changed": [],
  "capability_result": "PASS|SUPPORTED_WITH_LIMITS|NO_GO",
  "known_limits": [],
  "cleanup_done": true
}
```

A missing, malformed, or dishonest handoff is an integration failure.

### 4.4 Two-stage independent review

For every child:

1. **Spec reviewer:** receives child plan, frozen contracts, diff, tests, and handoff. It checks requirement compliance only.
2. **Quality/security reviewer:** receives diff and static/test output without implementer reasoning. It checks logic, races, security, leaks, portability, and test quality.
3. If either rejects, dispatch a separate fix AI limited to listed findings; rerun both reviews. Maximum two fix cycles before escalation.
4. The implementer never approves its own work.

Network/protocol children P02/P09/P10/P11/P12/P13 additionally need a network reviewer. P17 needs UI skills and browser review. P18 needs native-platform evidence review.

## 5. Child plan registry

| ID | Plan file | Depends on | Parallel wave | Primary ownership | Required exit |
|---|---|---|---|---|---|
| P01 | `01-governance-bootstrap.md` | inputs | W0 | repo/docs/toolchain/CI skeleton | clean bootstrap |
| P02 | `02-network-feasibility-spikes.md` | P01 | W1A | network spikes/evidence | network gates classified |
| P03 | `03-state-security-feasibility-spikes.md` | P01 | W1B | state/security spikes/evidence | state/security gates classified |
| P04 | `04-contract-freeze.md` | P02,P03 | W2 | protocol/state/API/installer contracts | machine-readable freeze |
| P05 | `05-protocol-domain-core.md` | P04 | W3 | protocol/config implementation | golden/fuzz pass |
| P06 | `06-controller-store-auth.md` | P05 | W4A | SQLite/store/auth services | migrations/backup/auth pass |
| P07 | `07-agent-localstate-reconciler.md` | P05 | W4B | bbolt/reconciler core | crash matrix pass |
| P08 | `08-enrollment-control-channel.md` | P06,P07 | W5A | enrollment/security/control WS | signed reconnect pass |
| P09 | `09-linux-tcp-direct-dataplane.md` | P07,P02 | W5B | route/PortRegistry/TCP proxy | direct data path pass |
| P10 | `10-wan-probe-activation-cli-e2e.md` | P08,P09,P06 | W6A | probe/activation/min API/CLI/apps | M1 E2E pass |
| P11 | `11-stun-shared-port.md` | P09,P04 | W6B | STUN codecs/clients/sockets | STUN gates pass |
| P12 | `12-gateway-traversal-detection.md` | P10,P11 | W7 | PCP/NAT-PMP/UPnP/strategy/detection | TCP traversal beta |
| P13 | `13-udp-dataplane.md` | P10,P11,P12 | W8 | UDP mux/sessions/probe | UDP E2E pass |
| P14 | `14-lifecycle-rotation-recovery.md` | P08,P12,P13 | W9 | delete/decommission/rotation/recovery | crash/reconnect pass |
| P15 | `15-controller-api-metrics-sse.md` | P14,P06 | W10 | complete API/SSE/metrics/rate | OpenAPI/API pass |
| P16 | `16-hooks-sandbox.md` | P14,P15,P03 | W11 | webhook/JS runner/broker | sandbox/SSRF pass |
| P17 | `17-web-ui-deployment.md` | P15,P16 | W12 | UI/assets/deployment command | browser/a11y pass |
| P18 | `18-installers-platforms.md` | P17,P14,P08 | W13 | installers/services/OCI/platform | install/upgrade/purge pass |
| P19 | `19-beta-integration-release.md` | P01-P18 | W14 | integration tests/release evidence only | beta candidate approved |

Only P02/P03, P06/P07, and P08/P09 are intended parallel pairs. P10/P11 may run in parallel only after P09 integration and only because their owned files are disjoint.

## 6. Dependency DAG

```text
P01
├── P02 ─┐
└── P03 ─┴─> P04 -> P05
                    ├─> P06 ─┐
                    └─> P07 ─┴─> P08 ─┐
                         └────────> P09 ├─> P10 ─┐
                                      └─> P11 ─┴─> P12 -> P13 -> P14
                                                                    ├─> P15 -> P16 -> P17 -> P18
                                                                    └───────────────────────────┘
P01..P18 -------------------------------------------------------------> P19
```

Before dispatch, the orchestrator must verify this DAG remains acyclic and every dependency handoff is integrated.

## 7. File ownership and transfer rules

- P04 freezes contract files. Later agents read them; contract edits require a proposal and orchestrator-approved new contract revision.
- P07 owns reconciler foundations; ownership of named extension files transfers serially to P10, then P14. No parallel edits.
- P08 owns control/enrollment; key rotation extension transfers to P14.
- P10 owns minimal API/router/app composition; full API ownership transfers to P15.
- P15 owns full router/API; hook-specific handler registration transfers serially to P16; UI assets remain P17-only.
- Migrations use one file per child (`0001_core`, `0002_control`, etc.) rather than editing old applied migrations.
- P19 must not fix production code directly. A failure is routed to the owning plan's fix AI and re-reviewed.

Any undeclared file edit is a spec-review failure.

## 8. Integration procedure per child

1. Verify dependency SHAs and contract hashes from the handoff.
2. Inspect changed files against declared ownership.
3. Run spec review.
4. Run static/security scan and independent quality review.
5. Re-run child focused tests on orchestrator host.
6. Cherry-pick candidate commits onto `integration/v1-beta`.
7. Run affected packages plus cumulative milestone suite.
8. Write `.hermes/handoffs/PXX-integrated.json` with integrated SHA.
9. Tag milestone only after its exit gate passes, e.g. `milestone/m1-direct-v4`.

If cherry-pick conflicts, reject integration and send the child back on the new base. The orchestrator must not manually resolve semantic conflicts.

## 9. Milestone promotion gates

### M0 after P04

- All spikes classified PASS/SUPPORTED_WITH_LIMITS/NO_GO with real evidence.
- Contracts and fixtures are machine-readable and hash-pinned.
- Unsupported capabilities removed/feature-gated before production coding.

### M1 after P10

- Empty-state Linux direct-v4 CLI E2E passes.
- Enrollment, signed control, target hot update, restart-unverified-reprobe, and online Forward delete pass.

### M2 after P12

- TCP STUN and each gateway adapter pass their declared evidence level.
- FIRST_HOP_MAPPED never publishes as verified.
- Detection/profile/fingerprint and cleanup work.

### M3 after P14

- UDP end-to-end, offline Forward delete, normal/force node deletion, key rotation and recovery crash tests pass.

### Product complete after P17

- Full API, SSE, rate/stat semantics, hooks, bilingual UI, navigation and deployment flow pass.

### Platform complete after P18

- Linux systemd fresh install/restart/upgrade rollback/purge pass.
- Other platforms are promoted only to their evidence-backed status.

### v1.0-beta after P19

- Exact release digest passes beta gates; no post-test rebuild.
- Support matrix and README make no broader claims than evidence.
- Rollback and known-limit documentation are complete.

## 10. Cumulative test matrix

At each integration point run the child suite plus applicable cumulative commands:

```bash
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
go test ./test/e2e -count=1 -v
sudo -E go test -tags=netns ./test/integration/... -count=1 -v
```

Native Windows/OpenRC/arm64 and real-WAN tests cannot be replaced with cross-builds. Infrastructure failures may retry once; deterministic failures never retry to green.

## 11. Beta release blocking rules

Block release for:

- Critical/High security finding;
- data race, panic, unbounded resource growth, stale publication, deletion resurrection, token/secret leak;
- failed install/upgrade rollback/purge on primary Linux target;
- missing exact-digest evidence or malformed handoff;
- Controller carrying user payload;
- unsupported capability shown as supported;
- UI making stale/unverified endpoint appear verified.

Non-blocking only when explicitly documented and feature-gated: unavailable Windows/arm64/router evidence, formal 2 Gbps/`<1 ms` GA SLO, JS runner disabled in favor of webhook-only.

## 12. Final assembly and rollback

P19 builds from the integrated SHA once, records digest, and runs all release tests against those exact artifacts. Promotion only changes metadata, never binaries. On failure, revert the last integrated child commit range or route a fix to the owning child. Preserve database/store compatibility and never roll back a delete/decommission fact without recovery reconciliation.
