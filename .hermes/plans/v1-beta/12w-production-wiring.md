# P12W — Close the P12 Production-Composition Gap (Manager/Detector/Adapters/Durable Journal) Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Make the P12 gateway-traversal library reachable as a production Agent Forward path: construct the traversal `Manager` and `Detector` in the composed Agent, register PCP/NAT-PMP/UPnP adapters, inject same-source STUN, provide a durable bbolt `JournalStore`, translate Forward strategies, replay the durable journal at startup, and wire route/resume/loss lifecycle state into activation.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P10, P11, P12, P13 integrated. Named ownership boundary recorded in `docs/development/CURRENT_STATE.md`.

**Wave:** pre-P14 follow-up (owned before P14 starts)

**Preferred model profile:** Distributed-systems/network-composition model

---

## Owned files

Create/own:

- `internal/agent/localstate/mapping_journal.go` + `mapping_journal_test.go` — bbolt `traversal.JournalStore` adapter writing the **existing** `mapping_journal` bucket (schema v1 already creates it; no agent schema migration needed).
- `internal/agent/strategy.go` + `strategy_test.go` — strategy translation `planFor(spec, profile) → PlanRequest`, the `auto` → concrete resolver, and the stun-only composer.
- `internal/agent/profiles.go` — detection-profile cache as a state-dir JSON file (mirrors `internal/agent/localstate/marker.go` file pattern); staleness via `Profile.IsStale`.
- `internal/agent/traversal_lifecycle.go` — `OnMappingDegraded/Lost/Recovered` handlers updating activation and persisting+send status, following the `onForwardRunError` lock discipline.
- `internal/agent/p12w_composition_test.go`, `p12w_recovery_test.go`, `p12w_lifecycle_test.go`.
- `test/integration/agent_gateway_test.go` (`//go:build linux && netns`) — composed `dataPlane`/Manager against real miniupnpd+coturn via `test/netns/traversal_lab.sh`.

Modify (P12W-owned via ownership transfer in this handoff):

- `internal/agent/app.go` — `Config` += `StunServers []string`, `AutoOrder []protocol.Strategy`; `New()` builds adapters/plainManager/gatewayManager/Detector; `dataPlaneConfig` += `*traversal.Manager`, `*traversal.Detector`; strategy router in `apply`; `forwardLease` abstraction replacing `socketLease`; `acquisitionMeta` per-actor; `appliedState` extras (`MappingJournalRef`, `AssignedGatewayPort`, `PublicPort` — frozen fields already declared); lifecycle callbacks; strategy-aware capability and liveness; strategy-aware `reopen`/`recover`; `replayJournalBoundaries()`.
- `cmd/antinat-agent/main.go` — flags/env to surface `StunServers`/`AutoOrder` defaults (P15 owns the full operator API later).

## Ownership transfer / integration notes

- P14 later owns: renew/delete-after-restart that decodes adapter `JournalRecord.State []byte` back to typed adapter state (no such decoder exists today), orphaned-journal evacuation, decommission/key-rotation interaction with mapping identity, `docs/recovery.md`, controller `0008_lifecycle.sql`. P12W does NOT implement decode; it attaches refs and classifies superseded/orphaned records for P14.
- Do not touch `migrations/*.sql` (last controller migration is `0007_traversal.sql`; P14 owns `0008_lifecycle.sql`). Do not touch `test/contracts/**` (frozen). Agent bbolt schema stays at version 3 (the `mapping_journal` bucket already exists since v1); the detection-profile cache must NOT require an agent schema migration (use the marker-style file object).
- The `stun` package is unchanged and is injected via seams (`stun.NewManagerObserver`, `stun.NewSharedPortRegistry`, `stun.LeaseSource`, `stun.NewSharedPortRegistry`). The accepted `traversal` library is unchanged except additive RED→GREEN-tested surfaces if an additive seam is genuinely required — prefer composition-root injection over library edits. `internal/forward/udp` (P13) stays untouched.

## Orchestrator-resolved decisions (binding)

- **D1 — Two Manager instances, not one.** `plainManager` uses `traversal.PortRegistrySource{Registry: d.registry}` (direct-v4, manual-static; preserves the accepted direct path byte-identical and UDP adjacency); `gatewayManager` uses `stun.LeaseSource{Registry: stun.NewSharedPortRegistry()}` (explicit-gateway; provides `SameTupleDialer` for the STUN seam). Both share Mappers/Journal/Clock/OnMapping* callbacks and `StunObserve`.
- **D2 — Journal within `localstate.Store`** (the `mapping_journal` bucket already exists at schema v1), not a separate DB file. Single bbolt lock, transactional adjacency with applied/tombstone rows for P14 atomic evacuation.
- **D3 — Detection-profile cache is a state-dir JSON file** (mirrors `marker.go`), not an agent bbolt v4 bucket (avoids a schema migration and cross-bucket consistency).
- **D4 — Pinned public port on NAT-PMP/IGDv1 degrades to a suggestion** (`PortPolicyAcceptAny`), the honest default; PCP/IGDv2 with a requested port use `PortPolicyStrict` when `CanRequestExact`.
- **D5 — Lifecycle callbacks are forward-scoped** with a mapped guard (re-check the forward is live and mapping-capable before touching activation); no library-level callback token. Document the residual stale-window in known_limits.

## Explicit non-goals

No UDP Manager path (P13 UDP stays direct-v4; `Manager.Acquire` is TCP-listener based); no UI/API; no installer; no adapter `State` decode; no real CPE/router/WAN claim; no controller SQL migration; no `recovery.md` (P14); no key rotation interaction (P14); no frozen contract changes.

## Stories

### Story 1: bbolt JournalStore adapter
- RED: `mapping_journal_test.go` opens a real `localstate.Store` (`t.TempDir()`), `store.MappingJournal()` satisfies `traversal.JournalStore`; Put/Get/Delete/List/ListByForward round-trip `EncodeJournalRecord`/`DecodeJournalRecord`; records survive `Close`+`Open` with `State []byte` and `Ownership` verbatim. Does not compile before GREEN.
- GREEN: file `localstate/mapping_journal.go`. Put/Delete = single `db.Update`; Get/List/ListByForward = single `db.View` (index-free full-scan + ForwardID filter, matching `MemoryJournal` semantics). Bounded-latency under the renewal lock (tiny single bucket ops).
- Files: `internal/agent/localstate/mapping_journal.go`, `mapping_journal_test.go`.

### Story 2: Production Manager/Detector construction, adapter registration, same-source STUN injection
- RED: an App-shaped composition whose `dataPlaneConfig.Manager` is non-nil applies a TCP `explicit-gateway` forward; the acquisition carries `JournalID != ""`, a Mapping with the mechanism's `Ownership`, and a STUN layer (`Layers[1].Kind == LayerKindSTUN`, `ParentLayer == 0`) when `StunServer` is configured. Before GREEN, `apply` rejects every non-direct strategy.
- GREEN: `New(cfg)` resolves the default gateway via `traversal.DefaultRouteSource(cfg.RouteTable)`; builds `pcp.NewAdapter` + `natpmp.NewAdapter` (Gateway = default-route gateway, port 5351) and `upnp.NewAdapter` (InterfaceIP = selection.Source); registers all three in `ManagerOptions.Mappers`; wires `stun.NewManagerObserver()` as `StunObserve` and `stun.LeaseSource` as gatewayManager.Listeners. Detector constructed with same Mappers + temp-socket `StunObserve` + `AutoOrder` + `StunServers`.
- Files: `internal/agent/app.go`, `internal/agent/strategy.go`, `internal/agent/p12w_composition_test.go`.

### Story 3: Strategy-aware TCP acquisition routing through Manager, preserving actor topology
- RED: (a) TCP `explicit-gateway` `dp.apply` returns applied state with `MappingJournalRef == acq.JournalID` and `AssignedGatewayPort == mapping.External.Port()`; (b) hot-update (same ID, new target, same transport+strategy) keeps the SAME acquisition running — `JournalID` unchanged, no new journal record; (c) strategy change in a hot-update fails closed (mirror of the transport-change rule).
- GREEN: `forwardLease` abstraction (`Tuple()`, `Release(context.Context) error`) with `registryLease`, `udpRegistryLease`, `acquisitionLease` adapters (`acquisitionLease.Release(ctx)` → `acq.Release(ctx)` deletes mapping+journal+listener); strategy router in `apply`; `acquisitionMeta` on the actor; `appliedState` extras. UDP path untouched.
- Files: `internal/agent/app.go`, `internal/agent/strategy.go`, `internal/agent/p12w_composition_test.go`.

### Story 4: Forward strategy translation + truthful failure surface
- RED: table-driven test asserting each `protocol.Strategy × ForwardSpec` maps to the expected `PlanRequest`/route; absent operator input produces a FAILED apply (not an Applied state):
  - `manual-static-v4` with empty `ManualExpectedEndpoint` → apply error;
  - `explicit-gateway` with no resolved mapping layer in the profile → apply error;
  - `stun-only` with no configured STUN server → apply error;
  - `auto` with no stored/passing profile → apply error.
- GREEN: pure `planFor` + resolver functions in `internal/agent/strategy.go`; reconcile layer surfaces each as `OutcomeFailed`, old desired retained (LKG preserved), PARTIAL report.
- Files: `internal/agent/strategy.go`, `internal/agent/strategy_test.go`.

### Story 5: auto strategy resolution from a persisted detection profile
- RED: `auto` forward applies only when the detection profile's `DefaultStrategy` is PASSED and non-empty; a stale profile fails rather than silently using old capability.
- GREEN: one-shot/periodic detection job runs `Detector.Run` and saves the profile via `profiles.go`; `auto` apply reads the cached profile and routes to the concrete strategy; UDP `auto` resolves to direct-v4 (`ErrUDPDetectionDeferred`).
- Files: `internal/agent/profiles.go`, `internal/agent/strategy.go`, `internal/agent/app.go`, `internal/agent/p12w_composition_test.go`.

### Story 6: Strategy-aware capability & liveness (gateway nodes not permanently capability-lost)
- RED: on a NAT-CPE route table (private source), `capabilityCheck()` currently returns `ErrCapabilityLost`; a gateway forward on a private-source node must apply.
- GREEN: redefine `capabilityReady` as "route table usable + fingerprint known"; per-strategy requirements move into apply/reopen (global source required only for direct; gateway/manual/stun-only need `DefaultRouteSource`; shared-port gate for STUN on non-Linux); `monitorLiveness` keys teardown on fingerprint change and rebuilds adapters+Managers on restore so acquisitions re-map onto a changed gateway. P14 owns suspend/resume finesse.
- Files: `internal/agent/app.go`, `internal/agent/p12w_composition_test.go`.

### Story 7: OnMapping* lifecycle → activation
- RED: scripted mapper forces 3 consecutive renewal failures then a success (pattern from `manager_test.go`); assert activation snapshot moves `keepalive_state DEGRADED`, then `LOST` with `publication_state STALE` + `wan_reachability NOT_TESTED`, then `keepalive_state HEALTHY` on recovery — frozen axes only, driven through the Agent's `a.activation(...)` + `SaveActivationSnapshot` + `sendActivationStatus`.
- GREEN: `traversal_lifecycle.go` handlers: Degraded → `keepalive_state DEGRADED`; Lost → `keepalive_state LOST` + `mapping_state LOST` + `EvidenceLost()`; Recovered → `keepalive_state HEALTHY` and restore `mapping_state` from `acq.Verdict`+`CurrentMapping()`. Callbacks run off-loop and contained (`ManagerOptions` doc); handlers follow the `onForwardRunError` lock discipline.
- Files: `internal/agent/traversal_lifecycle.go`, `internal/agent/app.go`, `internal/agent/p12w_lifecycle_test.go`.

### Story 8: Startup journal replay + mapping ref exposure
- RED: restart simulation — write a journal record + an applied record for a gateway forward via real store methods; `dp.recover` reopens the forward through the Manager, the new applied record's `MappingJournalRef` is the NEW `JournalID`, activation `mapping_state` reflects the acquisition verdict, and superseded/orphaned records remain in the bucket (not silently deleted) and are surfaced by a diagnostic.
- GREEN: strategy-aware `reopen` + `dataPlane.replayJournalBoundaries()` reconciling durable journal records against live applied forwards (delete-fence is the no-resurrection authority; fenced forwards are never reopened). Superseded/orphaned records are listed, never deleted (P14 evacuates with State decode).
- Files: `internal/agent/app.go`, `internal/agent/p12w_recovery_test.go`.

### Story 9: netns lab composition evidence
- RED: `agent_gateway_test.go` applies an `explicit-gateway` forward through the composed Manager+adapters+journal inside the lab topology; the vantage connects to the mapped external port; after release the CPE nft ruleset holds no forward rule. Fails until Story 2/3 land.
- GREEN: full composition + ownership evidence against real daemons (miniupnpd 2.3.4 + coturn in netns). No real CPE/WAN claim.
- Files: `test/integration/agent_gateway_test.go`, `internal/agent/app.go`.

### Story 10: Windows/ARM cross-compile & non-claims
- RED: `GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/traversal/... ./internal/forward/...` under the composed app must compile (compile-only; `StunSharedPortSupported()==false` on Windows fails shared-port strategies at runtime, not compile).
- GREEN: build matrix green for windows/amd64, darwin/amd64, linux/arm64; runtime strategy evidence stays Linux-only.
- Files: `internal/agent/*.go`, no runtime test on non-Linux.

## Required verification

```bash
GOWORK=off go test ./internal/traversal/... -race -count=10
GOWORK=off go test ./internal/agent/localstate -run MappingJournal -count=10
GOWORK=off go test ./internal/agent -run 'P12W|Strategy|Composition|Recovery|Lifecycle' -race -count=10
GOWORK=off go vet ./...
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./... -count=1
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./... -count=1
GOWORK=off go test ./test/contracts -run TestContractManifest -count=1
GOWORK=off go test -tags=netns ./test/integration -run 'TestTCPTraversal|TestAgentGatewayTraversal' -count=1
GOOS=windows GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/traversal/... ./internal/forward/...  # compile-only
GOOS=linux GOARCH=arm64 GOWORK=off go build ./cmd/... ./internal/traversal/... ./internal/forward/...    # compile-only
gofmt -l <all changed Go files>   # must be empty
git diff --check
```

## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA (`43c8423` on `integration/v1-beta`).
3. Work only on branch `ai/P12W-production-wiring` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P12W.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
- Evidence honesty: no real CPE/router/WAN/Windows-runtime claim; note that the pre-existing receipt-replay flake is unrelated to P12W.