# P17 contract-change record

Status: final candidate; implementation gates passed; awaiting final independent
review and integration.

This record is the required contract-change companion for P17. It does not
waive the frozen P04/P15/P16 contracts and does not authorize any old
`/api/admin/*` surface.

## Source and baseline

- Child plan: `.hermes/plans/v1-beta/17-web-ui-deployment.md`
- Continuation source: `.hermes/handoffs/P17-paused-handoff.md`
- Required implementation base: `329fdf5039e4e55350d923462f78c2d4ee2e3588`
- P17 candidate implementation commit: `5af5431`
- Pre-P17 OpenAPI manifest SHA-256: `aa60d05f621f62ecf617c52583babf59cf98e77633945e7a109b0b3da6b6ce32`
- P17 OpenAPI SHA-256: `43785c94abf6f158f52f0059d38a260d4d68f052a5ca1aed26539e48bc06c1eb`

## Approved additive API surface

Only this existing versioned node subresource path is added to the OpenAPI
surface, with these two methods:

- `GET /api/v1/nodes/{id}/deployment-profile`
- `PUT /api/v1/nodes/{id}/deployment-profile`

There is intentionally no POST deployment-profile method and no legacy
`/api/admin/*` route.

GET returns a secret-free structured profile view. An existing node without a
saved profile returns revision `0` and ETag `"rev-0"` with safe defaults; an
empty endpoint is not command-generatable. The response includes:

- `node_id`
- `profile`
- `revision`
- `etag`

PUT accepts `{ "profile": { ... } }`, requires `If-Match`, and returns the
updated view. Missing `If-Match` is `428 PRECONDITION_REQUIRED`; a stale ETag
is `412 PRECONDITION_FAILED`; malformed/unknown-field/trailing/duplicate JSON
is rejected; semantically invalid profile data is `422 UNPROCESSABLE_ENTITY`.
Profile and one-time enrollment-token responses use `Cache-Control: private,
no-store`. This is a security-only header hardening on the pre-existing token
route, not a new route or method.

The allowed profile fields are:

- `platform`: `linux | windows | docker`
- `controller_endpoint`
- `bind_interface`
- `detection_scheduler`: `sequential | parallel`
- `github_proxy`
- `install_dir`
- `service_name`
- `log_level`: `debug | info | warn | error`
- `auto_update`: `disabled | manual | stable | enabled`

Token, secret, password, command, GPU/memory/mountpoint, monthly-rotation,
macOS and other legacy product-intent fields are not profile fields.

## Persistence and migration

P15 already created `node_deployment_profiles` in migration `0009`; P17 does
not create a second profile/token/command table and does not change the schema
version or migration registry.

The P15 `PutDeploymentProfile` seam now delegates to the explicit P17
`internal/controller/store/deployment_profile.go` implementation. The write
path validates a typed profile, canonicalizes it, compares the revision and
writes under one SQLite `BEGIN IMMEDIATE` transaction. Concurrent writers with
the same ETag produce exactly one success and one CAS conflict.

This is an explicit ownership transfer for the deployment-profile storage
seam; it is not a silent change to unrelated P15 traffic semantics.

The following narrow cross-phase edits are also explicitly transferred for P17
acceptance and are limited to the corresponding durable behavior:

| Existing owner file | P17 transfer reason | Boundary |
|---|---|---|
| `internal/controller/api/node_ops.go` | mount the approved deployment-profile subresource in the existing node dispatcher | no new legacy route or lifecycle API |
| `internal/controller/store/traffic.go` | make the existing profile seam strict and atomic | profile rows only; no traffic semantics |
| `internal/controller/store/node_bundle.go` | append `NODE_CREATED` in the node-create transaction | no node lifecycle changes |
| `internal/controller/api/node_delete.go` | require the current node ETag before normal/force deletion | existing route only; 412/428 safety responses |
| `internal/controller/api/operations.go` | report completed node cleanup ACK as `remote_cleanup_confirmed` | operation projection only |
| `internal/controller/api/forwards_min.go` | project existing runtime UpdatedAt/ActivationID as evidence metadata | additive response fields; no new route |
| `internal/controller/store/p15_repair1_page.go` | hide force-tombstoned nodes from regular navigation | durable node row retained; no lifecycle deletion |
| `internal/controller/api/nodes_min.go` | prevent caching of the pre-existing one-time enrollment response | response header only; no new token field or route |
| `internal/controller/api/auth.go`, `observability.go` | bound/redact the minimal fallback SSE path | fallback stream only; canonical route remains bounded |
| `internal/controller/web/sse.go` | close remaining canonical redaction gaps | SSE payload redaction only |
| `internal/controller/api/api_test.go`, `deployment_test.go`, `p15_repair1_h3_test.go`, `p15_repair2_test.go` | regression coverage for token cache, profile, delete CAS and fallback SSE | tests only |
| `internal/controller/store/deployment_p17_test.go`, `internal/controller/deployment/profile_test.go` | strict profile/CAS and JSON boundary coverage | tests only |
| `internal/controller/web/admin.go`, `home.go`, `home_test.go`, `router_min.go`, `ui.go`, `ui18n.go`, `web/embed.go` | P17 UI handler/template/embed wiring and browser-facing status projection | no protocol or lifecycle wiring |
No P19 lifecycle wiring, agent delivery, or unrelated P15/P16 endpoint is
transferred by this record. The user-requested acceptance/integration task is
the authorization to complete these narrow transfers serially in this
worktree; the next agent must not broaden them.

## Command and credential boundary

The command builder is in `internal/controller/deployment/` and has no token
parameter or token field. POSIX arguments are single-quoted; PowerShell uses
UTF-16LE Base64 `-EncodedCommand`; Docker uses host networking and removes
installer-only profile flags. The UI renders a one-time token in a separate
panel and never serializes it into the profile, command, URL, audit/SSE event,
environment or service configuration.

The installer artifact URL remains the frozen-contract `releases/latest`
placeholder and has not received a new trust/signature protocol in P17. This
is command-generation/UI evidence only; it is not native installer or release
artifact evidence.

## Explicit limits

- The existing traversal-detection API queues a PENDING operation only. P17
  does not invent polling, per-strategy results or all-failed completion; the UI
  says so explicitly and still permits profile save after a queue error.
- Browser evidence is loopback-only against a temporary store.
- No native Windows execution, Docker runtime, real router, independent WAN
  vantage or release artifact verification was performed.
- HTTP(S) endpoint syntax is validated, but P17 does not add a new TLS policy
  for non-loopback endpoints; deployment operators must use the confirmed
  HTTPS endpoint for production.
- P17 does not wire node lifecycle/deployment delivery owned by P19/P18.
- The evidence rail projects the real durable runtime source, RFC3339
  `ForwardRuntimeStatus.UpdatedAt`, and activation ID for each current snapshot.
  It does not invent a probe-round ID when the existing frozen runtime row has
  none; a future approved contract may add per-axis/probe metadata.

## Verification references

The machine-readable P17 handoff lists exact commands and exit codes. The
OpenAPI manifest was updated to the P17 OpenAPI hash above. Browser review
screenshots are under `test/browser/evidence/`.
