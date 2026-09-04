# P17 contract-change record

Status: additive candidate recorded for independent review/integration.

This record is the required contract-change companion for P17. It does not
waive the frozen P04/P15/P16 contracts and does not authorize any old
`/api/admin/*` surface.

## Source and baseline

- Child plan: `.hermes/plans/v1-beta/17-web-ui-deployment.md`
- Continuation source: `.hermes/handoffs/P17-paused-handoff.md`
- Required implementation base: `329fdf5039e4e55350d923462f78c2d4ee2e3588`
- P17 candidate branch: `ai/P17-web-ui`
- Pre-P17 OpenAPI manifest SHA-256: `aa60d05f621f62ecf617c52583babf59cf98e77633945e7a109b0b3da6b6ce32`
- P17 OpenAPI SHA-256: `a6bb8336c8f5642f9b9966cfe094b2107316afd5307fd53ac911c82b2c9cda9b`

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
Profile responses use `Cache-Control: private, no-store`. The pre-existing
enrollment-token endpoint retains its frozen P15 response contract; P17 fetches
the profile before issuing a token and the browser harness retains no token,
session state, or trace on failure.

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
not create a second profile/token/command table. Migration `0011_deployment.sql`
adds only the recency index:

`idx_node_deployment_profiles_updated ON node_deployment_profiles(updated_at, node_id)`

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
| `internal/controller/store/node_bundle.go` | append `NODE_CREATED` in the node-create transaction | one durable event; no node lifecycle changes |
| `internal/controller/api/auth.go`, `observability.go` | bound/redact the minimal fallback SSE path | fallback stream only; canonical route remains bounded |
| `internal/controller/web/sse.go` | close remaining canonical redaction gaps | SSE payload redaction only |
| migration/version tests | register and verify `0011_deployment.sql` | one additive index only |

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

## Verification references

The machine-readable P17 handoff lists exact commands and exit codes. The
OpenAPI manifest was updated to the P17 OpenAPI hash above. Browser review
screenshots are under `test/browser/evidence/`.
