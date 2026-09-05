# P18 contract-change record

Status: approved by the P18 orchestrator for fresh independent review and
integration, limited to the additive revision recorded below. This is not
release approval.

Approval record: on 2026-09-05 UTC, the P18 orchestrator approved the
candidate snapshot `3520b57038dbcfe8bbe3fba9c8d61903e09cec96` proposal to
add the required public `controller_pin` field to the existing
`EnrollmentToken` response and update the byte-matched contract manifest.
The approval does not authorize a new route or method, a secret channel, a
protocol or lifecycle revision, a legacy API surface, or any further frozen
contract change.

This record amends the P17 deployment/enrollment handoff narrowly. It does
not waive the frozen installer, protocol, or lifecycle contracts, and it does
not authorize any legacy `/api/admin/*` surface.

## Problem and baseline

P17 added the deployment UI and the existing
`POST /api/v1/nodes/{id}/enrollment-token` response still contained only the
one-time token and its expiry. The Agent enrollment transcript requires the
Controller's 32-byte Ed25519 public key before it will consume that token.
Consequently, a generated Linux, Windows, or Docker deployment command could
not complete enrollment without an operator manually discovering and adding a
trust pin.

Baseline OpenAPI contract: the P17 `EnrollmentToken` schema required only
`token` and `expires_at`.

## Additive change

The existing `EnrollmentToken` response gains one required field:

- `controller_pin`: lowercase hexadecimal encoding of the active Controller
  Ed25519 public key (exactly 64 characters / 32 bytes).

The value is public trust material, not an enrollment secret. It is derived
from the active keyring configured by `controller.App`, passed through
`api.RouterConfig`, and returned alongside the existing one-time token. The
response remains `Cache-Control: private, no-store`; the token remains shown
once and is never persisted in a profile, command, environment, service unit,
or log.

This is additive for clients that ignore unknown response fields. Clients
that generate an enrollment command must require and validate the field before
showing a command.

## Deployment command boundary

The ephemeral node ID and `controller_pin` are command-rendering inputs only;
they are not added to the persisted deployment profile. Linux and Windows
commands expose them to the installer through `ANTINAT_NODE_ID` and
`ANTINAT_CONTROLLER_PIN`. The enrollment token remains available only through
the frozen installer TTY, `--token-fd`, or protected `--token-file` inputs.

Docker commands pass the Agent-supported endpoint/node/pin environment values
before the image, mount a protected operator token-file placeholder at the
wrapper's `/run/secrets/antinat_enrollment_token` path, and have no arguments
after the image. Docker v1 remains Linux host-network only.

## Narrow ownership transfer

The following P17-owned boundaries are transferred to P18 solely to make the
installer acceptance flow executable:

| File or area | Boundary |
|---|---|
| `internal/controller/api/auth.go`, `nodes_min.go` | Carry the configured public key into the existing token response; no new route or token storage change |
| `internal/controller/app.go` | Pass the active keyring public key into the existing router composition |
| `internal/controller/deployment/command.go` and its tests | Render ephemeral node/pin context for the three existing deployment platforms; no profile persistence or token parameter |
| `web/static/js/deployment.js` and browser tests | Consume the additive response field and render the same secret-free command contract |
| `api/openapi.yaml`, `test/contracts/manifest.json` | Record this additive response-field change and its resulting manifest hash |
| `docker/compose.yaml`, `docker/README.md` | Keep the documented Docker environment/token-file contract aligned with command output |

No P19 lifecycle delivery, protocol, installer parser, or unowned state schema
is changed by this amendment.
