# Controller menu and separate Agent installer

User-requested post-release change, based on `dfd72ba9c934d8e041351e6d45002c9657ceccf7`
on `fix/simple-installer`. Agent repository baseline:
`fd5b62c2c04200b1c0e7a75c88be5e1b111b3aa4`.

The public Controller bootstrap exposes only Controller, Controller + local
Agent, and complete local purge. It accepts `--port`, provisions the local
node through privileged Controller business logic, and executes the structured
form of the generated Agent command with a private token file. Existing
Controller ports are preserved. Incomplete previously enrolled Agents fail
explicitly instead of reporting success. The lower-level frozen installer
flags and enrollment wire contracts are unchanged.

Agent entry points and generated commands use AntiNAT-Agent. The Controller
Docker image and default Compose deployment do not include an Agent.

Validation (exit 0 unless noted):

- `python3 scripts/test-bootstrap.py`: 10 cases, including streamed TTY,
  parameter validation, local enrollment dispatch, retry and purge exit mapping.
- `python3 ../agent-installer-simple/tests/test_bootstrap.py`: 5 cases.
- `bash scripts/test-controller-port.sh`: actual occupied socket and both init systems.
- `bash scripts/test-installers.sh`: isolated installation/rollback/purge regression.
- `GOWORK=off go test ./internal/controller/... ./cmd/antinat-controller ./test/contracts`.
- `GOWORK=off go test -race ./internal/controller -run TestProvisionLocalAgent -count=1`:
  includes actual signed enrollment against a running Controller on loopback.
- `GOWORK=off go vet ./internal/controller/... ./cmd/antinat-controller`.
- `GOWORK=off GOOS=windows GOARCH=amd64 go build ./cmd/antinat-controller`.
- `bash -n install.sh scripts/libinstall.sh ../agent-installer-simple/install.sh`.
- `docker compose -f docker/compose.yaml config --services`: Controller only.
- `docker build --target controller -t antinat:local-controller-menu .`;
  container file inspection confirms no Agent binary; real container readyz succeeds.
- Cross-repository ownership test: Controller manifest → Agent merge → Controller
  HMAC validation, retaining the Controller resources and installation ID.
- Go deployment tests verify backend command rendering and actual shell argument forwarding.
- `node --check web/static/js/deployment.js` and `node --check test/browser/deployment.spec.js`; Node VM execution verifies frontend Linux/Windows command generation. Full Playwright was not rerun.
- `git diff --check` in both repositories.

Focused behavior tests were observed failing before implementation. Independent
review findings about retry, inherited token FDs, enrollment state and platform
URLs were addressed. No frozen contract files were modified. This is a user
requested post-release change, not progression of a historical Pxx plan.

Release limitation: the new workflow requires matching beta.2 Controller and
Agent assets. The existing beta.1 Controller lacks the provisioning CLI, and
AntiNAT-Agent had no published Releases when checked. No remote push, release,
or installation into this host's system services was performed. Windows and
OpenRC runtime installation remain unverified. Tokens are never printed in
commands or logs. Interrupted registered nodes with missing local credentials
require recovery through the Controller; existing identities are not overwritten.
