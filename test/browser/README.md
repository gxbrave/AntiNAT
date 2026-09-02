# AntiNAT P17 Browser Test Harness

Framework frozen at P17 (Story 1, `docs/ui-design-direction.md` §9). The v0.8
plan required the framework to be frozen at M0; P04 did not document one, so
P17 fixes it here.

## Framework and version

- **Framework:** Playwright
- **Pin:** `playwright@1.62.1` exactly (`test/browser/package.json`)
- **Browsers:** the provisioned 1.62.x build is already at
  `/root/.cache/ms-playwright` (`chromium-1228`). Tests run
  headless against the **Chromium desktop project** (`chromium-desktop`,
  1280x800); individual specs narrow the viewport to mobile widths when the
  behavior under test is mobile-specific.
- **Command:** `./scripts/test-browser.sh` — the single browser gate.

## How it works

`scripts/test-browser.sh`:

1. Builds `cmd/antinat-controller` into `test/browser/.bin/`.
2. Picks an ephemeral loopback port and starts the controller against a
   temporary data directory (`mktemp -d`), never the real store.
3. Waits for `/readyz`.
4. Runs the store-backed seeder (`go run ./test/browser/seed`) to create the
   deterministic fixture: an admin (`admin` / `s3cret-pass-123`), online and
   offline nodes, forwards with real orthogonal activation snapshots, and
   navigation categories/items covering verified / unverified / stale / offline
   statuses. The `private` scenario flips `private_site=true`.
5. Runs the Playwright suite headless with
   `PLAYWRIGHT_BROWSERS_PATH=/root/.cache/ms-playwright` and
   `ANTINAT_BASE_URL=http://127.0.0.1:<port>`.
6. Tears the controller down and **exits non-zero on any failure**.

## Environment facts (recorded, not claimed)

- `node v22.23.1`, `npm 10.9.8` are present; the npm registry is reachable.
- `playwright@1.62.1` is pinned in `test/browser/package.json`; `npm install`
  pulls only the package, never browsers.
- The browser tests are LOCAL loopback tests against a real controller
  process. There is no real-WAN, real-router, or native-Windows claim.

## Adding a suite

New specs: `test/browser/<name>.spec.js`. Register them in
`scripts/test-browser.sh` after the seeding step they need. Keep the suite
bounded: prefer narrow assertions over full-page screenshots, and keep the
total run under two minutes.