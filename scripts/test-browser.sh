#!/usr/bin/env bash
# AntiNAT P17 browser test driver (framework frozen at playwright@1.62.1,
# docs/ui-design-direction.md §9). Builds and starts cmd/antinat-controller on
# an ephemeral port against a temporary data directory, runs the Playwright
# suite headless against it, tears everything down, and exits non-zero on any
# failure. NEVER uses the real store, a real WAN, or a real router.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BROWSER_DIR="$ROOT/test/browser"
BIN_DIR="$BROWSER_DIR/.bin"
BIN="$BIN_DIR/antinat-controller"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/antinat-browser.XXXXXX")"
CONTROLLER_PID=""
PORT=""
FAILED=0

PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/root/.cache/ms-playwright}"

cleanup() {
  if [ -n "$CONTROLLER_PID" ] && kill -0 "$CONTROLLER_PID" 2>/dev/null; then
    kill "$CONTROLLER_PID" 2>/dev/null || true
    wait "$CONTROLLER_PID" 2>/dev/null || true
  fi
  if [ "$FAILED" -ne 0 ]; then
    echo "test-browser: FAILED (see logs above); work dir retained at $WORK"
    echo "test-browser: controller log: $WORK/controller.log"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

pick_port() {
  port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
)"
  echo "$port"
}

wait_ready() {
  local url="http://127.0.0.1:$1/readyz"
  for _ in $(seq 1 100); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "test-browser: controller did not become ready"
  return 1
}

run_suite() {
  local spec="$1"
  local auth_state=""
  case "$spec" in
    admin.spec.js|deployment.spec.js) auth_state="$WORK/browser-auth.json" ;;
  esac
  ( cd "$BROWSER_DIR" && ANTINAT_BASE_URL="http://127.0.0.1:$PORT" \
      ANTINAT_AUTH_STATE="$auth_state" \
      PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" \
      npx playwright test "$spec" )
}

echo "== test-browser: build controller =="
mkdir -p "$BIN_DIR"
go build -o "$BIN" ./cmd/antinat-controller

if [ ! -d "$BROWSER_DIR/node_modules/playwright" ]; then
  echo "== test-browser: npm install playwright@1.62.1 (pinned) =="
  ( cd "$BROWSER_DIR" && npm install --no-audit --no-fund )
fi

# The pinned 1.62.1 expects chromium-headless-shell build 1234. Provisioned
# caches may carry a different build; download the exact one when missing so
# the suite is reproducible (bounded, network only when required).
EXPECTED_SHELL="$PLAYWRIGHT_BROWSERS_PATH/chromium_headless_shell-1234"
if [ ! -d "$EXPECTED_SHELL" ]; then
  echo "== test-browser: downloading chromium-headless-shell 1234 for playwright 1.62.1 =="
  ( cd "$BROWSER_DIR" && PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" npx playwright install chromium-headless-shell )
fi

PORT="$(pick_port)"
echo "== test-browser: start controller on 127.0.0.1:$PORT (temp store) =="
ANTINAT_STORE="$WORK/controller.db" ANTINAT_KEYDIR="$WORK/keys" \
  "$BIN" -listen "127.0.0.1:$PORT" >"$WORK/controller.log" 2>&1 &
CONTROLLER_PID=$!

if ! wait_ready "$PORT"; then
  echo "--- controller.log ---"
  cat "$WORK/controller.log" || true
  FAILED=1
  exit 1
fi

echo "== test-browser: seed public fixture =="
( cd "$ROOT" && go run ./test/browser/seed -store "$WORK/controller.db" -scenario public )

run_suite home-public.spec.js || FAILED=1

run_suite admin.spec.js || FAILED=1

run_suite deployment.spec.js || FAILED=1

run_suite destructive.spec.js || FAILED=1

run_suite a11y.spec.js || FAILED=1

echo "== test-browser: seed private-site fixture =="
( cd "$ROOT" && go run ./test/browser/seed -store "$WORK/controller.db" -scenario private )

run_suite home-private.spec.js || FAILED=1

echo "== test-browser: stop controller =="
kill "$CONTROLLER_PID" 2>/dev/null || true
wait "$CONTROLLER_PID" 2>/dev/null || true
CONTROLLER_PID=""

if [ "$FAILED" -ne 0 ]; then
  echo "test-browser: FAILED (browser suite exited non-zero)"
  exit 1
fi
echo "test-browser: PASS"
exit 0