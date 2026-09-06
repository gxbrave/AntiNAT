#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/antinat-docker-stage.XXXXXX")
long_wrapper_pid=
cleanup() {
    if [ -n "${long_wrapper_pid:-}" ] && kill -0 "$long_wrapper_pid" 2>/dev/null; then
        kill -TERM "$long_wrapper_pid" 2>/dev/null || true
        wait "$long_wrapper_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_dir"
}
trap cleanup EXIT

state_dir="$test_dir/state"
secret_file="$test_dir/secret"
fake_agent="$test_dir/fake-agent"
run_log="$test_dir/run.log"
mkdir -- "$state_dir"
chmod 700 -- "$state_dir"
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$secret_file"
chmod 0444 -- "$secret_file"

printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'mode=restart' \
    'if [ "${1:-}" = "--token-file" ]; then' \
    '    token_file=$2' \
    '    [ -f "$token_file" ]' \
    '    [ ! -L "$token_file" ]' \
    '    [ "$(stat -c %a "$token_file")" = 600 ]' \
    '    [ -s "$token_file" ]' \
    '    rm -f -- "$token_file"' \
    '    mode=token' \
    'fi' \
    'printf "%s\\n" "$mode" >"$ANTINAT_DOCKER_TEST_LOG"' \
    >"$fake_agent"
chmod 755 -- "$fake_agent"

ANTINAT_STATE="$state_dir" \
ANTINAT_DOCKER_TOKEN_FILE="$secret_file" \
ANTINAT_DOCKER_AGENT_BIN="$fake_agent" \
ANTINAT_DOCKER_TEST_LOG="$run_log" \
ANTINAT_TEST_MODE=1 \
  "$script_dir/stage-enrollment.sh"

[ ! -e "$state_dir/.enrollment-token" ]
[ -f "$state_dir/.enrollment-complete" ]
[ "$(stat -c %a "$state_dir/.enrollment-complete")" = 600 ]
[ "$(cat "$run_log")" = token ]

# A restart sees the durable completion marker and must not restage or pass a
# token, even though the source secret is still mounted and available.
ANTINAT_STATE="$state_dir" \
ANTINAT_DOCKER_TOKEN_FILE="$secret_file" \
ANTINAT_DOCKER_AGENT_BIN="$fake_agent" \
ANTINAT_DOCKER_TEST_LOG="$run_log" \
ANTINAT_TEST_MODE=1 \
  "$script_dir/stage-enrollment.sh"
[ "$(cat "$run_log")" = restart ]
[ ! -e "$state_dir/.enrollment-token" ]

# A normal long-running Agent must make enrollment durable as soon as it has
# consumed the token. Interrupting and restarting it must not restage the
# source secret or attempt enrollment a second time.
long_state="$test_dir/long-state"
long_agent="$test_dir/long-agent"
long_log="$test_dir/long.log"
mkdir -- "$long_state"
chmod 700 -- "$long_state"
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'token_file=$2' \
    'rm -f -- "$token_file"' \
    'printf "%s\n" consumed >"$ANTINAT_DOCKER_TEST_LOG"' \
    'trap "exit 0" TERM INT HUP' \
    'while :; do sleep 1; done' \
    >"$long_agent"
chmod 755 -- "$long_agent"
ANTINAT_STATE="$long_state" \
ANTINAT_DOCKER_TOKEN_FILE="$secret_file" \
ANTINAT_DOCKER_AGENT_BIN="$long_agent" \
ANTINAT_DOCKER_TEST_LOG="$long_log" \
ANTINAT_TEST_MODE=1 \
  "$script_dir/stage-enrollment.sh" &
long_wrapper_pid=$!
attempt=0
while [ ! -f "$long_log" ] && [ "$attempt" -lt 50 ]; do
    sleep 0.1
    attempt=$((attempt + 1))
done
[ -f "$long_log" ]
[ "$(cat "$long_log")" = consumed ]
attempt=0
while [ ! -f "$long_state/.enrollment-complete" ] && [ "$attempt" -lt 50 ]; do
    sleep 0.1
    attempt=$((attempt + 1))
done
[ -f "$long_state/.enrollment-complete" ]
[ "$(stat -c %a "$long_state/.enrollment-complete")" = 600 ]
[ "$(cat "$long_state/.enrollment-complete")" = enrolled ]
kill -TERM "$long_wrapper_pid"
set +e
wait "$long_wrapper_pid"
long_status=$?
set -e
long_wrapper_pid=
case "$long_status" in
    0|143) ;;
    *) exit "$long_status" ;;
esac
ANTINAT_STATE="$long_state" \
ANTINAT_DOCKER_TOKEN_FILE="$secret_file" \
ANTINAT_DOCKER_AGENT_BIN="$fake_agent" \
ANTINAT_DOCKER_TEST_LOG="$long_log" \
ANTINAT_TEST_MODE=1 \
  "$script_dir/stage-enrollment.sh"
[ "$(cat "$long_log")" = restart ]
[ ! -e "$long_state/.enrollment-token" ]

# A failure before token consumption must not produce a successful enrollment
# marker, and the staged token remains available for a retry.
failure_state="$test_dir/failure-state"
failing_agent="$test_dir/failing-agent"
mkdir -- "$failure_state"
chmod 700 -- "$failure_state"
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'exit 7' \
    >"$failing_agent"
chmod 755 -- "$failing_agent"
set +e
ANTINAT_STATE="$failure_state" \
ANTINAT_DOCKER_TOKEN_FILE="$secret_file" \
ANTINAT_DOCKER_AGENT_BIN="$failing_agent" \
ANTINAT_DOCKER_TEST_LOG="$run_log" \
ANTINAT_TEST_MODE=1 \
  "$script_dir/stage-enrollment.sh"
failure_status=$?
set -e
[ "$failure_status" = 7 ]
[ ! -e "$failure_state/.enrollment-complete" ]
[ -f "$failure_state/.enrollment-token" ]
[ ! -L "$failure_state/.enrollment-token" ]

# A reparse/symlink source is never copied into the state volume.
symlink_state="$test_dir/symlink-state"
symlink_secret="$test_dir/symlink-secret"
mkdir -- "$symlink_state"
chmod 700 -- "$symlink_state"
ln -s "$secret_file" "$symlink_secret"
if ANTINAT_STATE="$symlink_state" \
    ANTINAT_DOCKER_TOKEN_FILE="$symlink_secret" \
    ANTINAT_DOCKER_AGENT_BIN="$fake_agent" \
    ANTINAT_DOCKER_TEST_LOG="$run_log" \
    ANTINAT_TEST_MODE=1 \
    "$script_dir/stage-enrollment.sh"; then
    printf '%s\n' 'symlink enrollment source was accepted' >&2
    exit 1
fi

# Symlinks at either private state path must never be followed or accepted.
staged_symlink_state="$test_dir/staged-symlink-state"
mkdir -- "$staged_symlink_state"
chmod 700 -- "$staged_symlink_state"
ln -s "$secret_file" "$staged_symlink_state/.enrollment-token"
if ANTINAT_STATE="$staged_symlink_state" \
    ANTINAT_DOCKER_TOKEN_FILE="$secret_file" \
    ANTINAT_DOCKER_AGENT_BIN="$fake_agent" \
    ANTINAT_DOCKER_TEST_LOG="$run_log" \
    ANTINAT_TEST_MODE=1 \
    "$script_dir/stage-enrollment.sh"; then
    printf '%s\n' 'symlink staged enrollment token was accepted' >&2
    exit 1
fi

marker_symlink_state="$test_dir/marker-symlink-state"
mkdir -- "$marker_symlink_state"
chmod 700 -- "$marker_symlink_state"
ln -s "$secret_file" "$marker_symlink_state/.enrollment-complete"
if ANTINAT_STATE="$marker_symlink_state" \
    ANTINAT_DOCKER_TOKEN_FILE="$secret_file" \
    ANTINAT_DOCKER_AGENT_BIN="$fake_agent" \
    ANTINAT_DOCKER_TEST_LOG="$run_log" \
    ANTINAT_TEST_MODE=1 \
    "$script_dir/stage-enrollment.sh"; then
    printf '%s\n' 'symlink enrollment marker was accepted' >&2
    exit 1
fi

printf '%s\n' 'docker/test-stage-enrollment.sh: PASS'
