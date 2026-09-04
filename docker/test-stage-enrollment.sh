#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/antinat-docker-stage.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT

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

# A failed Agent must not turn token removal into a successful enrollment
# marker. The source secret remains available for an operator retry.
failure_state="$test_dir/failure-state"
failing_agent="$test_dir/failing-agent"
mkdir -- "$failure_state"
chmod 700 -- "$failure_state"
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'rm -f -- "$2"' \
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

printf '%s\n' 'docker/test-stage-enrollment.sh: PASS'
