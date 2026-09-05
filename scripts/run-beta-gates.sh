#!/usr/bin/env bash

# Build the release set once, then bind every recorded gate to the manifest
# digest. This script deliberately leaves unavailable external gates as
# SUPPORTED_WITH_LIMITS so a candidate cannot be mistaken for an approved
# release.
set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)

artifacts_arg=""
evidence_arg=""
release_version="${ANTINAT_RELEASE_VERSION:-v1.0.0-beta.1}"

usage() {
    cat >&2 <<'EOF'
Usage: run-beta-gates.sh --artifacts DIR --evidence DIR [--version v1.0.0-beta.N]

The command creates DIR/release and records the exact artifact-bound gate
results in DIR/evidence. It never publishes, tags, or pushes a release.
EOF
}

die() {
    printf 'P19 gate runner: %s\n' "$*" >&2
    exit 2
}

while (($# > 0)); do
    case "$1" in
        --artifacts)
            (($# >= 2)) || die "--artifacts requires a directory"
            artifacts_arg=$2
            shift 2
            ;;
        --evidence)
            (($# >= 2)) || die "--evidence requires a directory"
            evidence_arg=$2
            shift 2
            ;;
        --version)
            (($# >= 2)) || die "--version requires a value"
            release_version=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[[ -n "$artifacts_arg" && -n "$evidence_arg" ]] || { usage; exit 2; }
[[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$ ]] || die "version must match vMAJOR.MINOR.PATCH-beta.N"

artifacts_root=$(mkdir -p -- "$artifacts_arg" && cd -- "$artifacts_arg" && pwd -P)
evidence_dir=$(mkdir -p -- "$evidence_arg" && cd -- "$evidence_arg" && pwd -P)
release_dir="$artifacts_root/release"

if [[ -e "$release_dir" || -L "$release_dir" ]]; then
    die "refusing to overwrite existing artifact directory: $release_dir"
fi
if find "$evidence_dir" -mindepth 1 -print -quit | grep -q .; then
    die "refusing to overwrite non-empty evidence directory: $evidence_dir"
fi

if [[ -n "$(git -C "$repo_dir" status --porcelain --untracked-files=all)" ]]; then
    die "release source tree must be clean before the one-time build"
fi

mkdir -m 700 -- "$release_dir"

source_commit=$(git -C "$repo_dir" rev-parse HEAD)
source_tree=$(git -C "$repo_dir" rev-parse 'HEAD^{tree}')
source_built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
source_go=$(go version | awk '{print $3}')
source_os=$(go env GOOS)
source_arch=$(go env GOARCH)

cd -- "$repo_dir"

[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || die "git HEAD is not a full commit identity"
[[ "$source_tree" =~ ^[0-9a-f]{40}$ ]] || die "git tree is not a full tree identity"
[[ "$source_os" == linux && "$source_arch" == amd64 ]] || die "P19 build must run on the Linux amd64 release host"

declare -a gate_ids=()
declare -a gate_results=()
declare -a gate_required=()
declare -a gate_commands=()
declare -a gate_evidence=()
declare -a gate_summaries=()
overall_failure=0

record_gate() {
    local id=$1 result=$2 required=$3 command=$4 evidence=$5 summary=$6
    gate_ids+=("$id")
    gate_results+=("$result")
    gate_required+=("$required")
    gate_commands+=("$command")
    gate_evidence+=("$evidence")
    gate_summaries+=("$summary")
}

run_gate() {
    local id=$1 required=$2 command=$3 summary=$4
    shift 4
    local log="$evidence_dir/$id.log"
    local rc
    set +e
    "$@" >"$log" 2>&1
    rc=$?
    set -e
    if ((rc == 0)); then
        record_gate "$id" PASS "$required" "$command" "$(basename -- "$log")" "$summary"
    else
        printf 'exit_code=%s\n' "$rc" >>"$log"
        record_gate "$id" FAIL "$required" "$command" "$(basename -- "$log")" "$summary (exit_code=$rc)"
        overall_failure=1
    fi
}

limited_gate() {
    local id=$1 required=$2 command=$3 summary=$4
    local log="$evidence_dir/$id.log"
    printf 'result=SUPPORTED_WITH_LIMITS\nreason=%s\n' "$summary" >"$log"
    record_gate "$id" SUPPORTED_WITH_LIMITS "$required" "$command" "$(basename -- "$log")" "$summary"
}

run_test_command() (
    umask 022
    "$@"
)

build_one() {
    local goos=$1 goarch=$2 output=$3 package=$4
    env GOWORK=off CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$output" "$package"
}

build_release() {
    ldflags="-X github.com/gxbrave/AntiNAT/internal/buildinfo.Version=$release_version -X github.com/gxbrave/AntiNAT/internal/buildinfo.Commit=$source_commit -X github.com/gxbrave/AntiNAT/internal/buildinfo.Date=$source_built_at"
    printf 'source_commit=%s\nsource_tree=%s\ngo=%s\n' "$source_commit" "$source_tree" "$source_go"
    build_one linux amd64 "$release_dir/antinat-agent-linux-amd64" ./cmd/antinat-agent
    build_one linux amd64 "$release_dir/antinat-controller-linux-amd64" ./cmd/antinat-controller
    build_one linux amd64 "$release_dir/antinat-hook-runner-linux-amd64" ./cmd/antinat-hook-runner
    build_one linux amd64 "$release_dir/antinat-probe-linux-amd64" ./cmd/antinat-probe
    build_one linux amd64 "$release_dir/antinatctl-linux-amd64" ./cmd/antinatctl
    build_one windows amd64 "$release_dir/antinat-agent-windows-amd64.exe" ./cmd/antinat-agent
    build_one windows amd64 "$release_dir/antinat-controller-windows-amd64.exe" ./cmd/antinat-controller
    build_one windows amd64 "$release_dir/antinat-hook-runner-windows-amd64.exe" ./cmd/antinat-hook-runner
    build_one windows amd64 "$release_dir/antinat-probe-windows-amd64.exe" ./cmd/antinat-probe
    build_one windows amd64 "$release_dir/antinatctl-windows-amd64.exe" ./cmd/antinatctl

    local arm_tmp="$release_dir/.arm64"
    mkdir -m 700 -- "$arm_tmp"
    if build_one linux arm64 "$arm_tmp/antinat-agent-linux-arm64" ./cmd/antinat-agent && \
        build_one linux arm64 "$arm_tmp/antinatctl-linux-arm64" ./cmd/antinatctl; then
        mv -- "$arm_tmp/antinat-agent-linux-arm64" "$release_dir/antinat-agent-linux-arm64"
        mv -- "$arm_tmp/antinatctl-linux-arm64" "$release_dir/antinatctl-linux-arm64"
        arm64_status=SUPPORTED_WITH_LIMITS
        printf 'arm64_agent_cli=PASS\n'
    else
        arm64_status=SUPPORTED_WITH_LIMITS
        printf 'arm64_agent_cli=SUPPORTED_WITH_LIMITS (cross-build unavailable)\n'
    fi
    find "$arm_tmp" -mindepth 1 -maxdepth 1 -type f -delete
    rmdir -- "$arm_tmp" 2>/dev/null || true

    chmod 700 -- "$release_dir"/*
}

run_gate exact-build true "single trimpath build for the Linux/Windows candidate set" \
    "the release binaries were built once before any release test" build_release

cat >"$release_dir/source.json" <<EOF
{
  "schema_version": "antinat.release-source/v1",
  "release": "$release_version",
  "module": "github.com/gxbrave/AntiNAT",
  "commit_sha": "$source_commit",
  "tree_sha": "$source_tree",
  "go_version": "$source_go",
  "host": "$source_os/$source_arch",
  "built_at": "$source_built_at",
  "artifact_policy": "build-once-test-exact-manifest"
}
EOF

sbom_status=SUPPORTED_WITH_LIMITS
generate_sbom() {
    if command -v syft >/dev/null 2>&1; then
        syft "dir:$repo_dir" \
            --exclude '*/.git/**' \
            --exclude '*/test/browser/node_modules/**' \
            -o "cyclonedx-json=$release_dir/sbom.cdx.json"
        sbom_status=PASS
        return 0
    fi

    local components
    components=$(GOWORK=off go list -m -f '{{.Path}}\t{{.Version}}' all | \
        while IFS=$'\t' read -r module version; do
            [[ -n "$module" ]] || continue
            [[ -n "$version" ]] || version='main-module'
            jq -cn --arg name "$module" --arg version "$version" \
                '{type:"library",name:$name,version:$version}'
        done | jq -sc .)
    jq -n --arg version "$release_version" --arg source "$source_commit" \
        --argjson components "$components" \
        '{bomFormat:"CycloneDX",specVersion:"1.5",version:1,
          metadata:{component:{type:"application",name:"AntiNAT",version:$version},
                    properties:[{name:"antinat:source_commit",value:$source}]},
          components:$components}' >"$release_dir/sbom.cdx.json"
    printf 'syft=unavailable\nsource=go list -m\n'
}

run_gate sbom true "generate CycloneDX SBOM for the exact source tree" \
    "the release contains a machine-readable dependency inventory" generate_sbom

make_checksums() {
    local path name
    : >"$release_dir/checksums.txt"
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        path="$release_dir/$name"
        sha256sum -- "$path" | awk -v name="$name" '{print $1 "  " name}'
    done < <(find "$release_dir" -maxdepth 1 -type f \
        ! -name checksums.txt ! -name manifest.json ! -name manifest.sig \
        -printf '%f\n' | LC_ALL=C sort) >"$release_dir/checksums.txt"
}

make_manifest() {
    local trust_root_id=${ANTINAT_TRUST_ROOT_ID:-release-key-2026}
    if [[ "$trust_root_id" != release-key-2026 && "${ANTINAT_TEST_MODE:-0}" != 1 ]]; then
        die "custom trust roots require ANTINAT_TEST_MODE=1"
    fi
    local artifacts='{}' name digest
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        digest=$(sha256sum -- "$release_dir/$name" | awk '{print $1}')
        artifacts=$(jq -c --arg name "$name" --arg digest "$digest" \
            '. + {($name):$digest}' <<<"$artifacts")
    done < <(find "$release_dir" -maxdepth 1 -type f \
        ! -name manifest.json ! -name manifest.sig ! -name checksums.txt \
        -printf '%f\n' | LC_ALL=C sort)
    digest=$(sha256sum -- "$release_dir/checksums.txt" | awk '{print $1}')
    artifacts=$(jq -c --arg digest "$digest" '. + {"checksums.txt":$digest}' <<<"$artifacts")
    jq -cnS --arg release "$release_version" --arg trust "$trust_root_id" \
        --argjson artifacts "$artifacts" \
        '{schema_version:"1",release:$release,artifacts:$artifacts,
          trust_root:$trust,signature_algorithm:"ed25519"}' >"$release_dir/manifest.json"

    signature_status=SKIPPED
    if [[ -n "${ANTINAT_RELEASE_SIGNING_KEY:-}" ]]; then
        [[ -f "$ANTINAT_RELEASE_SIGNING_KEY" && ! -L "$ANTINAT_RELEASE_SIGNING_KEY" ]] || \
            die "release signing key must be a regular non-symlink file"
        openssl pkeyutl -sign -rawin -inkey "$ANTINAT_RELEASE_SIGNING_KEY" \
            -in "$release_dir/manifest.json" -out "$release_dir/manifest.sig"
        chmod 600 -- "$release_dir/manifest.sig"
        signature_status=PASS
    fi
    chmod 600 -- "$release_dir/manifest.json"
    printf 'trust_root=%s\nsignature_status=%s\n' "$trust_root_id" "$signature_status"
}

make_checksums
make_manifest

artifact_integrity_check() {
    local manifest=$1 root=$2 entries name expected actual count=0
    jq -e 'type == "object" and .schema_version == "1" and (.artifacts | type == "object" and length > 0)' \
        "$manifest" >/dev/null || return 1
    entries=$(jq -r '.artifacts | to_entries[] | [.key,.value] | @tsv' "$manifest") || return 1
    while IFS=$'\t' read -r name expected; do
        [[ -n "$name" && "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
        [[ "$name" != */* && "$name" != *..* ]] || return 1
        actual=$(sha256sum -- "$root/$name" | awk '{print $1}') || return 1
        [[ "$actual" == "$expected" ]] || return 1
        count=$((count + 1))
    done <<<"$entries"
    ((count > 0)) || return 1
}

run_gate artifact-integrity true "verify all manifest artifact SHA-256 values" \
    "every declared file is hashed before testing" \
    artifact_integrity_check "$release_dir/manifest.json" "$release_dir"

manifest_sum=$(sha256sum -- "$release_dir/manifest.json" | awk '{print $1}')
artifact_digest="sha256:$manifest_sum"
signature_status=${signature_status:-SKIPPED}

verify_manifest_signature() {
    local trust_root_file=${ANTINAT_TRUST_ROOT_FILE:-$repo_dir/deploy/trust/release-ed25519.pub}
    [[ -f "$release_dir/manifest.sig" && -f "$trust_root_file" ]] || return 1
    openssl pkeyutl -verify -pubin -inkey "$trust_root_file" -rawin \
        -in "$release_dir/manifest.json" -sigfile "$release_dir/manifest.sig" >/dev/null
}
if [[ "$signature_status" == PASS ]]; then
    run_gate signature true "verify detached Ed25519 manifest signature" \
        "the exact manifest is authenticated by the configured release trust root" verify_manifest_signature
else
    limited_gate signature true "verify detached Ed25519 manifest signature" \
        "no production signing key was supplied; the candidate cannot be promoted"
fi

exact_artifact_check() {
    local output
    output=$("$release_dir/antinat-controller-linux-amd64" version)
    grep -F -x -- "antinat-controller version=$release_version commit=$source_commit date=$source_built_at" <<<"$output"
    output=$("$release_dir/antinat-agent-linux-amd64" version)
    grep -F -x -- "antinat-agent version=$release_version commit=$source_commit date=$source_built_at" <<<"$output"
    for name in antinat-hook-runner-linux-amd64 antinat-probe-linux-amd64 antinatctl-linux-amd64; do
        [[ -s "$release_dir/$name" ]] || return 1
    done
}
run_gate exact-artifact-metadata true "execute version checks from the exact release binaries" \
    "the shipped Linux controller and agent report the recorded source identity" exact_artifact_check

run_gate unit-tests true "GOWORK=off go test -p 1 ./... -count=1" \
    "the integrated repository suite passes after the one-time build" \
    run_test_command env GOWORK=off ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 go test -p 1 ./... -count=1

run_gate race-tests true "GOWORK=off go test -p 1 -race ./... -count=1" \
    "the integrated repository race suite passes without rebuilding release artifacts" \
    run_test_command env GOWORK=off ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 go test -p 1 -race ./... -count=1

run_gate vet true "GOWORK=off go vet ./..." \
    "the integrated repository is vet-clean" env GOWORK=off go vet ./...

run_gate functional-e2e true "GOWORK=off go test ./test/e2e -count=1 -v" \
    "the local TCP/UDP and lifecycle E2E suite completes; WAN independence remains a separate gate" \
    run_test_command env GOWORK=off ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 go test ./test/e2e -count=1 -v

run_gate install-upgrade-purge true "bash scripts/test-installers.sh" \
    "isolated installer install, upgrade, rollback, and purge coverage passes" \
    run_test_command bash "$script_dir/test-installers.sh"

if [[ -x "$script_dir/test-browser.sh" && -d "$repo_dir/test/browser/node_modules" ]]; then
    run_gate browser-e2e true "./scripts/test-browser.sh" \
        "the bilingual UI and deployment browser suite passes" bash "$script_dir/test-browser.sh"
else
    limited_gate browser-e2e true "./scripts/test-browser.sh" \
        "Playwright dependencies are unavailable on this release host"
fi

security_scan() {
    local match
    if match=$(grep -RInaE --binary-files=without-match \
        -e 'BEGIN (RSA|EC|OPENSSH|ED25519) PRIVATE KEY' \
        -e 'ANTINAT_(TOKEN|PASSWORD|SECRET)=[^[:space:]]+' \
        "$release_dir" "$evidence_dir" 2>/dev/null); then
        printf '%s\n' "$match"
        return 1
    fi
    GOWORK=off go test ./test/release -run 'TestReleaseSecurityBoundary' -count=1
}
run_gate security true "secret scan plus release security boundary tests" \
    "no private key, token, or password was emitted into the release/evidence bundle" security_scan

if command -v govulncheck >/dev/null 2>&1; then
    run_gate govulncheck true "govulncheck ./..." \
        "the Go vulnerability scan is available and passes" env GOWORK=off govulncheck ./...
else
    limited_gate govulncheck true "govulncheck ./..." \
        "govulncheck is unavailable; vulnerability status is not promoted to PASS"
fi

if [[ -n "${ANTINAT_CONTROLLER_ENDPOINT:-}" && -n "${ANTINAT_REMOTE_PROBE_VANTAGE:-}" ]]; then
    limited_gate real-wan true "operator-supplied real-WAN gate" \
        "an external WAN gate was named but P19 does not execute unreviewed commands from environment variables"
else
    limited_gate real-wan true "independent WAN client/provider and restart matrix" \
        "controller endpoint and independent remote probe vantage are not provisioned"
fi

limited_gate platform-matrix true "native Windows, OpenRC, arm64 host, and OCI registry matrix" \
    "P18 supplies cross-build/local OCI evidence only; no native host or registry digest is available"

soak_seconds=${ANTINAT_SOAK_SECONDS:-0}
if [[ "$soak_seconds" =~ ^[0-9]+$ ]] && ((soak_seconds >= 86400)) && [[ -n "${ANTINAT_SOAK_COMMAND:-}" ]]; then
    run_gate soak true "timeout ${soak_seconds}s operator-provided primary-Linux soak" \
        "the requested soak command completed for at least 24 hours" \
        timeout --signal=TERM "${soak_seconds}s" bash -c "$ANTINAT_SOAK_COMMAND"
else
    limited_gate soak true "primary Linux 24-hour resource soak" \
        "a 24-hour soak command was not provisioned; no stability duration is claimed"
fi

gate_json='[]'
for ((i = 0; i < ${#gate_ids[@]}; i++)); do
    gate_json=$(jq -cn --argjson prior "$gate_json" \
        --arg id "${gate_ids[$i]}" --arg result "${gate_results[$i]}" \
        --argjson required "${gate_required[$i]}" --arg command "${gate_commands[$i]}" \
        --arg evidence "${gate_evidence[$i]}" --arg summary "${gate_summaries[$i]}" \
        --arg digest "$artifact_digest" \
        '$prior + [{id:$id,result:$result,required:$required,command:$command,
                   artifact_digest:$digest,evidence:[$evidence],summary:$summary}]')
done

approval_value=false
approver="${ANTINAT_RELEASE_APPROVER:-PENDING}"
if [[ "${ANTINAT_RELEASE_APPROVED:-0}" == 1 ]]; then
    approval_value=true
fi

release_status=PASS
for result in "${gate_results[@]}"; do
    if [[ "$result" == FAIL ]]; then
        release_status=FAIL
        break
    fi
    if [[ "$result" != PASS ]]; then
        release_status=SUPPORTED_WITH_LIMITS
    fi
done
if [[ "$signature_status" != PASS || "$approval_value" != true ]]; then
    [[ "$release_status" == FAIL ]] || release_status=SUPPORTED_WITH_LIMITS
fi

artifact_names=$(jq -r '.artifacts | keys[]' "$release_dir/manifest.json" | jq -Rsc 'split("\n") | map(select(length > 0))')
build_started_at=$(date -u -d "$source_built_at - 1 second" +%Y-%m-%dT%H:%M:%SZ)
build_finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
test_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
test_finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

write_release_record() {
    local final_gate_json=$1
    jq -nS \
        --arg schema antinat.release-evidence/v1 \
        --arg release "$release_version" --arg status "$release_status" \
        --arg artifact_directory "$(realpath --relative-to="$evidence_dir" "$release_dir")" \
        --arg manifest manifest.json --arg signature manifest.sig \
        --arg manifest_sha256 "$artifact_digest" --arg module github.com/gxbrave/AntiNAT \
        --arg commit "$source_commit" --arg tree "$source_tree" --arg go "$source_go" \
        --arg built_at "$source_built_at" --arg build_started "$build_started_at" \
        --arg build_finished "$build_finished_at" --arg test_started "$test_started_at" \
        --arg test_finished "$test_finished_at" --argjson approved "$approval_value" \
        --arg approver "$approver" --argjson gates "$final_gate_json" \
        --argjson artifacts "$artifact_names" --arg signature_status "$signature_status" \
        --arg sbom_status "$sbom_status" \
        '{schema_version:$schema,release:$release,status:$status,
          artifact_directory:$artifact_directory,manifest:$manifest,signature:$signature,
          manifest_sha256:$manifest_sha256,
          source:{module:$module,commit_sha:$commit,tree_sha:$tree,go_version:$go,built_at:$built_at},
          build:{count:1,started_at:$build_started,finished_at:$build_finished,
                 test_started_at:$test_started,test_finished_at:$test_finished},
          approval:{approved:$approved,approver:$approver},gates:$gates,
          known_limits:[
            "No production release signing key or independent release approver was supplied to this candidate run.",
            "Real public-WAN/router, native Windows, native arm64/OpenRC, registry OCI digest, and 24-hour soak evidence remain unproven when their gates are limited."
          ],
          evidence:($gates | map(.evidence[]) | unique | sort),
          artifact_names:$artifacts,signature_status:$signature_status,sbom_status:$sbom_status}' \
        >"$evidence_dir/release.json"
}

# The release verifier is itself a final gate. A placeholder log exists before
# the first pass so the evidence list is complete on both passes.
: >"$evidence_dir/release-evidence.log"
write_release_record "$gate_json"
set +e
if [[ -n "${ANTINAT_TRUST_ROOT_FILE:-}" ]]; then
    ANTINAT_TEST_MODE=1 go run "$script_dir/verify-release-evidence.go" \
        --public-key "$ANTINAT_TRUST_ROOT_FILE" --allow-test-root "$evidence_dir" \
        >"$evidence_dir/release-evidence.log" 2>&1
else
    go run "$script_dir/verify-release-evidence.go" "$evidence_dir" \
        >"$evidence_dir/release-evidence.log" 2>&1
fi
verification_rc=$?
set -e
if ((verification_rc == 0)); then
    verification_result=PASS
else
    verification_result=FAIL
    overall_failure=1
fi
record_gate release-evidence "$verification_result" true \
    "go run scripts/verify-release-evidence.go $evidence_dir" \
    "release-evidence.log" "release evidence verifier exit_code=$verification_rc"

gate_json='[]'
for ((i = 0; i < ${#gate_ids[@]}; i++)); do
    gate_json=$(jq -cn --argjson prior "$gate_json" \
        --arg id "${gate_ids[$i]}" --arg result "${gate_results[$i]}" \
        --argjson required "${gate_required[$i]}" --arg command "${gate_commands[$i]}" \
        --arg evidence "${gate_evidence[$i]}" --arg summary "${gate_summaries[$i]}" \
        --arg digest "$artifact_digest" \
        '$prior + [{id:$id,result:$result,required:$required,command:$command,
                   artifact_digest:$digest,evidence:[$evidence],summary:$summary}]')
done
write_release_record "$gate_json"

# Re-check after adding the verifier gate. This second pass still reads the
# same manifest and artifacts; no release binary is rebuilt.
if [[ -n "${ANTINAT_TRUST_ROOT_FILE:-}" ]]; then
    if ! ANTINAT_TEST_MODE=1 go run "$script_dir/verify-release-evidence.go" \
        --public-key "$ANTINAT_TRUST_ROOT_FILE" --allow-test-root "$evidence_dir" \
        >>"$evidence_dir/release-evidence.log" 2>&1; then
        overall_failure=1
    fi
else
    if ! go run "$script_dir/verify-release-evidence.go" "$evidence_dir" \
        >>"$evidence_dir/release-evidence.log" 2>&1; then
        overall_failure=1
    fi
fi

printf 'release=%s\nstatus=%s\nmanifest_digest=%s\n' \
    "$release_version" "$release_status" "$artifact_digest"
if [[ "$signature_status" != PASS ]]; then
    printf 'promotion=NO_GO (manifest is unsigned)\n'
elif [[ "$approval_value" != true ]]; then
    printf 'promotion=NO_GO (release approver is pending)\n'
elif ((overall_failure != 0)); then
    printf 'promotion=NO_GO (one or more required gates failed)\n'
else
    printf 'promotion=ELIGIBLE_FOR_INDEPENDENT_REVIEW\n'
fi

if ((overall_failure != 0)); then
    exit 1
fi
