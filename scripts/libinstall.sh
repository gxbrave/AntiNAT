#!/usr/bin/env bash

# Shared implementation for install.sh. This file intentionally uses arrays
# and direct command invocations; no user-controlled value is ever passed to
# eval or to a shell command string.

set -euo pipefail

INSTALLER_VERSION="1"
INSTALLER_SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

INSTALLER_EXIT_SUCCESS=0
INSTALLER_EXIT_GENERIC=1
INSTALLER_EXIT_USAGE=2
INSTALLER_EXIT_TOKEN=3
INSTALLER_EXIT_ARTIFACT=4
INSTALLER_EXIT_CONFLICT=5
INSTALLER_EXIT_ROLLBACK=6
INSTALLER_EXIT_PURGE=7
INSTALLER_EXIT_MIGRATION=8

INSTALLER_COMMAND=""
INSTALLER_PLATFORM="linux"
INSTALLER_ENDPOINT=""
INSTALLER_BIND_INTERFACE=""
INSTALLER_DIR="/opt/antinat"
INSTALLER_SERVICE_NAME="antinat-agent.service"
INSTALLER_LOG_LEVEL="info"
INSTALLER_AUTO_UPDATE="disabled"
INSTALLER_GITHUB_PROXY=""
INSTALLER_SCHEDULER="sequential"
INSTALLER_TOKEN_FD=""
INSTALLER_TOKEN_FILE=""
INSTALLER_TOKEN_TMP=""
INSTALLER_TOKEN_SOURCE_CONSUMED=0
INSTALLER_HELP_REQUESTED=0
INSTALLER_VERSION_REQUESTED=0

INSTALLER_TEST_ROOT="${ANTINAT_TEST_ROOT:-}"
INSTALLER_ROLE="${ANTINAT_ROLE:-agent}"

installer_die() {
    local code="$1"
    shift
    printf 'antinat installer: %s\n' "$*" >&2
    return "$code"
}

installer_usage() {
    cat >&2 <<'EOF'
Usage: install.sh {install|uninstall|purge|upgrade} [flags]

Frozen flags:
  --controller-endpoint URL --bind-interface NAME --install-dir PATH
  --service-name NAME --log-level LEVEL --auto-update POLICY
  --github-proxy URL --detection-scheduler MODE --platform linux|windows|docker
  --token-fd FD | --token-file PATH

Tokens are read from a hidden TTY by default. Literal --token arguments are
not accepted.
EOF
}

installer_logical_path() {
    local logical="$1"
    if [[ -n "$INSTALLER_TEST_ROOT" ]]; then
        printf '%s%s' "${INSTALLER_TEST_ROOT%/}" "$logical"
    else
        printf '%s' "$logical"
    fi
}

installer_init_paths() {
    INSTALLER_INSTALL_DIR=$(installer_logical_path /opt/antinat)
    INSTALLER_BIN_DIR=$(installer_logical_path /opt/antinat/bin)
    INSTALLER_AGENT_BINARY=$(installer_logical_path /opt/antinat/bin/antinat-agent)
    INSTALLER_CONTROLLER_BINARY=$(installer_logical_path /opt/antinat/bin/antinat-controller)
    INSTALLER_HOOK_BINARY=$(installer_logical_path /opt/antinat/bin/antinat-hook-runner)
    INSTALLER_DATA_DIR=$(installer_logical_path /var/lib/antinat)
    INSTALLER_CONFIG=$(installer_logical_path /etc/antinat/agent.conf)
    INSTALLER_LOG_DIR=$(installer_logical_path /var/log/antinat)
    INSTALLER_SERVICE_DIR=$(installer_logical_path /etc/systemd/system)
    INSTALLER_AGENT_UNIT=$(installer_logical_path "/etc/systemd/system/${INSTALLER_SERVICE_NAME}")
    INSTALLER_CONTROLLER_UNIT=$(installer_logical_path /etc/systemd/system/antinat-controller.service)
    INSTALLER_OWNERSHIP_MANIFEST=$(installer_logical_path /var/lib/antinat/ownership-manifest.json)
    INSTALLER_OWNERSHIP_KEY=$(installer_logical_path /var/lib/antinat/ownership.key)
    INSTALLER_BACKUP_DIR=$(installer_logical_path /var/lib/antinat/backups)
}

installer_parse_args() {
    if (($# == 0)); then
        installer_usage
        return "$INSTALLER_EXIT_USAGE"
    fi
    INSTALLER_COMMAND="$1"
    shift
    case "$INSTALLER_COMMAND" in
        install|uninstall|purge|upgrade) ;;
        --help)
            INSTALLER_COMMAND=""
            INSTALLER_HELP_REQUESTED=1
            ;;
        --version)
            INSTALLER_COMMAND=""
            INSTALLER_VERSION_REQUESTED=1
            ;;
        *)
            installer_usage
            return "$INSTALLER_EXIT_USAGE"
            ;;
    esac

    while (($# > 0)); do
        local raw="$1"
        local name="$raw"
        local value=""
        local has_value=0
        shift
        if [[ "$raw" == *=* ]]; then
            name="${raw%%=*}"
            value="${raw#*=}"
            has_value=1
        fi
        case "$name" in
            --help)
                ((has_value == 0)) || return "$INSTALLER_EXIT_USAGE"
                INSTALLER_HELP_REQUESTED=1
                ;;
            --version)
                ((has_value == 0)) || return "$INSTALLER_EXIT_USAGE"
                INSTALLER_VERSION_REQUESTED=1
                ;;
            --controller-endpoint|--bind-interface|--install-dir|--service-name|--log-level|--auto-update|--github-proxy|--detection-scheduler|--platform|--token-fd|--token-file)
                if ((has_value == 0)); then
                    (($# > 0)) || return "$INSTALLER_EXIT_USAGE"
                    [[ "$1" != -* ]] || return "$INSTALLER_EXIT_USAGE"
                    value="$1"
                    shift
                fi
                [[ -n "$value" ]] || return "$INSTALLER_EXIT_USAGE"
                case "$name" in
                    --controller-endpoint) INSTALLER_ENDPOINT="$value" ;;
                    --bind-interface) INSTALLER_BIND_INTERFACE="$value" ;;
                    --install-dir) INSTALLER_DIR="$value" ;;
                    --service-name) INSTALLER_SERVICE_NAME="$value" ;;
                    --log-level) INSTALLER_LOG_LEVEL="$value" ;;
                    --auto-update) INSTALLER_AUTO_UPDATE="$value" ;;
                    --github-proxy) INSTALLER_GITHUB_PROXY="$value" ;;
                    --detection-scheduler) INSTALLER_SCHEDULER="$value" ;;
                    --platform) INSTALLER_PLATFORM="$value" ;;
                    --token-fd) INSTALLER_TOKEN_FD="$value" ;;
                    --token-file) INSTALLER_TOKEN_FILE="$value" ;;
                esac
                ;;
            --token|--token-value|-t|--token-*)
                return "$INSTALLER_EXIT_USAGE"
                ;;
            -*|*)
                return "$INSTALLER_EXIT_USAGE"
                ;;
        esac
    done

    if ((INSTALLER_HELP_REQUESTED != 0 && INSTALLER_VERSION_REQUESTED != 0)); then
        return "$INSTALLER_EXIT_USAGE"
    fi
    # A metadata request may not be used to bypass token-input validation. This
    # keeps a literal or protected token argument rejected even when --help is
    # present.
    if [[ -z "$INSTALLER_COMMAND" && (-n "$INSTALLER_TOKEN_FD" || -n "$INSTALLER_TOKEN_FILE") ]]; then
        return "$INSTALLER_EXIT_USAGE"
    fi
    if ((INSTALLER_HELP_REQUESTED != 0)); then
        installer_usage
        return 0
    fi
    if ((INSTALLER_VERSION_REQUESTED != 0)); then
        printf 'antinat-installer %s\n' "$INSTALLER_VERSION"
        return 0
    fi
    [[ -n "$INSTALLER_COMMAND" ]] || return "$INSTALLER_EXIT_USAGE"
    [[ "$INSTALLER_PLATFORM" == linux ]] || return "$INSTALLER_EXIT_USAGE"
    [[ "$INSTALLER_DIR" == /opt/antinat ]] || return "$INSTALLER_EXIT_USAGE"
    [[ "$INSTALLER_SERVICE_NAME" == antinat-agent.service ]] || return "$INSTALLER_EXIT_USAGE"
    if [[ -n "$INSTALLER_TOKEN_FD" && -n "$INSTALLER_TOKEN_FILE" ]]; then
        return "$INSTALLER_EXIT_TOKEN"
    fi
    if [[ -n "$INSTALLER_TOKEN_FD" ]]; then
        [[ "$INSTALLER_TOKEN_FD" =~ ^[3-9][0-9]*$ ]] || return "$INSTALLER_EXIT_TOKEN"
    fi
    if [[ "$INSTALLER_COMMAND" == install && -z "$INSTALLER_ENDPOINT" && "${ANTINAT_TEST_MODE:-0}" != 1 ]]; then
        return "$INSTALLER_EXIT_USAGE"
    fi
    installer_validate_text "$INSTALLER_ENDPOINT" || return "$INSTALLER_EXIT_USAGE"
    installer_validate_text "$INSTALLER_BIND_INTERFACE" || return "$INSTALLER_EXIT_USAGE"
    installer_validate_text "$INSTALLER_GITHUB_PROXY" || return "$INSTALLER_EXIT_USAGE"
    installer_validate_text "$INSTALLER_SCHEDULER" || return "$INSTALLER_EXIT_USAGE"
    return 0
}

installer_validate_text() {
    local value="$1"
    # Bash strings cannot contain NUL bytes; reject the control characters
    # that can be represented in a shell variable.
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]]
}

installer_validate_endpoint() {
    local endpoint="$1"
    [[ "$endpoint" =~ ^https?://[^[:space:]/?#]+(:[0-9]+)?([/][^[:space:]?#]*)?$ ]] || return 1
    [[ "$endpoint" != *"@"* && "$endpoint" != *"?"* && "$endpoint" != *"#"* ]]
}

installer_require_tools() {
    local tool
    for tool in awk chmod cp curl find getent groupadd hostname id install jq mktemp mv od openssl readlink rm rmdir sha256sum stat tr useradd; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            installer_die "$INSTALLER_EXIT_GENERIC" "required tool $tool is unavailable" || true
            return "$INSTALLER_EXIT_GENERIC"
        fi
    done
}

installer_fetch_release() {
    if [[ -n "${ANTINAT_ARTIFACT_DIR:-}" ]]; then
        INSTALLER_ARTIFACT_DIR="$ANTINAT_ARTIFACT_DIR"
        INSTALLER_MANIFEST_FILE="${ANTINAT_MANIFEST_FILE:-$INSTALLER_ARTIFACT_DIR/manifest.json}"
        INSTALLER_SIGNATURE_FILE="${ANTINAT_SIGNATURE_FILE:-$INSTALLER_ARTIFACT_DIR/manifest.sig}"
        return 0
    fi
    local base_url="${ANTINAT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT/releases/download/v1.0.0-beta}"
    [[ "$base_url" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$ ]] || return "$INSTALLER_EXIT_ARTIFACT"
    local scratch
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/antinat-release.XXXXXX") || return "$INSTALLER_EXIT_ARTIFACT"
    INSTALLER_ARTIFACT_DIR="$scratch"
    INSTALLER_MANIFEST_FILE="$scratch/manifest.json"
    INSTALLER_SIGNATURE_FILE="$scratch/manifest.sig"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 60 "$base_url/manifest.json" -o "$INSTALLER_MANIFEST_FILE" || return "$INSTALLER_EXIT_ARTIFACT"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 60 "$base_url/manifest.sig" -o "$INSTALLER_SIGNATURE_FILE" || return "$INSTALLER_EXIT_ARTIFACT"
    local artifact
    while IFS= read -r artifact; do
        [[ -n "$artifact" ]] || continue
        [[ "$artifact" != */* ]] && artifact="${artifact##*/}"
        curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 120 "$base_url/$artifact" -o "$scratch/${artifact##*/}" || return "$INSTALLER_EXIT_ARTIFACT"
    done < <(jq -r '.artifacts | keys[]' "$INSTALLER_MANIFEST_FILE")
    return 0
}

installer_verify_artifacts() {
    local trust_root="${ANTINAT_TRUST_ROOT_FILE:-$INSTALLER_SCRIPT_DIR/../deploy/trust/release-ed25519.pub}"
    if [[ ! -d "$INSTALLER_ARTIFACT_DIR" || -L "$INSTALLER_ARTIFACT_DIR" || "$(readlink -f -- "$INSTALLER_ARTIFACT_DIR" 2>/dev/null)" != "$INSTALLER_ARTIFACT_DIR" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact directory is not a private canonical directory" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ ! -r "$trust_root" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "pinned release trust root is unavailable" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ ! -r "$INSTALLER_MANIFEST_FILE" || ! -r "$INSTALLER_SIGNATURE_FILE" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release manifest or detached signature is missing" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if ! jq -e 'type == "object" and ((keys - ["schema_version", "release", "artifacts", "trust_root", "signature_algorithm"]) | length == 0)' "$INSTALLER_MANIFEST_FILE" >/dev/null; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release manifest has unknown fields" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ "$(jq -r '.schema_version // empty' "$INSTALLER_MANIFEST_FILE")" != 1 ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "unsupported release manifest schema" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ "$(jq -r '.signature_algorithm // "ed25519"' "$INSTALLER_MANIFEST_FILE")" != ed25519 ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "unsupported release signature algorithm" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ "$(jq -r '.trust_root // empty' "$INSTALLER_MANIFEST_FILE")" != "${ANTINAT_TRUST_ROOT_ID:-release-key-2026}" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release manifest trust root is not pinned" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if ! jq -e '.trust_root | type == "string" and length > 0' "$INSTALLER_MANIFEST_FILE" >/dev/null || \
        ! jq -e '.artifacts | type == "object" and length > 0' "$INSTALLER_MANIFEST_FILE" >/dev/null; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release manifest has no artifacts" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if ! openssl pkeyutl -verify -pubin -inkey "$trust_root" -rawin -in "$INSTALLER_MANIFEST_FILE" -sigfile "$INSTALLER_SIGNATURE_FILE" >/dev/null 2>&1; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "detached release manifest signature failed" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi

    local name digest path actual leaf
    declare -A seen_artifact_leaves=()
    while IFS=$'\t' read -r name digest; do
        if [[ ! "$name" =~ ^[A-Za-z0-9._/-]+$ || "$name" == /* || "$name" == *"//"* || "$name" =~ (^|/)\.\.?(/|$) ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "unsafe artifact name" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
        leaf="${name##*/}"
        if [[ -z "$leaf" || -n "${seen_artifact_leaves[$leaf]+present}" ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact names collide after extraction" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
        seen_artifact_leaves["$leaf"]=1
        if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact digest is not lowercase SHA-256" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
        path="$INSTALLER_ARTIFACT_DIR/$leaf"
        if [[ ! -f "$path" || -L "$path" ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact is missing" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
        actual=$(sha256sum -- "$path" | awk '{print $1}')
        if [[ "$actual" != "$digest" ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact digest mismatch" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
    done < <(jq -r '.artifacts | to_entries[] | [.key,.value] | @tsv' "$INSTALLER_MANIFEST_FILE")
}

installer_find_artifact() {
    local suffix="$1"
    local name
    name=$(jq -r --arg suffix "$suffix" '.artifacts | keys[] | select(endswith($suffix))' "$INSTALLER_MANIFEST_FILE" | head -n 1)
    [[ -n "$name" ]] || return 1
    printf '%s/%s' "$INSTALLER_ARTIFACT_DIR" "${name##*/}"
}

installer_read_token() {
    local token_tmp_dir="$INSTALLER_DATA_DIR"
    mkdir -p -- "$token_tmp_dir"
    chmod 700 -- "$token_tmp_dir"
    INSTALLER_TOKEN_TMP=$(mktemp "$token_tmp_dir/.enrollment-token.XXXXXX") || return "$INSTALLER_EXIT_TOKEN"
    chmod 600 -- "$INSTALLER_TOKEN_TMP"
    if [[ -n "$INSTALLER_TOKEN_FD" ]]; then
        # The descriptor is read directly; its contents are never placed in
        # argv or an environment variable.
        head -c 4097 <&"$INSTALLER_TOKEN_FD" >"$INSTALLER_TOKEN_TMP" || return "$INSTALLER_EXIT_TOKEN"
    elif [[ -n "$INSTALLER_TOKEN_FILE" ]]; then
        [[ -f "$INSTALLER_TOKEN_FILE" && ! -L "$INSTALLER_TOKEN_FILE" ]] || return "$INSTALLER_EXIT_TOKEN"
        local mode owner links
        mode=$(stat -c '%a' -- "$INSTALLER_TOKEN_FILE") || return "$INSTALLER_EXIT_TOKEN"
        owner=$(stat -c '%u' -- "$INSTALLER_TOKEN_FILE") || return "$INSTALLER_EXIT_TOKEN"
        links=$(stat -c '%h' -- "$INSTALLER_TOKEN_FILE") || return "$INSTALLER_EXIT_TOKEN"
        [[ "$mode" == 600 && "$owner" == "$(id -u)" && "$links" == 1 ]] || return "$INSTALLER_EXIT_TOKEN"
        head -c 4097 -- "$INSTALLER_TOKEN_FILE" >"$INSTALLER_TOKEN_TMP" || return "$INSTALLER_EXIT_TOKEN"
    else
        local tty=/dev/tty token
        [[ -r "$tty" && -w "$tty" ]] || return "$INSTALLER_EXIT_TOKEN"
        printf 'Enrollment token: ' >"$tty"
        IFS= read -r -s token <"$tty" || return "$INSTALLER_EXIT_TOKEN"
        printf '\n' >"$tty"
        printf '%s\n' "$token" >"$INSTALLER_TOKEN_TMP"
    fi
    [[ "$(wc -c <"$INSTALLER_TOKEN_TMP")" -le 4096 ]] || return "$INSTALLER_EXIT_TOKEN"
    [[ -s "$INSTALLER_TOKEN_TMP" ]] || return "$INSTALLER_EXIT_TOKEN"
    # The systemd Agent runs as antinat, while the installer normally runs as
    # root. Transfer ownership before the path is placed in its environment.
    installer_chown antinat:antinat "$INSTALLER_TOKEN_TMP" || return "$INSTALLER_EXIT_TOKEN"
}

installer_cleanup_token() {
    if [[ -n "$INSTALLER_TOKEN_TMP" && -e "$INSTALLER_TOKEN_TMP" ]]; then
        chmod 600 -- "$INSTALLER_TOKEN_TMP" 2>/dev/null || true
        rm -f -- "$INSTALLER_TOKEN_TMP"
    fi
    INSTALLER_TOKEN_TMP=""
}

installer_consume_source_token() {
    [[ -n "$INSTALLER_TOKEN_FILE" && "$INSTALLER_TOKEN_SOURCE_CONSUMED" == 0 ]] || return 0
    [[ -f "$INSTALLER_TOKEN_FILE" && ! -L "$INSTALLER_TOKEN_FILE" ]] || return "$INSTALLER_EXIT_TOKEN"
    local mode owner links
    mode=$(stat -c '%a' -- "$INSTALLER_TOKEN_FILE") || return "$INSTALLER_EXIT_TOKEN"
    owner=$(stat -c '%u' -- "$INSTALLER_TOKEN_FILE") || return "$INSTALLER_EXIT_TOKEN"
    links=$(stat -c '%h' -- "$INSTALLER_TOKEN_FILE") || return "$INSTALLER_EXIT_TOKEN"
    [[ "$mode" == 600 && "$owner" == "$(id -u)" && "$links" == 1 ]] || return "$INSTALLER_EXIT_TOKEN"
    rm -f -- "$INSTALLER_TOKEN_FILE" || return "$INSTALLER_EXIT_TOKEN"
    INSTALLER_TOKEN_SOURCE_CONSUMED=1
}

installer_atomic_copy() {
    local source="$1" destination="$2" mode="$3"
    [[ -f "$source" && ! -L "$source" ]] || return 1
    mkdir -p -- "$(dirname -- "$destination")"
    local temporary
    temporary=$(mktemp "$(dirname -- "$destination")/.antinat-copy.XXXXXX") || return 1
    chmod "$mode" -- "$temporary"
    if ! cp -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    chmod "$mode" -- "$temporary"
    mv -f -- "$temporary" "$destination"
}

installer_write_config() {
    local token_file="${1:-}"
    local node_id="${ANTINAT_NODE_ID:-}"
    if [[ -z "$node_id" ]]; then
        node_id=$(hostname 2>/dev/null || printf 'antinat-node')
    fi
    if ((${#node_id} > 16)); then
        node_id=$(printf '%s' "$node_id" | sha256sum | awk '{print substr($1,1,16)}')
    fi
    installer_validate_endpoint "$INSTALLER_ENDPOINT" || return "$INSTALLER_EXIT_USAGE"
    installer_validate_text "$node_id" || return "$INSTALLER_EXIT_USAGE"
    mkdir -p -- "$(dirname -- "$INSTALLER_CONFIG")"
    chmod 750 -- "$(dirname -- "$INSTALLER_CONFIG")"
    local temporary
    temporary=$(mktemp "$(dirname -- "$INSTALLER_CONFIG")/.agent-conf.XXXXXX") || return 1
    chmod 600 -- "$temporary"
    {
        printf "ANTINAT_ENDPOINT='%s'\n" "${INSTALLER_ENDPOINT//\'/\'\\\'\'}"
        printf "ANTINAT_NODE='%s'\n" "${node_id//\'/\'\\\'\'}"
        printf "ANTINAT_STATE='%s'\n" "${INSTALLER_DATA_DIR//\'/\'\\\'\'}"
        if [[ -n "${ANTINAT_CONTROLLER_PIN:-}" ]]; then
            printf "ANTINAT_PIN='%s'\n" "${ANTINAT_CONTROLLER_PIN//\'/\'\\\'\'}"
        fi
        if [[ -n "$token_file" ]]; then
            printf "ANTINAT_TOKEN_FILE='%s'\n" "${token_file//\'/\'\\\'\'}"
        fi
        if [[ -n "$INSTALLER_GITHUB_PROXY" ]]; then
            printf "ANTINAT_GITHUB_PROXY='%s'\n" "${INSTALLER_GITHUB_PROXY//\'/\'\\\'\'}"
        fi
        if [[ -n "${ANTINAT_STUN_SERVERS:-}" ]]; then
            printf "ANTINAT_STUN_SERVERS='%s'\n" "${ANTINAT_STUN_SERVERS//\'/\'\\\'\'}"
        fi
        if [[ -n "${ANTINAT_AUTO_ORDER:-}" ]]; then
            printf "ANTINAT_AUTO_ORDER='%s'\n" "${ANTINAT_AUTO_ORDER//\'/\'\\\'\'}"
        fi
    } >"$temporary"
    mv -f -- "$temporary" "$INSTALLER_CONFIG"
    chmod 600 -- "$INSTALLER_CONFIG"
}

installer_create_user() {
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    if ! getent group antinat >/dev/null 2>&1; then
        groupadd --system antinat
    fi
    if ! id antinat >/dev/null 2>&1; then
        useradd --system --gid antinat --home-dir /var/lib/antinat --shell /usr/sbin/nologin antinat
    fi
}

installer_install_unit() {
    local source="$1" destination="$2"
    [[ -r "$source" ]] || return 1
    mkdir -p -- "$(dirname -- "$destination")"
    installer_atomic_copy "$source" "$destination" 644
}

installer_find_service_source() {
    local unit="$1" candidate
    if [[ -n "${ANTINAT_SYSTEMD_DIR:-}" ]]; then
        candidate="$ANTINAT_SYSTEMD_DIR/$unit"
        if [[ -r "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
    for candidate in \
        "$INSTALLER_SCRIPT_DIR/../deploy/systemd/$unit" \
        "$INSTALLER_SCRIPT_DIR/systemd/$unit" \
        "/usr/share/antinat/systemd/$unit"; do
        if [[ -r "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

installer_install_embedded_unit() {
    local unit="$1" destination="$2" temporary
    temporary=$(mktemp "${TMPDIR:-/tmp}/antinat-unit.XXXXXX") || return 1
    case "$unit" in
        antinat-agent.service)
            {
                printf '%s\n' '[Unit]' 'Description=AntiNAT Agent' \
                    'Wants=network-online.target' 'After=network-online.target'
                printf '%s\n' '' '[Service]' 'Type=simple' 'User=antinat' \
                    'Group=antinat' 'EnvironmentFile=-/etc/antinat/agent.conf' \
                    'ExecStart=/opt/antinat/bin/antinat-agent' \
                    'WorkingDirectory=/var/lib/antinat' 'Restart=on-failure' \
                    'RestartSec=5s' 'TimeoutStopSec=15s' 'UMask=0077' \
                    'NoNewPrivileges=true' 'PrivateTmp=true' 'ProtectHome=true' \
                    'ProtectSystem=strict' 'CapabilityBoundingSet=' \
                    'AmbientCapabilities=' 'ReadWritePaths=/var/lib/antinat /var/log/antinat'
                printf '%s\n' '' '[Install]' 'WantedBy=multi-user.target'
            } >"$temporary"
            ;;
        antinat-controller.service)
            {
                printf '%s\n' '[Unit]' 'Description=AntiNAT Controller' \
                    'Wants=network-online.target' 'After=network-online.target'
                printf '%s\n' '' '[Service]' 'Type=simple' 'User=antinat' \
                    'Group=antinat' \
                    'ExecStart=/opt/antinat/bin/antinat-controller -listen 127.0.0.1:3111 -store /var/lib/antinat/controller.db -keydir /var/lib/antinat/controller-keys' \
                    'WorkingDirectory=/var/lib/antinat' 'Restart=on-failure' \
                    'RestartSec=5s' 'TimeoutStopSec=15s' 'UMask=0077' \
                    'NoNewPrivileges=true' 'PrivateTmp=true' 'ProtectHome=true' \
                    'ProtectSystem=strict' 'CapabilityBoundingSet=' \
                    'AmbientCapabilities=' 'ReadWritePaths=/var/lib/antinat /var/log/antinat'
                printf '%s\n' '' '[Install]' 'WantedBy=multi-user.target'
            } >"$temporary"
            ;;
        *)
            rm -f -- "$temporary"
            return 1
            ;;
    esac
    if ! installer_atomic_copy "$temporary" "$destination" 644; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
}

installer_install_service_unit() {
    local unit="$1" destination="$2" source
    if source=$(installer_find_service_source "$unit"); then
        installer_install_unit "$source" "$destination"
    else
        installer_install_embedded_unit "$unit" "$destination"
    fi
}

installer_systemctl() {
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    systemctl "$@"
}

installer_chown() {
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    chown "$@"
}

installer_make_ownership_manifest() {
    local installation_id
    installation_id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    mkdir -p -- "$INSTALLER_DATA_DIR"
    chmod 700 -- "$INSTALLER_DATA_DIR"
    [[ -e "$INSTALLER_OWNERSHIP_KEY" ]] || head -c 32 /dev/urandom >"$INSTALLER_OWNERSHIP_KEY"
    chmod 600 -- "$INSTALLER_OWNERSHIP_KEY"
    local key_hex payload mac manifest
    key_hex=$(od -An -v -tx1 "$INSTALLER_OWNERSHIP_KEY" | tr -d ' \n')
    payload=$(jq -cn \
        --arg id "$installation_id" \
        --arg install "$INSTALLER_INSTALL_DIR" \
        --arg data "$INSTALLER_DATA_DIR" \
        --arg config "$(dirname -- "$INSTALLER_CONFIG")" \
        --arg service "$INSTALLER_SERVICE_DIR" \
        '{schema_version:1,installation_id:$id,resources:[
          {root:$install,path:"bin/antinat-agent"},
          {root:$install,path:"bin/antinat-controller"},
          {root:$install,path:"bin/antinat-hook-runner"},
          {root:$data,path:"state.db"},
          {root:$data,path:"node.key"},
          {root:$data,path:"controller.db"},
          {root:$data,path:"terminal.marker"},
          {root:$data,path:"agent.marker"},
          {root:$data,path:"backups"},
          {root:$data,path:"ownership-manifest.json"},
          {root:$data,path:"ownership.key"},
          {root:$config,path:"agent.conf"},
          {root:$service,path:"antinat-agent.service"},
          {root:$service,path:"antinat-controller.service"}
        ]}')
    mac=$(printf '%s' "$payload" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" | awk '{print $NF}')
    manifest=$(printf '%s' "$payload" | jq -c --arg hmac "$mac" '. + {hmac:$hmac}')
    printf '%s\n' "$manifest" >"$INSTALLER_OWNERSHIP_MANIFEST"
    chmod 600 -- "$INSTALLER_OWNERSHIP_MANIFEST"
}

installer_prepare_dirs() {
    mkdir -p -- "$INSTALLER_BIN_DIR" "$INSTALLER_DATA_DIR" "$INSTALLER_LOG_DIR" "$INSTALLER_SERVICE_DIR" "$(dirname -- "$INSTALLER_CONFIG")"
    chmod 755 -- "$INSTALLER_INSTALL_DIR" "$INSTALLER_BIN_DIR" "$INSTALLER_LOG_DIR" "$INSTALLER_SERVICE_DIR"
    chmod 700 -- "$INSTALLER_DATA_DIR"
    chmod 750 -- "$(dirname -- "$INSTALLER_CONFIG")"
    installer_chown antinat:antinat "$INSTALLER_DATA_DIR" "$INSTALLER_LOG_DIR"
}

installer_install_files() {
    local agent controller hook
    if ! agent=$(installer_find_artifact "antinat-agent-linux-amd64"); then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "Linux Agent artifact is missing" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    installer_atomic_copy "$agent" "$INSTALLER_AGENT_BINARY" 755 || return 1
    controller=$(installer_find_artifact "antinat-controller-linux-amd64") || true
    if [[ -n "$controller" && -f "$controller" ]]; then
        installer_atomic_copy "$controller" "$INSTALLER_CONTROLLER_BINARY" 755 || return 1
    fi
    hook=$(installer_find_artifact "antinat-hook-runner-linux-amd64") || true
    if [[ -n "$hook" && -f "$hook" ]]; then
        installer_atomic_copy "$hook" "$INSTALLER_HOOK_BINARY" 755 || return 1
    fi
}

installer_install_services() {
    installer_install_service_unit antinat-agent.service "$INSTALLER_AGENT_UNIT" || return 1
    if [[ -f "$INSTALLER_CONTROLLER_BINARY" ]]; then
        installer_install_service_unit antinat-controller.service "$INSTALLER_CONTROLLER_UNIT" || return 1
    fi
    installer_systemctl daemon-reload
    installer_systemctl enable --now "$INSTALLER_SERVICE_NAME"
}

installer_wait_for_token_consumption() {
    [[ -n "$INSTALLER_TOKEN_TMP" ]] || return 0
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    local i
    for ((i=0; i<30; i++)); do
        [[ ! -e "$INSTALLER_TOKEN_TMP" ]] && { installer_consume_source_token; return 0; }
        sleep 1
    done
    # Enrollment has not been proven. Preserve the source token and report a
    # token failure; the service can be inspected and retried by the operator.
    return "$INSTALLER_EXIT_TOKEN"
}

installer_conflict() {
    [[ "$INSTALLER_COMMAND" == install ]] || return 1
    [[ -e "$INSTALLER_AGENT_BINARY" || -e "$INSTALLER_AGENT_UNIT" ]]
}

installer_install() {
    if ! installer_validate_endpoint "$INSTALLER_ENDPOINT"; then
        installer_die "$INSTALLER_EXIT_USAGE" "controller endpoint must be an http(s) URL without credentials, query or fragment" || true
        return "$INSTALLER_EXIT_USAGE"
    fi
    installer_init_paths
    installer_require_tools
    installer_fetch_release || return "$INSTALLER_EXIT_ARTIFACT"
    installer_verify_artifacts
    if installer_conflict; then
        installer_die "$INSTALLER_EXIT_CONFLICT" "AntiNAT is already installed; use upgrade" || true
        return "$INSTALLER_EXIT_CONFLICT"
    fi
    installer_create_user
    installer_prepare_dirs
    if [[ -n "$INSTALLER_TOKEN_FD" || -n "$INSTALLER_TOKEN_FILE" || "${ANTINAT_TEST_MODE:-0}" != 1 ]]; then
        installer_read_token || { installer_cleanup_token; return "$INSTALLER_EXIT_TOKEN"; }
    fi
    installer_install_files || {
        installer_cleanup_token
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    }
    local token_for_service="${INSTALLER_TOKEN_TMP:-}"
    installer_write_config "$token_for_service" || {
        installer_cleanup_token
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    }
    installer_install_services || {
        installer_cleanup_token
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    }
    installer_wait_for_token_consumption || {
        installer_cleanup_token
        installer_rollback_new_install
        return "$INSTALLER_EXIT_TOKEN"
    }
    if [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]]; then
        installer_consume_source_token || {
            installer_cleanup_token
            installer_rollback_new_install
            return "$INSTALLER_EXIT_TOKEN"
        }
    fi
    if [[ -n "$INSTALLER_TOKEN_TMP" ]]; then
        # The one-time path is only needed until enrollment commits. Keeping
        # it in the service environment would make every later restart try to
        # enroll against a file that the Agent already consumed.
        installer_write_config "" || {
            installer_cleanup_token
            installer_rollback_new_install
            return "$INSTALLER_EXIT_GENERIC"
        }
        installer_systemctl daemon-reload || true
    fi
    installer_cleanup_token
    if ! installer_make_ownership_manifest; then
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    fi
    installer_chown antinat:antinat "$INSTALLER_CONFIG" "$INSTALLER_OWNERSHIP_MANIFEST" "$INSTALLER_OWNERSHIP_KEY"
    printf 'antinat installer: install complete\n'
}

installer_stop_service() {
    installer_systemctl stop "$INSTALLER_SERVICE_NAME" || true
    installer_systemctl disable "$INSTALLER_SERVICE_NAME" || true
    installer_systemctl daemon-reload || true
}

installer_uninstall() {
    installer_init_paths
    installer_stop_service
    rm -f -- "$INSTALLER_AGENT_UNIT" "$INSTALLER_CONTROLLER_UNIT" "$INSTALLER_AGENT_BINARY" "$INSTALLER_CONTROLLER_BINARY" "$INSTALLER_HOOK_BINARY" "$INSTALLER_CONFIG"
    printf 'antinat installer: service and executable files removed; state retained\n'
}

installer_safe_remove() {
    local root="$1" relative="$2"
    [[ "$root" == /* && "$relative" != /* && "$relative" != *".."* && "$relative" != *"\\"* ]] || return 1
    local canonical_root canonical_target
    canonical_root=$(readlink -f -- "$root") || return 1
    [[ "$canonical_root" == "$root" ]] || return 1
    local target="$root/$relative"
    [[ ! -L "$target" ]] || return 1
    if [[ -e "$target" || -L "$target" ]]; then
        canonical_target=$(readlink -f -- "$target") || return 1
        [[ "$canonical_target" == "$target" ]] || return 1
    fi
    if [[ -d "$target" ]]; then
        local child
        while IFS= read -r -d '' child; do
            [[ ! -L "$child" ]] || return 1
            if [[ -d "$child" ]]; then
                installer_safe_remove "$root" "${child#"$root"/}" || return 1
            else
                [[ -f "$child" ]] || return 1
                rm -f -- "$child"
            fi
        done < <(find -P -- "$target" -mindepth 1 -maxdepth 1 -print0)
        rmdir -- "$target"
    elif [[ -e "$target" ]]; then
        [[ -f "$target" ]] || return 1
        rm -f -- "$target"
    fi
}

installer_rollback_new_install() {
    installer_stop_service
    installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-agent || true
    installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-controller || true
    installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-hook-runner || true
    installer_safe_remove "$INSTALLER_DATA_DIR" state.db || true
    installer_safe_remove "$INSTALLER_DATA_DIR" node.key || true
    installer_safe_remove "$INSTALLER_DATA_DIR" controller.db || true
    installer_safe_remove "$INSTALLER_DATA_DIR" terminal.marker || true
    installer_safe_remove "$INSTALLER_DATA_DIR" agent.marker || true
    installer_safe_remove "$INSTALLER_DATA_DIR" ownership-manifest.json || true
    installer_safe_remove "$INSTALLER_DATA_DIR" ownership.key || true
    installer_safe_remove "$(dirname -- "$INSTALLER_CONFIG")" agent.conf || true
    installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-agent.service || true
    installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-controller.service || true
    rmdir -- "$INSTALLER_BIN_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_INSTALL_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_SERVICE_DIR" 2>/dev/null || true
    rmdir -- "$(dirname -- "$INSTALLER_CONFIG")" 2>/dev/null || true
    rmdir -- "$INSTALLER_DATA_DIR" 2>/dev/null || true
}

installer_fallback_purge() {
    installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-agent || return 1
    installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-controller || return 1
    installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-hook-runner || return 1
    installer_safe_remove "$INSTALLER_DATA_DIR" terminal.marker || return 1
    installer_safe_remove "$INSTALLER_DATA_DIR" agent.marker || return 1
    installer_safe_remove "$INSTALLER_DATA_DIR" state.db || return 1
    installer_safe_remove "$INSTALLER_DATA_DIR" node.key || return 1
    installer_safe_remove "$INSTALLER_DATA_DIR" controller.db || return 1
    installer_safe_remove "$INSTALLER_DATA_DIR" backups || return 1
    installer_safe_remove "$INSTALLER_DATA_DIR" ownership-manifest.json || return 1
    installer_safe_remove "$INSTALLER_DATA_DIR" ownership.key || return 1
    installer_safe_remove "$(dirname -- "$INSTALLER_CONFIG")" agent.conf || return 1
    installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-agent.service || return 1
    installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-controller.service || return 1
}

installer_manifest_purge() {
    [[ -f "$INSTALLER_OWNERSHIP_MANIFEST" && ! -L "$INSTALLER_OWNERSHIP_MANIFEST" ]] || return 1
    [[ -f "$INSTALLER_OWNERSHIP_KEY" && ! -L "$INSTALLER_OWNERSHIP_KEY" ]] || return 1
    local mode owner links
    mode=$(stat -c '%a' -- "$INSTALLER_OWNERSHIP_KEY") || return 1
    owner=$(stat -c '%u' -- "$INSTALLER_OWNERSHIP_KEY") || return 1
    links=$(stat -c '%h' -- "$INSTALLER_OWNERSHIP_KEY") || return 1
    [[ "$mode" == 600 && "$owner" == "$(id -u)" && "$links" == 1 ]] || return 1
    local key_hex expected payload actual
    key_hex=$(od -An -v -tx1 "$INSTALLER_OWNERSHIP_KEY" | tr -d ' \n')
    if ! jq -e 'type == "object" and ((keys - ["schema_version", "installation_id", "resources", "hmac"]) | length == 0) and .schema_version == 1 and (.installation_id | type == "string" and test("^[A-Za-z0-9._-]+$")) and (.resources | type == "array" and length > 0) and (.hmac | type == "string" and test("^[0-9a-f]{64}$"))' "$INSTALLER_OWNERSHIP_MANIFEST" >/dev/null; then
        return 1
    fi
    payload=$(jq -c '{schema_version,installation_id,resources}' "$INSTALLER_OWNERSHIP_MANIFEST") || return 1
    expected=$(jq -r '.hmac // empty' "$INSTALLER_OWNERSHIP_MANIFEST")
    actual=$(printf '%s' "$payload" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" | awk '{print $NF}')
    [[ "$expected" =~ ^[0-9a-f]{64}$ && "$expected" == "$actual" ]] || return 1
    local root path allowlisted
    while IFS=$'\t' read -r root path; do
        allowlisted=0
        case "$root:$path" in
            "$INSTALLER_INSTALL_DIR:bin/antinat-agent"|\
            "$INSTALLER_INSTALL_DIR:bin/antinat-controller"|\
            "$INSTALLER_INSTALL_DIR:bin/antinat-hook-runner"|\
            "$INSTALLER_DATA_DIR:state.db"|\
            "$INSTALLER_DATA_DIR:node.key"|\
            "$INSTALLER_DATA_DIR:controller.db"|\
            "$INSTALLER_DATA_DIR:terminal.marker"|\
            "$INSTALLER_DATA_DIR:agent.marker"|\
            "$INSTALLER_DATA_DIR:backups"|\
            "$INSTALLER_DATA_DIR:ownership-manifest.json"|\
            "$INSTALLER_DATA_DIR:ownership.key"|\
            "$(dirname -- "$INSTALLER_CONFIG"):agent.conf"|\
            "$INSTALLER_SERVICE_DIR:antinat-agent.service"|\
            "$INSTALLER_SERVICE_DIR:antinat-controller.service")
                allowlisted=1
                ;;
        esac
        ((allowlisted == 1)) || return 1
        installer_safe_remove "$root" "$path" || return 1
    done < <(jq -r '.resources[] | [.root,.path] | @tsv' "$INSTALLER_OWNERSHIP_MANIFEST")
}

installer_purge() {
    installer_init_paths
    installer_stop_service
    local used_manifest=1
    if ! installer_manifest_purge; then
        used_manifest=0
        printf 'antinat installer: ownership manifest unavailable or invalid; using compile-time allowlist only\n' >&2
        installer_fallback_purge || return "$INSTALLER_EXIT_GENERIC"
    fi
    # Empty parent directories are safe to remove only when they contain no
    # user files. Never use recursive deletion for these shared parents.
    rmdir -- "$INSTALLER_BIN_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_INSTALL_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_SERVICE_DIR" 2>/dev/null || true
    rmdir -- "$(dirname -- "$INSTALLER_CONFIG")" 2>/dev/null || true
    rmdir -- "$INSTALLER_DATA_DIR" 2>/dev/null || true
    if ((used_manifest == 0)); then
        printf 'antinat installer: remote decommission status is unknown; verify Controller-side purge separately\n' >&2
    fi
    printf 'antinat installer: purge complete; no owned residue remains\n'
    return "$INSTALLER_EXIT_PURGE"
}

installer_snapshot_files() {
    local backup="$1"
    mkdir -p -- "$backup"
    chmod 700 -- "$backup"
    local root relative source destination
    while IFS=$'\t' read -r root relative; do
        source="$root/$relative"
        [[ -e "$source" ]] || continue
        [[ -f "$source" && ! -L "$source" ]] || return 1
        destination="$backup/${root#/}/$relative"
        mkdir -p -- "$(dirname -- "$destination")"
        cp -- "$source" "$destination" || return 1
        chmod "$(stat -c '%a' -- "$source")" -- "$destination"
    done < <(installer_upgrade_resource_list)
}

installer_upgrade_resource_list() {
    printf '%s\t%s\n' "$INSTALLER_INSTALL_DIR" bin/antinat-agent
    printf '%s\t%s\n' "$INSTALLER_INSTALL_DIR" bin/antinat-controller
    printf '%s\t%s\n' "$INSTALLER_INSTALL_DIR" bin/antinat-hook-runner
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" state.db
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" node.key
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" controller.db
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" ownership-manifest.json
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" ownership.key
    printf '%s\t%s\n' "$(dirname -- "$INSTALLER_CONFIG")" agent.conf
}

installer_restore_snapshot() {
    local backup="$1"
    local root relative source destination
    while IFS=$'\t' read -r root relative; do
        source="$root/$relative"
        destination="$backup/${root#/}/$relative"
        if [[ -f "$destination" ]]; then
            installer_atomic_copy "$destination" "$source" "$(stat -c '%a' -- "$destination")" || return 1
        fi
    done < <(installer_upgrade_resource_list)
}

installer_upgrade() {
    installer_init_paths
    installer_require_tools
    installer_fetch_release || return "$INSTALLER_EXIT_ARTIFACT"
    installer_verify_artifacts
    if [[ ! -e "$INSTALLER_AGENT_BINARY" ]]; then
        installer_die "$INSTALLER_EXIT_CONFLICT" "cannot upgrade an installation that is not present" || true
        return "$INSTALLER_EXIT_CONFLICT"
    fi
    mkdir -p -- "$INSTALLER_BACKUP_DIR"
    local lock="$INSTALLER_DATA_DIR/.upgrade.lock"
    if ! (set -C; printf '%s\n' "upgrade barrier" >"$lock") 2>/dev/null; then
        installer_die "$INSTALLER_EXIT_CONFLICT" "another upgrade is already running" || true
        return "$INSTALLER_EXIT_CONFLICT"
    fi
    local backup
    backup=$(mktemp -d "$INSTALLER_BACKUP_DIR/upgrade.XXXXXX") || { rm -f -- "$lock"; return "$INSTALLER_EXIT_GENERIC"; }
    local failed=0
    installer_stop_service
    installer_snapshot_files "$backup" || failed=1
    if ((failed == 0)); then
        local agent
        agent=$(installer_find_artifact "antinat-agent-linux-amd64") || failed=1
        ((failed == 1)) || installer_atomic_copy "$agent" "$INSTALLER_AGENT_BINARY" 755 || failed=1
        if [[ "${ANTINAT_FAIL_MIGRATION:-0}" == 1 ]]; then
            failed=1
        fi
        if ((failed == 0)); then
            installer_systemctl daemon-reload || failed=1
            installer_systemctl start "$INSTALLER_SERVICE_NAME" || failed=1
        fi
        if ((failed == 0 && "${ANTINAT_FORCE_HEALTH_FAIL:-0}" == 1)); then
            failed=1
        fi
        if ((failed == 0)) && [[ -z "$INSTALLER_TEST_ROOT" ]] && [[ "${ANTINAT_TEST_MODE:-0}" != 1 ]]; then
            curl --fail --silent --show-error --max-time 10 http://127.0.0.1:3111/readyz >/dev/null || failed=1
        fi
    fi
    if ((failed != 0)); then
        installer_restore_snapshot "$backup" || true
        installer_systemctl start "$INSTALLER_SERVICE_NAME" || true
        rm -f -- "$lock"
        printf 'antinat installer: upgrade failed; previous version restored\n' >&2
        return "$INSTALLER_EXIT_ROLLBACK"
    fi
    rm -f -- "$lock"
    printf 'antinat installer: upgrade complete\n'
}

installer_run() {
    installer_parse_args "$@" || return $?
    case "$INSTALLER_COMMAND" in
        install) installer_install ;;
        uninstall) installer_uninstall ;;
        purge) installer_purge ;;
        upgrade) installer_upgrade ;;
    esac
}
