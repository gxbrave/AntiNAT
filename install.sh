#!/usr/bin/env bash

# Raw GitHub bootstrap. The signed release manifest remains the trust boundary;
# this file only stages the release installer and its pinned public key.
set -euo pipefail

bootstrap_usage() {
    cat <<'EOF'
AntiNAT 一键安装 / Installer
Usage: install.sh [1|2|3|controller|agent|both] [flags]
       install.sh [install|upgrade|uninstall|purge] [--role ROLE] [flags]

  1 / controller  安装主控
  2 / agent       安装 Agent
  3 / both        安装主控和 Agent
  --role ROLE     controller / agent / both（也支持 1 / 2 / 3）
  --controller-endpoint URL  主控地址
  --token-file PATH         从 0600 文件读取注册 token
  --token-fd FD             从文件描述符读取注册 token

不带参数时显示菜单；Agent token 默认通过终端隐藏输入。
其他参数透传给 Release 安装器；兼容 ANTINAT_ROLE 环境变量。
EOF
}

bootstrap_read() {
    # stdin contains the script when invoked as curl | bash. Always use the TTY.
    local tty_fd
    if ! { exec {tty_fd}<>/dev/tty; } 2>/dev/null; then
        printf 'antinat bootstrap: 需要交互终端；请提供 --role 和 --controller-endpoint（Agent）。\n' >&2
        exit 2
    fi
    printf '%s' "$1" >&"$tty_fd"
    if ! IFS= read -r REPLY <&"$tty_fd"; then
        printf 'antinat bootstrap: 输入已结束\n' >&2
        exit 2
    fi
    exec {tty_fd}>&-
}

bootstrap_role() {
    case "$1" in
        1|controller) role=controller ;;
        2|agent) role=agent ;;
        3|both) role=both ;;
        *) return 2 ;;
    esac
}

command=install
role="${ANTINAT_ROLE:-}"
args=()
endpoint_set=0
legacy_command=0
case "${1:-}" in
    --version) printf 'antinat-installer 1\n'; exit 0 ;;
    install|upgrade|uninstall|purge) command="$1"; legacy_command=1; shift ;;
    1|2|3|controller|agent|both) bootstrap_role "$1"; shift ;;
esac
while (($#)); do
    case "$1" in
        --version) printf 'antinat-installer 1\n'; exit 0 ;;
        --help|-h) bootstrap_usage; exit 0 ;;
        --role)
            (($# >= 2)) || { bootstrap_usage >&2; exit 2; }
            bootstrap_role "$2" || { bootstrap_usage >&2; exit 2; }
            shift 2 ;;
        --role=*) bootstrap_role "${1#*=}" || { bootstrap_usage >&2; exit 2; }; shift ;;
        --controller-endpoint)
            (($# >= 2)) || { bootstrap_usage >&2; exit 2; }
            endpoint_set=1; args+=("$1" "$2"); shift 2 ;;
        --controller-endpoint=*) endpoint_set=1; args+=("$1"); shift ;;
        *) args+=("$1"); shift ;;
    esac
done
# Keep the old explicit-command default (agent), including upgrades/uninstalls.
if [[ -z "$role" && "$legacy_command" == 1 ]]; then role=agent; fi
if [[ -z "$role" ]]; then
    printf 'AntiNAT 安装\n  1) 主控 Controller\n  2) Agent\n  3) 主控 + Agent\n' >&2
    while true; do
        bootstrap_read '请选择 [1/2/3]: '
        bootstrap_role "$REPLY" && break
        printf '请输入 1、2 或 3。\n' >&2
    done
fi
bootstrap_role "$role" || { bootstrap_usage >&2; exit 2; }
if [[ "$command" == install && "$role" != controller && "$endpoint_set" == 0 ]]; then
    while true; do
        bootstrap_read '请输入主控地址（例如 https://controller.example.com）: '
        [[ -n "$REPLY" ]] && break
    done
    args+=(--controller-endpoint "$REPLY")
fi
export ANTINAT_ROLE="$role"
set -- "$command" "${args[@]}"

release_version="${ANTINAT_RELEASE_VERSION:-v1.0.0-beta.1}"
release_base_url="${ANTINAT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT/releases/download/$release_version}"

[[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$ ]] || {
    printf 'antinat bootstrap: invalid release version\n' >&2
    exit 2
}
[[ "$release_base_url" != *"@"* && "$release_base_url" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$ ]] || {
    printf 'antinat bootstrap: invalid release URL\n' >&2
    exit 4
}

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/antinat-installer.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir -p -- "$tmp_dir/scripts" "$tmp_dir/deploy/trust"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$release_base_url/libinstall.sh" -o "$tmp_dir/scripts/libinstall.sh"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$release_base_url/release-ed25519.pub" -o "$tmp_dir/deploy/trust/release-ed25519.pub"
chmod 700 -- "$tmp_dir" "$tmp_dir/scripts" "$tmp_dir/deploy" "$tmp_dir/deploy/trust"
chmod 600 -- "$tmp_dir/scripts/libinstall.sh" "$tmp_dir/deploy/trust/release-ed25519.pub"

# shellcheck source=/dev/null
source "$tmp_dir/scripts/libinstall.sh"
installer_run "$@"
