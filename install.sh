#!/usr/bin/env bash
# Controller entry point. Agent enrollment is always issued by the Controller.
set -euo pipefail
umask 077

bootstrap_usage() {
    cat <<'EOF'
AntiNAT 一键安装
Usage: install.sh [1|2|3] [--port PORT]
  1 / controller  仅安装主控
  2 / both        安装主控 + 本地 Agent
  3 / purge       完全卸载本机主控、Agent 及其配置和数据
  --port PORT     主控监听端口，默认 3111

不带选项时进入菜单。主控 + Agent 自动注册本地节点，无需公网地址或 token。
远程 Agent 请使用主控页面生成的 AntiNAT-Agent 安装命令。
EOF
}

bootstrap_fail() { printf 'antinat: %s\n' "$*" >&2; exit 2; }
bootstrap_read() {
    local tty_fd
    if ! { exec {tty_fd}<>/dev/tty; } 2>/dev/null; then
        bootstrap_fail '没有交互终端，请直接指定 1/2/3 和 --port。'
    fi
    printf '%s' "$1" >&"$tty_fd"
    IFS= read -r REPLY <&"$tty_fd" || bootstrap_fail '输入已结束。'
    exec {tty_fd}>&-
}
bootstrap_choice() {
    case "$1" in
        1|controller) choice=1 ;;
        2|both) choice=2 ;;
        3|purge) choice=3 ;;
        *) return 2 ;;
    esac
}
bootstrap_valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}
choice=''
port=''
interactive=0
while (($#)); do
    case "$1" in
        --help|-h) bootstrap_usage; exit 0 ;;
        --port)
            (($# >= 2)) || bootstrap_fail '--port 缺少值。'
            port="$2"; shift 2 ;;
        --port=*) port="${1#*=}"; shift ;;
        *)
            [[ -z "$choice" ]] && bootstrap_choice "$1" || bootstrap_fail "不支持的选项：$1"
            shift ;;
    esac
done
[[ -z "$port" ]] || bootstrap_valid_port "$port" || bootstrap_fail '端口必须为 1–65535。'
if [[ -z "$choice" ]]; then
    interactive=1
    printf 'AntiNAT\n  1. 仅安装主控\n  2. 安装主控 + Agent\n  3. 完全卸载（删除本机配置和数据）\n' >&2
    while true; do
        bootstrap_read '请选择 [1/2/3]: '
        bootstrap_choice "$REPLY" && break
        printf '请输入 1、2 或 3。\n' >&2
    done
fi
if [[ "$choice" != 3 && -z "$port" && "$interactive" == 1 ]]; then
    while true; do
        bootstrap_read '主控端口 [3111]: '
        port="${REPLY:-3111}"
        bootstrap_valid_port "$port" && break
        printf '端口必须为 1–65535。\n' >&2
    done
fi
port="${port:-3111}"
export ANTINAT_CONTROLLER_PORT="$((10#$port))"
((EUID == 0)) || bootstrap_fail '请以 root 运行（curl ... | sudo bash）。'
for dependency in curl python3 jq; do
    command -v "$dependency" >/dev/null || bootstrap_fail "请先安装依赖：$dependency"
done

release_version="${ANTINAT_RELEASE_VERSION:-v1.0.0-beta.2}"
release_base_url="${ANTINAT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT/releases/download/$release_version}"
[[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$ ]] || bootstrap_fail 'invalid release version'
[[ "$release_base_url" != *"@"* && "$release_base_url" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$ ]] || bootstrap_fail 'invalid release URL'
export ANTINAT_RELEASE_BASE_URL="$release_base_url"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/antinat-installer.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir -p -- "$tmp_dir/scripts" "$tmp_dir/deploy/trust"
bootstrap_download() {
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$1" -o "$2"
}
bootstrap_download "$release_base_url/libinstall.sh" "$tmp_dir/scripts/libinstall.sh"
bootstrap_download "$release_base_url/release-ed25519.pub" "$tmp_dir/deploy/trust/release-ed25519.pub"

if [[ "$choice" == 3 ]]; then
    # Both local components are being removed, including the Controller's DB.
    export ANTINAT_ROLE=both ANTINAT_FORCE_OFFLINE_PURGE=1
else
    export ANTINAT_ROLE=controller
fi
# shellcheck source=/dev/null
source "$tmp_dir/scripts/libinstall.sh"
if [[ "$choice" == 3 ]]; then
    # The lower-level contract uses exit 7 for a completed terminal purge.
    set +e
    (set -e; installer_run purge)
    purge_status=$?
    set -e
    [[ "$purge_status" != 7 ]] || exit 0
    exit "$purge_status"
fi
installer_init_paths
if [[ -x "$INSTALLER_CONTROLLER_BINARY" ]]; then
    unit="$INSTALLER_CONTROLLER_UNIT"
    [[ -r "$unit" ]] || unit="$INSTALLER_OPENRC_DIR/antinat-controller"
    [[ -r "$unit" ]] || bootstrap_fail '已有主控但找不到服务配置，请检查安装状态。'
    installed_port=$(sed -nE 's/.*-listen[ =]+[^ :"]+:([0-9]+).*/\1/p' "$unit")
    bootstrap_valid_port "$installed_port" || bootstrap_fail '无法读取已有主控的监听端口。'
    export ANTINAT_CONTROLLER_PORT="$((10#$installed_port))"
    printf '使用已有主控，端口 %s。\n' "$ANTINAT_CONTROLLER_PORT"
else
    installer_run install
fi
endpoint="http://127.0.0.1:$ANTINAT_CONTROLLER_PORT"
if [[ "$choice" == 2 ]]; then
    # Readiness precedes provisioning; the running Controller sees the committed node.
    ready=0
    for ((attempt=0; attempt<30; attempt++)); do
        if curl --fail --silent --show-error --max-time 2 "$endpoint/readyz" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 1
    done
    [[ "$ready" == 1 ]] || { printf '主控未就绪；主控已保留，请检查服务后重试。\n' >&2; exit 1; }
    "$INSTALLER_CONTROLLER_BINARY" provision-local-agent \
        --store "$INSTALLER_DATA_DIR/controller.db" \
        --keydir "$INSTALLER_CONTROLLER_KEY_DIR" --endpoint "$endpoint" \
        --install-dir "$INSTALLER_INSTALL_DIR" >"$tmp_dir/local-agent.json"
    if [[ "$(jq -r '.already_enrolled // false' "$tmp_dir/local-agent.json")" == true ]]; then
        if [[ ! -x "$INSTALLER_AGENT_BINARY" || ! -s "$INSTALLER_CONFIG" || ! -s "$INSTALLER_DATA_DIR/node.key" ]]; then
            printf '本地节点已注册，但本机 Agent 文件不完整。请在主控中恢复该节点及其凭据后重试；不会覆盖已注册身份。\n' >&2
            exit 1
        fi
        if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
            systemctl is-active --quiet antinat-agent.service || {
                printf '本地 Agent 已注册但服务未运行，请检查 antinat-agent.service。\n' >&2; exit 1;
            }
        else
            rc-service antinat-agent status >/dev/null || {
                printf '本地 Agent 已注册但服务未运行，请检查 antinat-agent。\n' >&2; exit 1;
            }
        fi
    else
        # Execute the structured form of the Controller-generated command, without eval.
        python3 - "$tmp_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
data = json.loads((root / 'local-agent.json').read_text())
expected = 'https://raw.githubusercontent.com/gxbrave/AntiNAT-Agent/main/install.sh'
if data['installer_url'] != expected:
    raise SystemExit('unexpected Agent installer URL')
args = data['install_argv']
if not isinstance(args, list) or not all(isinstance(a, str) and '\0' not in a for a in args):
    raise SystemExit('invalid Agent installer arguments')
(root / 'token').write_text(data['enrollment_token'])
(root / 'args').write_bytes(b''.join(a.encode() + b'\0' for a in args))
PY
        bootstrap_download "$(jq -r '.installer_url' "$tmp_dir/local-agent.json")" "$tmp_dir/agent-install.sh"
        mapfile -d '' -t agent_args <"$tmp_dir/args"
        ANTINAT_NODE_ID="$(jq -r '.node_id' "$tmp_dir/local-agent.json")" \
        ANTINAT_CONTROLLER_PIN="$(jq -r '.controller_pin' "$tmp_dir/local-agent.json")" \
        ANTINAT_AGENT_RELEASE_VERSION="$release_version" \
        ANTINAT_AGENT_RELEASE_BASE_URL="${ANTINAT_AGENT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT-Agent/releases/download/$release_version}" \
            bash "$tmp_dir/agent-install.sh" install "${agent_args[@]}" --token-file "$tmp_dir/token"
    fi
fi
printf '安装完成。主控端口：%s；本机访问：%s\n' "$ANTINAT_CONTROLLER_PORT" "$endpoint"
