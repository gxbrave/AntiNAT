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

不带选项时进入菜单，并设置管理员账号和密码（留空分别随机生成 8 位字母数字）。
直接指定 1/2 时，新管理员账号和密码自动随机生成。已有管理员不会被覆盖。
主控 + Agent 自动注册本地节点，无需公网地址或 token。
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

download_mirror="${ANTINAT_DOWNLOAD_MIRROR:-}"
download_mirror="${download_mirror%/}"
[[ -z "$download_mirror" || ( "$download_mirror" != *"@"* && "$download_mirror" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$ ) ]] || bootstrap_fail 'invalid download mirror URL'
bootstrap_mirror_url() {
    case "$1" in
        https://github.com/*|https://raw.githubusercontent.com/*)
            printf '%s%s\n' "${download_mirror:+$download_mirror/}" "$1" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

release_version="${ANTINAT_RELEASE_VERSION:-v1.0.0-beta.2}"
release_base_url="${ANTINAT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT/releases/download/$release_version}"
[[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$ ]] || bootstrap_fail 'invalid release version'
[[ "$release_base_url" != *"@"* && "$release_base_url" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$ ]] || bootstrap_fail 'invalid release URL'
release_base_url=$(bootstrap_mirror_url "$release_base_url")
export ANTINAT_RELEASE_BASE_URL="$release_base_url"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/antinat-installer.XXXXXX")
admin_created=0
bootstrap_admin_summary() {
    printf '管理员账号：%s\n' "$(jq -r '.username' "$tmp_dir/admin.json")"
    printf '管理员密码：%s\n' "$(jq -r '.password' "$tmp_dir/admin.json")"
    printf '请妥善保存以上登录信息。\n'
}
bootstrap_cleanup() {
    local status=$?
    if [[ "$status" != 0 && "$admin_created" == 1 ]]; then
        printf '安装未全部完成，但主控管理员已创建；请保存凭据后排查重试。\n' >&2
        printf '本机管理地址：%s/admin\n' "$endpoint"
        bootstrap_admin_summary
    fi
    rm -rf -- "$tmp_dir"
}
trap bootstrap_cleanup EXIT
mkdir -p -- "$tmp_dir/scripts" "$tmp_dir/deploy/trust"
bootstrap_download() {
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$(bootstrap_mirror_url "$1")" -o "$2"
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
# Read only the existing account count; never reset or recover stored passwords.
python3 - "$INSTALLER_DATA_DIR/controller.db" "$tmp_dir/admin.json" "$interactive" <<'PY'
import getpass
import json
import os
from pathlib import Path
import secrets
import sqlite3
import string
import sys

database, output, interactive = sys.argv[1:]
if Path(database).exists():
    try:
        with sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True) as db:
            exists = db.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0
    except sqlite3.Error:
        raise SystemExit('无法检查已有管理员；请检查主控数据库后重试。')
    if exists:
        print('已有管理员，保留原账号和密码。')
        sys.exit(0)

def random_credential():
    alphabet = string.ascii_letters + string.digits
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(8))
        if any(c.isalpha() for c in value) and any(c.isdigit() for c in value):
            return value

def printable(value):
    return all(c.isprintable() for c in value)

username = password = ''
if interactive == '1':
    try:
        with open('/dev/tty', 'r') as tty_input, open('/dev/tty', 'w') as tty:
            while True:
                tty.write('管理员账号 [留空随机生成 8 位字母数字]: ')
                tty.flush()
                line = tty_input.readline()
                if not line:
                    raise EOFError
                username = line.strip()
                if printable(username) and not any(c.isspace() for c in username):
                    break
                tty.write('账号不能包含空白或控制字符。\n')
            while True:
                password = getpass.getpass('管理员密码 [留空随机生成 8 位字母数字]: ', stream=tty)
                if not password or (len(password) >= 8 and printable(password)):
                    break
                tty.write('密码至少 8 个字符，且不能包含控制字符。\n')
    except (OSError, EOFError, KeyboardInterrupt):
        raise SystemExit('管理员输入已取消，未开始安装。')

credentials = {'username': username or random_credential(), 'password': password or random_credential()}
with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as file:
    json.dump(credentials, file)
PY
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
# Both installation modes need a ready Controller before administrator setup.
ready=0
for ((attempt=0; attempt<30; attempt++)); do
    if curl --noproxy '*' --fail --silent --show-error --max-time 2 "$endpoint/readyz" >/dev/null 2>&1; then
        ready=1; break
    fi
    sleep 1
done
[[ "$ready" == 1 ]] || { printf '主控未就绪；主控已保留，请检查服务后重试。\n' >&2; exit 1; }
if [[ -f "$tmp_dir/admin.json" ]]; then
    # Keep credentials out of argv and the environment. Only send them to loopback.
    admin_status=$(curl --noproxy '*' --silent --show-error --max-time 30 \
        -H 'Content-Type: application/json' --data-binary "@$tmp_dir/admin.json" \
        -o "$tmp_dir/admin-response.json" --write-out '%{http_code}' "$endpoint/api/v1/auth/init") || \
        bootstrap_fail '管理员初始化请求失败；请检查主控后重试。'
    if [[ "$admin_status" == 201 ]] && jq -e '.created == true' "$tmp_dir/admin-response.json" >/dev/null; then
        admin_created=1
    elif [[ "$admin_status" == 401 || "$admin_status" == 409 ]]; then
        bootstrap_fail '管理员已被其他操作创建；本次输入的账号密码未生效，请使用已有账号登录。'
    else
        bootstrap_fail "管理员初始化失败（HTTP $admin_status）；未完成安装。"
    fi
fi
if [[ "$choice" == 2 ]]; then
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
        ANTINAT_AGENT_RELEASE_BASE_URL="$(bootstrap_mirror_url "${ANTINAT_AGENT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT-Agent/releases/download/$release_version}")" \
            bash "$tmp_dir/agent-install.sh" install "${agent_args[@]}" --token-file "$tmp_dir/token"
    fi
fi
printf '安装完成。主控端口：%s\n本机管理地址：%s/admin\n' "$ANTINAT_CONTROLLER_PORT" "$endpoint"
python3 - "$ANTINAT_CONTROLLER_PORT" <<'PY'
import ipaddress
import subprocess
import sys
try:
    addresses = subprocess.check_output(['hostname', '-I'], text=True, stderr=subprocess.DEVNULL).split()
except (OSError, subprocess.CalledProcessError):
    addresses = []
for address in dict.fromkeys(addresses):
    ip = ipaddress.ip_address(address)
    if ip.version == 4 and not ip.is_loopback:
        print(f'主机管理地址：http://{ip}:{sys.argv[1]}/admin')
print('远程访问请使用主控可达的 IP 或域名，并放行所选端口；内网地址不等于公网地址。')
PY
if [[ "$admin_created" == 1 ]]; then
    bootstrap_admin_summary
else
    printf '管理员：沿用已有账号和密码（不会重置或显示原密码）。\n'
fi
