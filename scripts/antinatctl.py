#!/usr/bin/env python3
"""Root-only local SSH management for installations made by install.sh.

The developer API client remains in cmd/antinatctl. This standalone manager
uses the system Argon2 library and the installed service/installer, without Go.
"""
from contextlib import closing
import ctypes
import ctypes.util
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import string
import subprocess
import sys
import tempfile
import time

PACKAGE = Path('/opt/antinat/manage')
COMMAND = Path('/usr/local/bin/antinatctl')
DATABASE = Path('/var/lib/antinat/controller.db')
MARKER = 'antinat-local-manager-v1'
FILES = ('antinatctl.py', 'libinstall.sh', 'config.json', MARKER)


def ask(prompt):
    with open('/dev/tty', 'r') as reader, open('/dev/tty', 'w') as writer:
        writer.write(prompt)
        writer.flush()
        line = reader.readline()
        if not line:
            raise EOFError('输入已取消')
        return line.strip()


def random_password():
    while True:
        value = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        if any(c.isalpha() for c in value) and any(c.isdigit() for c in value):
            return value


def argon2_library():
    name = ctypes.util.find_library('argon2')
    if not name:
        raise RuntimeError('缺少 Argon2 库，请先执行：sudo apt-get install -y libargon2-1')
    library = ctypes.CDLL(name)
    library.argon2id_hash_encoded.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
    ]
    library.argon2id_hash_encoded.restype = ctypes.c_int
    return library


def hash_password(password):
    # Matches internal/controller/auth/password.go (Argon2id v19, 64 MiB).
    library = argon2_library()
    raw, salt = password.encode('utf-8'), secrets.token_bytes(16)
    encoded = ctypes.create_string_buffer(256)
    result = library.argon2id_hash_encoded(3, 65536, 4, raw, len(raw), salt, len(salt), 32, encoded, len(encoded))
    if result != 0:
        raise RuntimeError('密码哈希生成失败，原账号未修改')
    return encoded.value.decode('ascii')


def connect(database, mode='ro'):
    return sqlite3.connect(Path(database).resolve().as_uri() + '?mode=' + mode, uri=True, timeout=15)


def reset_credentials(database, user_id, username, password_hash):
    with closing(connect(database, 'rw')) as db, db:
        db.execute('BEGIN IMMEDIATE')
        result = db.execute('''UPDATE users SET username=?, password_hash=?,
            password_algorithm='argon2id-v19', revision=revision+1, updated_at=? WHERE id=?''',
            (username, password_hash, int(time.time()), user_id))
        if result.rowcount != 1:
            raise RuntimeError('管理员已不存在，未修改数据库')
        db.execute('UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',
                   (int(time.time()), user_id))


def service_manager():
    value = json.loads((PACKAGE / 'config.json').read_text())['service_manager']
    if value not in ('systemd', 'openrc'):
        raise RuntimeError('服务管理配置无效，请重新运行安装脚本补装管理工具')
    return value


def service(action, component='controller', check=True):
    manager = service_manager()
    if manager == 'systemd':
        args = ['systemctl', action, f'antinat-{component}.service']
        if action == 'is-active':
            args.append('--quiet')
    else:
        args = ['rc-service', f'antinat-{component}', 'status' if action == 'is-active' else action]
    return subprocess.run(args, check=check, stdout=subprocess.DEVNULL if action == 'is-active' else None,
                          stderr=subprocess.DEVNULL if action == 'is-active' else None).returncode


def port():
    if service_manager() == 'systemd':
        unit = Path('/etc/systemd/system/antinat-controller.service')
    else:
        unit = Path('/etc/init.d/antinat-controller')
    match = re.search(r'-listen[ =]+[^ :"\n]+:([0-9]+)', unit.read_text())
    if not match or not 1 <= int(match[1]) <= 65535:
        raise RuntimeError('无法读取主控端口，请检查服务配置')
    return int(match[1])


def status():
    for component in ('controller', 'agent'):
        if Path(f'/opt/antinat/bin/antinat-{component}').exists():
            print(f'{component}: ' + ('运行中' if service('is-active', component, False) == 0 else '未运行'))
    print(f'本机管理页面：http://127.0.0.1:{port()}/admin')
    print(f'远程管理页面：http://主控IP或域名:{port()}/admin（HTTPS 请使用反向代理地址）')
    with closing(connect(DATABASE)) as db:
        users = db.execute('SELECT username FROM users ORDER BY created_at,id').fetchall()
    print('管理员账号：' + ('、'.join(row[0] for row in users) or '尚未创建'))
    print('原密码不可读取；忘记密码请运行 sudo antinatctl reset-admin。')


def reset_admin():
    with closing(connect(DATABASE)) as db:
        users = db.execute('SELECT id,username FROM users ORDER BY created_at,id').fetchall()
    if not users:
        raise RuntimeError('尚无管理员，请重新运行安装脚本选择 1 完成初始化')
    for index, (_, username) in enumerate(users, 1):
        print(f'{index}. {username}')
    selected = 0
    if len(users) > 1:
        value = ask('选择要重设的管理员编号: ')
        if not value.isdecimal() or not 1 <= int(value) <= len(users):
            raise ValueError('无效编号')
        selected = int(value) - 1
    user_id, old_username = users[selected]
    username = ask(f'新账号 [留空保留 {old_username}]: ') or old_username
    if not username.isprintable() or any(c.isspace() for c in username):
        raise ValueError('账号不能包含空白或控制字符')
    with open('/dev/tty', 'w') as tty:
        password = getpass.getpass('新密码 [留空随机生成 8 位字母数字]: ', stream=tty) or random_password()
    if len(password) < 8 or not password.isprintable():
        raise ValueError('密码至少 8 个字符，且不能包含控制字符')
    encoded = hash_password(password)
    was_active = service('is-active', check=False) == 0
    if was_active:
        service('stop')
    try:
        reset_credentials(DATABASE, user_id, username, encoded)
        # Print immediately after commit, even if restarting the service fails.
        print(f'管理员已更新。\n管理员账号：{username}\n管理员密码：{password}\n旧登录会话已失效，请保存新凭据。', flush=True)
    finally:
        if was_active:
            service('start')


def atomic_write(destination, data, mode):
    fd, name = tempfile.mkstemp(prefix='.antinat-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fchmod(file.fileno(), mode)
        os.replace(name, destination)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def install_manager(source, library, manager, destination=PACKAGE, command=COMMAND):
    if manager not in ('systemd', 'openrc'):
        raise ValueError('不支持的服务管理器')
    if command.is_symlink():
        if command.readlink() != destination / 'antinatctl.py':
            raise RuntimeError('antinatctl 已被其他程序使用，未覆盖')
    elif command.exists():
        raise RuntimeError('antinatctl 已被其他程序使用，未覆盖')
    if destination.is_symlink() or (destination.exists() and not (destination / MARKER).is_file()):
        raise RuntimeError('管理工具目录已被其他文件占用，未覆盖')
    destination.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(destination, 0o755)
    atomic_write(destination / MARKER, b'AntiNAT local SSH manager\n', 0o600)
    atomic_write(destination / 'antinatctl.py', Path(source).read_bytes(), 0o755)
    atomic_write(destination / 'libinstall.sh', Path(library).read_bytes(), 0o600)
    atomic_write(destination / 'config.json', json.dumps({'service_manager': manager}).encode(), 0o600)
    command.parent.mkdir(parents=True, exist_ok=True)
    if not command.is_symlink():
        command.symlink_to(destination / 'antinatctl.py')


def remove_manager(destination=PACKAGE, command=COMMAND):
    if destination.is_symlink() or not (destination / MARKER).is_file():
        raise RuntimeError('管理工具目录不属于 AntiNAT，未删除')
    if command.is_symlink() and command.readlink() == destination / 'antinatctl.py':
        command.unlink()
    for name in FILES:
        (destination / name).unlink(missing_ok=True)
    # Leave any unrelated user files alone.
    try:
        destination.rmdir()
    except OSError:
        pass


def uninstall(destination=PACKAGE, command=COMMAND):
    print('将完全卸载本机主控和 Agent，并删除所属配置、数据库和密钥。请先备份。')
    if ask('输入 DELETE 确认卸载，其他输入取消: ') != 'DELETE':
        print('已取消卸载。')
        return False
    if not (destination / MARKER).is_file() or not (destination / 'libinstall.sh').is_file():
        raise RuntimeError('本地卸载组件缺失，请重新运行安装脚本补装管理工具')
    env = {key: value for key, value in os.environ.items() if not key.startswith('ANTINAT_')}
    env.update(ANTINAT_ROLE='both', ANTINAT_FORCE_OFFLINE_PURGE='1')
    result = subprocess.run(['bash', '-c', 'set -euo pipefail; source "$1"; installer_run purge',
                             'antinatctl', str(destination / 'libinstall.sh')], env=env)
    if result.returncode not in (0, 7):
        raise RuntimeError('卸载未完成，管理命令已保留，请检查上方错误后重试')
    remove_manager(destination, command)
    try:
        destination.parent.rmdir()
    except OSError:
        pass
    print('卸载完成，antinatctl 管理入口已移除。')
    return True


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if args in (['--help'], ['-h'], ['help']):
        print('AntiNAT SSH 管理：sudo antinatctl [status|reset-admin|restart|upgrade|uninstall]\n不带参数打开菜单。升级暂未开放。')
        return 0
    if os.geteuid() != 0:
        raise PermissionError('请使用 sudo antinatctl，或以 root 运行')
    if args == ['--check']:
        argon2_library()
        return 0
    if len(args) == 3 and args[0] == '--install':
        install_manager(Path(__file__), Path(args[1]), args[2])
        return 0
    if args == ['--remove-manager']:
        remove_manager()
        return 0
    actions = {'status': status, 'reset-admin': reset_admin, 'restart': lambda: service('restart'),
               'upgrade': lambda: print('升级功能暂未开放；当前不会下载或修改任何文件。'), 'uninstall': uninstall}
    if args:
        if len(args) != 1 or args[0] not in actions:
            raise ValueError('未知命令，请运行 antinatctl --help')
        actions[args[0]]()
        return 0
    choices = {'1': 'status', '2': 'reset-admin', '3': 'restart', '4': 'upgrade', '5': 'uninstall'}
    while True:
        print('\nAntiNAT 管理\n  1. 查看状态、访问地址和管理员账号\n  2. 重设管理员账号/密码\n  3. 重启主控\n  4. 升级（暂未开放）\n  5. 完全卸载\n  0. 退出')
        choice = ask('请选择: ')
        if choice == '0':
            return 0
        if choice not in choices:
            print('请输入 0–5。')
            continue
        result = actions[choices[choice]]()
        if choice == '5' and result:
            return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError, EOFError) as error:
        print(f'antinatctl: {error}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\n已取消。', file=sys.stderr)
        sys.exit(130)
