# 首次创建管理员 / First administrator setup

当前一键安装不会自动创建管理员，也没有默认账号密码。请在主控机器上执行下面的命令，使用安装时已经准备好的 Python 3，不需要安装 Go。Docker 用户在主机上运行即可（需要 Python 3）。

The installer does not create an administrator or a default password. Run the command below on the Controller host using Python 3; Go is not needed. Docker users can run it on the host with Python 3 installed.

首次初始化接口只在没有管理员时允许创建账号。初始化完成前，请用防火墙限制主控管理端口，避免其他人抢先创建账号。已有账号时不要重复执行；该步骤不能重置密码。

Restrict access to the Controller port until setup is complete: the first administrator can be created without authentication while the database has no administrator. This command cannot reset an existing account's password.

命令会询问主控端口、用户名和密码。密码至少 8 个字符，输入时不显示，也不会写进命令行历史。随后在浏览器打开 `http://主控IP:端口/admin`，用该账号登录。远程使用请配置 HTTPS。

The command asks for the Controller port, username and a password of at least 8 characters. Password input is hidden and stays out of shell history. Then open `http://CONTROLLER_IP:PORT/admin` and sign in. Configure HTTPS for remote use.

```bash
python3 - <<'PY'
import getpass
import json
import urllib.error
import urllib.request

with open('/dev/tty', 'r+') as tty:
    def ask(prompt, default):
        tty.write(prompt)
        tty.flush()
        return tty.readline().strip() or default

    port = ask('Controller port [3111]: ', '3111')
    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise SystemExit('Invalid port')
    username = ask('Username [admin]: ', 'admin')
    password = getpass.getpass('Password (at least 8 characters): ', stream=tty)
    if len(password) < 8:
        raise SystemExit('Password is too short')
    if password != getpass.getpass('Repeat password: ', stream=tty):
        raise SystemExit('Passwords do not match')

request = urllib.request.Request(
    f'http://127.0.0.1:{port}/api/v1/auth/init',
    data=json.dumps({'username': username, 'password': password}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST',
)
# Keep this local request off any proxy configured in the environment.
client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with client.open(request, timeout=15) as response:
        print('Administrator created. Sign in at /admin.')
except urllib.error.HTTPError as error:
    raise SystemExit(f'Setup failed (HTTP {error.code}). An administrator may already exist.')
except urllib.error.URLError:
    raise SystemExit('Cannot connect. Check the Controller service and port.')
PY
```

如果已自行编译 `antinatctl`，也可以用它创建管理员（无需再执行上面的命令）。该命令会生成并显示一次随机密码，请妥善保存：

If you have built `antinatctl`, you can use it instead. It generates and displays a random password once; save it securely:

```bash
./bin/antinatctl --endpoint http://127.0.0.1:3111 admin init --username admin
```
