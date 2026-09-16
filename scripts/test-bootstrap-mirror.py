#!/usr/bin/env python3
"""Exercise bootstrap downloads without installing services or accessing the network."""
import json
import os
import pty
import select
import signal
import sqlite3
import time
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class BootstrapMirrorTest(unittest.TestCase):
    def run_bootstrap(self, mirror, choice='2', overrides=None, prompts=None, expected_code=0, existing_admin=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            curl = root / 'curl'
            curl.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://') or a.startswith('http://'))
with open(os.environ['DOWNLOAD_LOG'], 'a') as log: log.write(url + '\\n')
if url.endswith('/api/v1/auth/init'):
    payload = pathlib.Path(args[args.index('--data-binary') + 1][1:])
    assert payload.stat().st_mode & 0o777 == 0o600
    pathlib.Path(os.environ['ADMIN_LOG']).write_text(payload.read_text())
    pathlib.Path(args[args.index('-o') + 1]).write_text('{"created": true}')
    print(os.environ.get('ADMIN_STATUS', '201'), end='')
    sys.exit(0)
if '-o' not in args: sys.exit(0)
out = pathlib.Path(args[args.index('-o') + 1])
if url.endswith('/libinstall.sh'):
    out.write_text(''' + repr('''installer_init_paths() {
    INSTALLER_CONTROLLER_BINARY="$TEST_SCRATCH/controller"
    INSTALLER_DATA_DIR="$TEST_SCRATCH/data"
    INSTALLER_CONTROLLER_KEY_DIR="$TEST_SCRATCH/keys"
    INSTALLER_INSTALL_DIR="$TEST_SCRATCH/bin"
    INSTALLER_CONTROLLER_UNIT="$TEST_SCRATCH/controller.service"
}
installer_run() {
    chmod +x "$TEST_SCRATCH/controller"
    printf '%s\\n' "$ANTINAT_RELEASE_BASE_URL" >> "$BASE_LOG"
}
''') + ''')
elif url.endswith('/install.sh') and os.environ.get('AGENT_FAIL') == '1':
    out.write_text('exit 17')
elif url.endswith('/install.sh'):
    out.write_text('printf "%s\\\\n" "$ANTINAT_AGENT_RELEASE_BASE_URL" >> "$BASE_LOG"\\n')
else: out.write_text('test fixture')
''')
            curl.chmod(0o755)
            controller = root / 'controller'
            controller.write_text('#!/bin/sh\ncat <<\'EOF\'\n' + json.dumps({
                'installer_url': 'https://raw.githubusercontent.com/gxbrave/AntiNAT-Agent/main/install.sh',
                'install_argv': ['--controller-endpoint', 'http://127.0.0.1:3111'],
                'enrollment_token': 'fixture', 'node_id': 'fixture', 'controller_pin': 'a' * 64,
            }) + '\nEOF\n')
            if existing_admin:
                controller.chmod(0o755)
                (root / 'controller.service').write_text('ExecStart=controller -listen 0.0.0.0:48221\n')
                (root / 'data').mkdir()
                with sqlite3.connect(root / 'data/controller.db') as db:
                    db.execute('CREATE TABLE users (username TEXT)')
                    db.execute("INSERT INTO users VALUES ('original')")
            # Bootstrap must see a fresh Controller, then invoke the fixture after installation.
            env = {k: v for k, v in os.environ.items() if not k.startswith('ANTINAT_')}
            env.update(PATH=f'{root}:{env["PATH"]}', TEST_SCRATCH=tmp, TMPDIR=tmp,
                       DOWNLOAD_LOG=str(root / 'downloads'), BASE_LOG=str(root / 'bases'),
                       ADMIN_LOG=str(root / 'admin'),
                       ANTINAT_DOWNLOAD_MIRROR=mirror)
            env.update(overrides or {})
            if prompts is None:
                result = subprocess.run(['bash', str(REPO / 'install.sh'), choice], env=env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, expected_code, result.stderr)
                self.last_output = result.stdout
            else:
                pid, fd = pty.fork()
                if pid == 0:
                    os.execvpe('bash', ['bash', str(REPO / 'install.sh')], env)
                output = b''
                next_prompt = 0
                cursor = 0
                deadline = time.monotonic() + 15
                try:
                    while time.monotonic() < deadline:
                        if select.select([fd], [], [], .1)[0]:
                            try:
                                chunk = os.read(fd, 65536)
                            except OSError:
                                break
                            if not chunk:
                                break
                            output += chunk
                            if next_prompt < len(prompts):
                                prompt, answer = prompts[next_prompt]
                                found = output.find(prompt.encode(), cursor)
                                if found >= 0:
                                    os.write(fd, (answer + '\n').encode())
                                    cursor = found + len(prompt.encode())
                                    next_prompt += 1
                    else:
                        self.fail('interactive bootstrap timed out')
                    _, status = os.waitpid(pid, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(status), expected_code, output.decode())
                    self.assertEqual(next_prompt, len(prompts), output.decode())
                    self.last_output = output.decode()
                finally:
                    os.close(fd)
                    try:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                    except (ProcessLookupError, ChildProcessError):
                        pass
            self.assertEqual(list(root.glob('antinat-installer.*')), [], 'temporary credentials must be removed')
            self.last_admin = json.loads((root / 'admin').read_text()) if (root / 'admin').exists() else None
            return [u for u in (root / 'downloads').read_text().splitlines() if not u.startswith('http://127.0.0.1:')], ((root / 'bases').read_text().splitlines() if (root / 'bases').exists() else [])

    def test_mirror_controller_and_agent(self):
        urls, bases = self.run_bootstrap('https://ghfast.top/')
        downloads = [u for u in urls if not u.startswith('http://127.0.0.1:')]
        self.assertEqual(len(downloads), 3)
        self.assertTrue(all(u.startswith('https://ghfast.top/https://') for u in downloads), downloads)
        self.assertEqual(bases, [f'https://ghfast.top/https://github.com/gxbrave/{repo}/releases/download/v1.0.0-beta.2' for repo in ['AntiNAT', 'AntiNAT-Agent']])

    def test_generated_admin_and_summary(self):
        self.run_bootstrap('', '1')
        self.assertIsNotNone(self.last_admin)
        for key in ('username', 'password'):
            value = self.last_admin[key]
            self.assertRegex(value, r'^[A-Za-z0-9]{8}$')
            self.assertRegex(value, r'[A-Za-z]')
            self.assertRegex(value, r'[0-9]')
            self.assertIn(value, self.last_output)
        self.assertIn('http://127.0.0.1:3111/admin', self.last_output)

    def test_interactive_custom_admin(self):
        self.run_bootstrap('', prompts=[
            ('请选择 [1/2/3]: ', '1'),
            ('主控端口 [3111]: ', '48221'),
            ('管理员账号 [留空随机生成 8 位字母数字]: ', 'myadmin'),
            ('管理员密码 [留空随机生成 8 位字母数字]: ', 'short'),
            ('管理员密码 [留空随机生成 8 位字母数字]: ', 'Pass"word123'),
        ])
        self.assertEqual(self.last_admin, {'username': 'myadmin', 'password': 'Pass"word123'})
        self.assertIn('http://127.0.0.1:48221/admin', self.last_output)
        self.assertNotIn('Pass"word123', self.last_output.split('安装完成。')[0])
        self.assertIn('Pass"word123', self.last_output)

    def test_interactive_blank_defaults(self):
        self.run_bootstrap('', prompts=[
            ('请选择 [1/2/3]: ', '2'),
            ('主控端口 [3111]: ', ''),
            ('管理员账号 [留空随机生成 8 位字母数字]: ', ''),
            ('管理员密码 [留空随机生成 8 位字母数字]: ', ''),
        ])
        for value in self.last_admin.values():
            self.assertRegex(value, r'^[A-Za-z0-9]{8}$')
            self.assertRegex(value, r'[A-Za-z]')
            self.assertRegex(value, r'[0-9]')
            self.assertIn(value, self.last_output)
        self.assertIn('http://127.0.0.1:3111/admin', self.last_output)

    def test_existing_admin_preserved(self):
        self.run_bootstrap('', '1', existing_admin=True)
        self.assertIsNone(self.last_admin)
        self.assertIn('沿用已有账号和密码', self.last_output)
        self.assertIn('http://127.0.0.1:48221/admin', self.last_output)
        self.assertNotIn('管理员密码：', self.last_output)

    def test_admin_api_failure_is_not_success(self):
        self.run_bootstrap('', '1', {'ADMIN_STATUS': '500'}, expected_code=2)
        self.assertNotIn('安装完成。', self.last_output)
        self.assertNotIn('管理员密码：', self.last_output)

    def test_admin_race_is_not_success(self):
        self.run_bootstrap('', '1', {'ADMIN_STATUS': '401'}, expected_code=2)
        self.assertNotIn('安装完成。', self.last_output)
        self.assertNotIn('管理员密码：', self.last_output)

    def test_agent_failure_preserves_created_credentials(self):
        self.run_bootstrap('', '2', {'AGENT_FAIL': '1'}, expected_code=17)
        self.assertNotIn('安装完成。', self.last_output)
        self.assertIn(self.last_admin['username'], self.last_output)
        self.assertIn(self.last_admin['password'], self.last_output)

    def test_purge_skips_admin(self):
        self.run_bootstrap('', '3')
        self.assertIsNone(self.last_admin)
        self.assertNotIn('管理员密码：', self.last_output)

    def test_direct_controller(self):
        urls, bases = self.run_bootstrap('', '1')
        self.assertTrue(all(u.startswith('https://github.com/') for u in urls), urls)
        self.assertEqual(bases, ['https://github.com/gxbrave/AntiNAT/releases/download/v1.0.0-beta.2'])

    def test_existing_mirror_not_prefixed_twice(self):
        base = 'https://ghfast.top/https://github.com/gxbrave/AntiNAT/releases/download/v1.0.0-beta.2'
        urls, bases = self.run_bootstrap('https://ghfast.top', '1', {'ANTINAT_RELEASE_BASE_URL': base})
        self.assertEqual(bases, [base])
        self.assertEqual(urls, [base + '/libinstall.sh', base + '/release-ed25519.pub'])


if __name__ == '__main__':
    unittest.main()
