#!/usr/bin/env python3
"""Exercise the streamed installer with fake releases and a real controlling TTY."""
import json
import os
import pathlib
import pty
import select
import signal
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class BootstrapTest(unittest.TestCase):
    def run_bootstrap(self, args, answer=None, existing=False, enrolled=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)
            library = path / 'library'
            library.write_text('''installer_init_paths() {
    INSTALLER_CONTROLLER_BINARY="$FIXTURE_DIR/not-installed"
    INSTALLER_CONTROLLER_UNIT="$FIXTURE_DIR/controller.service"
    INSTALLER_OPENRC_DIR="$FIXTURE_DIR/openrc"
    INSTALLER_DATA_DIR="$FIXTURE_DIR/data"
    INSTALLER_CONTROLLER_KEY_DIR="$FIXTURE_DIR/keys"
    INSTALLER_INSTALL_DIR=/opt/antinat
    INSTALLER_AGENT_BINARY="$FIXTURE_DIR/missing-agent"
    INSTALLER_CONFIG="$FIXTURE_DIR/agent.conf"
    if [[ "$FIXTURE_EXISTING" == 1 ]]; then INSTALLER_CONTROLLER_BINARY="$FIXTURE_DIR/controller"; fi
}
installer_run() {
    printf 'RUN:%s:%s:PORT=%s\\n' "$ANTINAT_ROLE" "$1" "${ANTINAT_CONTROLLER_PORT:-}"
    INSTALLER_CONTROLLER_BINARY="$FIXTURE_DIR/controller"
    INSTALLER_DATA_DIR="$FIXTURE_DIR/data"
    INSTALLER_CONTROLLER_KEY_DIR="$FIXTURE_DIR/keys"
    INSTALLER_INSTALL_DIR=/opt/antinat
    [[ "$1" != purge ]] || return 7
}
''')
            ctl = path / 'controller'
            ctl.write_text('''#!/usr/bin/env python3
import json, sys, os
endpoint = sys.argv[sys.argv.index('--endpoint') + 1]
if os.environ['FIXTURE_ENROLLED'] == '1':
    print(json.dumps(dict(node_id='local-agent', already_enrolled=True)))
    sys.exit(0)
print(json.dumps(dict(node_id='local-agent', controller_pin='ab'*32, enrollment_token='private-token', installer_url='https://raw.githubusercontent.com/gxbrave/AntiNAT-Agent/main/install.sh', install_command='unused', install_argv=['--controller-endpoint',endpoint])))
''')
            ctl.chmod(0o755)
            (path / 'controller.service').write_text('ExecStart=controller -listen 0.0.0.0:5678 -store db\n')
            curl = path / 'curl'
            curl.write_text('''#!/usr/bin/env python3
import sys, pathlib, os
if '-o' not in sys.argv:
    sys.exit(0)
out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
if out.name == 'libinstall.sh':
    out.write_text((pathlib.Path(os.environ['FIXTURE_DIR'])/'library').read_text())
elif out.name == 'agent-install.sh':
    out.write_text(''' + repr('''#!/usr/bin/env bash
set -eu
[[ "$ANTINAT_NODE_ID" == local-agent && "$ANTINAT_CONTROLLER_PIN" == abababababababababababababababababababababababababababababababab ]]
[[ "$1" == install ]]; shift
while (($#)); do
 case "$1" in
 --token-file) [[ "$(stat -c %a "$2")" == 600 && "$(cat "$2")" == private-token ]]; shift 2 ;;
 --controller-endpoint) printf 'AGENT:%s\\n' "$2"; shift 2 ;;
 *) exit 88 ;;
 esac
done
''') + ''')
else:
    out.write_text('test key')
''')
            curl.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if not k.startswith('ANTINAT_')}
            env.update(PATH=tmp + ':' + env['PATH'], FIXTURE_DIR=tmp, FIXTURE_EXISTING='1' if existing else '0', FIXTURE_ENROLLED='1' if enrolled else '0')
            command = ['bash', '-c', 'cat "$1" | bash -s -- "${@:2}"', 'test', str(ROOT / 'install.sh'), *args]
            if answer is None:
                result = subprocess.run(command, env=env, capture_output=True, text=True, start_new_session=True, timeout=10)
                return result.returncode, result.stdout + result.stderr
            pid, fd = pty.fork()
            if pid == 0:
                os.execvpe(command[0], command, env)
            os.write(fd, answer.encode())
            output = b''
            try:
                while True:
                    if not select.select([fd], [], [], 10)[0]:
                        os.kill(pid, signal.SIGKILL)
                        self.fail('TTY installer timed out: ' + output.decode())
                    data = os.read(fd, 4096)
                    if not data:
                        break
                    output += data
            except OSError:
                pass
            finally:
                os.close(fd)
                _, status = os.waitpid(pid, 0)
            return os.waitstatus_to_exitcode(status), output.decode()

    def test_controller(self):
        code, out = self.run_bootstrap(['1', '--port', '4567'])
        self.assertEqual(code, 0, out)
        self.assertIn('RUN:controller:install:PORT=4567', out)
        self.assertNotIn('AGENT:', out)

    def test_local_agent_without_public_address(self):
        code, out = self.run_bootstrap(['2', '--port', '4567'])
        self.assertEqual(code, 0, out)
        self.assertIn('RUN:controller:install:PORT=4567', out)
        self.assertIn('AGENT:http://127.0.0.1:4567', out)
        self.assertNotIn('private-token', out)

    def test_existing_controller_adds_local_agent_on_actual_port(self):
        code, out = self.run_bootstrap(['2'], existing=True)
        self.assertEqual(code, 0, out)
        self.assertNotIn('RUN:controller:install', out)
        self.assertIn('AGENT:http://127.0.0.1:5678', out)

    def test_purge(self):
        code, out = self.run_bootstrap(['3'])
        self.assertEqual(code, 0, out)
        self.assertIn('RUN:both:purge:', out)
        self.assertNotIn('AGENT:', out)

    def test_enrolled_but_missing_agent_does_not_report_success(self):
        code, out = self.run_bootstrap(['2'], existing=True, enrolled=True)
        self.assertEqual(code, 1, out)
        self.assertIn('Agent 文件不完整', out)
        self.assertNotIn('安装完成', out)

    def test_pipe_menu_and_port(self):
        code, out = self.run_bootstrap([], '9\n2\n4567\n')
        self.assertEqual(code, 0, out)
        self.assertIn('AGENT:http://127.0.0.1:4567', out)
        self.assertIn('完全卸载', out)

    def test_default_port(self):
        code, out = self.run_bootstrap([], '1\n\n')
        self.assertEqual(code, 0, out)
        self.assertIn('PORT=3111', out)

    def test_reject_agent_and_invalid_arguments(self):
        for args in [['agent'], ['1', '--port', '0'], ['1', '--port', '65536'], ['1', '--port', 'x'], ['2', '--controller-endpoint', 'https://example.com'], ['1', '--platform', 'docker']]:
            code, out = self.run_bootstrap(args)
            self.assertEqual(code, 2, out)
            self.assertNotIn('RUN:', out)

    def test_no_terminal(self):
        code, out = self.run_bootstrap([])
        self.assertEqual(code, 2, out)

    def test_help(self):
        code, out = self.run_bootstrap(['--help'])
        self.assertEqual(code, 0, out)
        self.assertIn('--port', out)
        self.assertNotIn('RUN:', out)

if __name__ == '__main__':
    unittest.main()
