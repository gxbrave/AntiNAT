#!/usr/bin/env python3
"""Exercise the curl-pipe entry point with a fake release downloader and real TTY."""
import os
import pathlib
import pty
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class BootstrapTest(unittest.TestCase):
    def run_bootstrap(self, args, answer=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)
            curl = path / 'curl'
            curl.write_text('''#!/usr/bin/env python3
import sys, pathlib
out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
if out.name == 'libinstall.sh':
    out.write_text('installer_run() { printf "RESULT:%s\\\\n" "$ANTINAT_ROLE"; if [[ " $* " == *" --token-fd 9 "* ]]; then test -e /proc/$$/fd/9 || return 91; fi; printf "ARG:%s\\\\n" "$@"; }\\n')
else:
    out.write_text('test key')
''')
            curl.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if not k.startswith('ANTINAT_')}
            env['PATH'] = tmp + ':' + env['PATH']
            command = ['bash', '-c', 'cat "$1" | bash -s -- "${@:2}"', 'test', str(ROOT / 'install.sh'), *args]
            if answer is None:
                result = subprocess.run(command, env=env, capture_output=True, text=True, start_new_session=True, timeout=10)
                return result.returncode, result.stdout + result.stderr
            pid, fd = pty.fork()
            if pid == 0:
                token_fd = os.open('/dev/null', os.O_RDONLY)
                os.dup2(token_fd, 9, inheritable=True)
                os.execvpe(command[0], command, env)
            os.write(fd, answer.encode())
            output = b''
            try:
                while True:
                    output += os.read(fd, 4096)
            except OSError:
                pass
            finally:
                os.close(fd)
            _, status = os.waitpid(pid, 0)
            return os.waitstatus_to_exitcode(status), output.decode()

    def test_roles(self):
        for value, role in [('1', 'controller'), ('2', 'agent'), ('3', 'both'), ('controller', 'controller'), ('agent', 'agent'), ('both', 'both')]:
            code, out = self.run_bootstrap([value, '--controller-endpoint', 'https://example.com'])
            self.assertEqual(code, 0, out)
            self.assertIn('RESULT:' + role, out)
            self.assertIn('ARG:install', out)
            self.assertIn('ARG:https://example.com', out)

    def test_pipe_menu(self):
        code, out = self.run_bootstrap([], '9\n1\n')
        self.assertEqual(code, 0, out)
        self.assertIn('RESULT:controller', out)

    def test_pipe_endpoint(self):
        code, out = self.run_bootstrap([], '2\nhttps://example.com\n')
        self.assertEqual(code, 0, out)
        self.assertIn('RESULT:agent', out)
        self.assertIn('ARG:https://example.com', out)

    def test_preserve_token_fd(self):
        code, out = self.run_bootstrap(['agent', '--token-fd', '9'], 'https://example.com\n')
        self.assertEqual(code, 0, out)

    def test_no_terminal(self):
        code, out = self.run_bootstrap([])
        self.assertEqual(code, 2, out)
        self.assertIn('--role', out)

    def test_help(self):
        code, out = self.run_bootstrap(['--help'])
        self.assertEqual(code, 0, out)
        self.assertIn('--role', out)
        self.assertNotIn('RESULT:', out)

    def test_explicit_role(self):
        code, out = self.run_bootstrap(['install', '--role', 'controller'])
        self.assertEqual(code, 0, out)
        self.assertIn('RESULT:controller', out)

    def test_install_version(self):
        code, out = self.run_bootstrap(["install", "--version"])
        self.assertEqual(code, 0, out)
        self.assertIn("antinat-installer 1", out)

    def test_upgrade_compatible(self):
        code, out = self.run_bootstrap(['upgrade'])
        self.assertEqual(code, 0, out)
        self.assertIn('ARG:upgrade', out)

if __name__ == '__main__':
    unittest.main()
