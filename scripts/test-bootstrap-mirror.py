#!/usr/bin/env python3
"""Exercise bootstrap downloads without installing services or accessing the network."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class BootstrapMirrorTest(unittest.TestCase):
    def run_bootstrap(self, mirror, choice='2', overrides=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            curl = root / 'curl'
            curl.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://') or a.startswith('http://'))
with open(os.environ['DOWNLOAD_LOG'], 'a') as log: log.write(url + '\\n')
if '-o' not in args: sys.exit(0)
out = pathlib.Path(args[args.index('-o') + 1])
if url.endswith('/libinstall.sh'):
    out.write_text(''' + repr('''installer_init_paths() {
    INSTALLER_CONTROLLER_BINARY="$TEST_SCRATCH/controller"
    INSTALLER_DATA_DIR="$TEST_SCRATCH/data"
    INSTALLER_CONTROLLER_KEY_DIR="$TEST_SCRATCH/keys"
    INSTALLER_INSTALL_DIR="$TEST_SCRATCH/bin"
}
installer_run() {
    chmod +x "$INSTALLER_CONTROLLER_BINARY"
    printf '%s\\n' "$ANTINAT_RELEASE_BASE_URL" >> "$BASE_LOG"
}
''') + ''')
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
            # Bootstrap must see a fresh Controller, then invoke the fixture after installation.
            env = {k: v for k, v in os.environ.items() if not k.startswith('ANTINAT_')}
            env.update(PATH=f'{root}:{env["PATH"]}', TEST_SCRATCH=tmp,
                       DOWNLOAD_LOG=str(root / 'downloads'), BASE_LOG=str(root / 'bases'),
                       ANTINAT_DOWNLOAD_MIRROR=mirror)
            env.update(overrides or {})
            result = subprocess.run(['bash', str(REPO / 'install.sh'), choice], env=env,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return (root / 'downloads').read_text().splitlines(), (root / 'bases').read_text().splitlines()

    def test_mirror_controller_and_agent(self):
        urls, bases = self.run_bootstrap('https://ghfast.top/')
        downloads = [u for u in urls if not u.startswith('http://127.0.0.1:')]
        self.assertEqual(len(downloads), 3)
        self.assertTrue(all(u.startswith('https://ghfast.top/https://') for u in downloads), downloads)
        self.assertEqual(bases, [f'https://ghfast.top/https://github.com/gxbrave/{repo}/releases/download/v1.0.0-beta.2' for repo in ['AntiNAT', 'AntiNAT-Agent']])

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
