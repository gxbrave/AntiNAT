#!/usr/bin/env python3
"""Local SSH manager tests: isolated databases and mocked service operations."""
import importlib.util
import sqlite3
import shutil
import os
import json
import re
import subprocess
import time
import urllib.request
import urllib.error
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('manager', Path(__file__).with_name('antinatctl.py'))
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class ManagementTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / 'controller.db'
        with sqlite3.connect(self.db) as db:
            db.executescript('''
                CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE,
                    password_hash TEXT, password_algorithm TEXT, revision INTEGER,
                    created_at INTEGER, updated_at INTEGER);
                CREATE TABLE web_sessions (user_id TEXT, revoked_at INTEGER);
                CREATE TABLE nodes (id TEXT);
                INSERT INTO users VALUES ('a','old','oldhash','argon2id-v19',1,1,1);
                INSERT INTO users VALUES ('b','other','otherhash','argon2id-v19',1,1,1);
                INSERT INTO web_sessions VALUES ('a',NULL),('b',NULL);
                INSERT INTO nodes VALUES ('keep-me');
            ''')

    def test_reset_rotates_hash_and_revokes_only_selected_user(self):
        hashed = manager.hash_password('NewPass123')
        manager.reset_credentials(self.db, 'a', 'newadmin', hashed)
        with sqlite3.connect(self.db) as db:
            row = db.execute("SELECT username,password_hash,revision FROM users WHERE id='a'").fetchone()
            self.assertEqual(row[0], 'newadmin')
            self.assertTrue(row[1].startswith('$argon2id$v=19$m=65536,t=3,p=4$'))
            self.assertEqual(row[2], 2)
            self.assertIsNotNone(db.execute("SELECT revoked_at FROM web_sessions WHERE user_id='a'").fetchone()[0])
            self.assertIsNone(db.execute("SELECT revoked_at FROM web_sessions WHERE user_id='b'").fetchone()[0])
            self.assertEqual(db.execute('SELECT id FROM nodes').fetchone()[0], 'keep-me')

    def test_conflicting_username_rolls_back(self):
        with self.assertRaises(sqlite3.IntegrityError):
            manager.reset_credentials(self.db, 'a', 'other', 'hash')
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT password_hash FROM users WHERE id='a'").fetchone()[0], 'oldhash')
            self.assertIsNone(db.execute("SELECT revoked_at FROM web_sessions WHERE user_id='a'").fetchone()[0])

    def test_missing_user_cannot_mutate_sessions(self):
        with self.assertRaises(RuntimeError):
            manager.reset_credentials(self.db, 'missing', 'new', 'hash')

    def test_reset_restores_running_service_on_failure(self):
        with patch.object(manager, 'DATABASE', self.db), \
             patch.object(manager, 'ask', side_effect=['1', 'other']), \
             patch.object(manager.getpass, 'getpass', return_value='NewPass123'), \
             patch('builtins.open', unittest.mock.mock_open()), \
             patch.object(manager, 'service', return_value=0) as service:
            with self.assertRaises(sqlite3.IntegrityError):
                manager.reset_admin()
            self.assertEqual([call.args[0] for call in service.call_args_list], ['is-active', 'stop', 'start'])

    def test_random_password(self):
        for _ in range(20):
            value = manager.random_password()
            self.assertRegex(value, r'^[A-Za-z0-9]{8}$')
            self.assertRegex(value, '[A-Za-z]')
            self.assertRegex(value, '[0-9]')

    def test_upgrade_placeholder_has_no_side_effect(self):
        with patch.object(manager.subprocess, 'run') as run:
            self.assertEqual(manager.main(['upgrade']), 0)
            run.assert_not_called()

    def test_menu_upgrade_and_exit(self):
        with patch.object(manager, 'ask', side_effect=['4', '0']), patch.object(manager.subprocess, 'run') as run:
            self.assertEqual(manager.main([]), 0)
            run.assert_not_called()

    def test_non_root_cannot_reset(self):
        with patch.object(manager.os, 'geteuid', return_value=1000):
            with self.assertRaises(PermissionError):
                manager.main(['reset-admin'])

    def test_installer_refuses_unrelated_command(self):
        source = Path(__file__).with_name('antinatctl.py')
        lib = self.root / 'lib.sh'; lib.write_text('# fixture')
        link = self.root / 'bin/antinatctl'; link.parent.mkdir()
        link.write_text('user-owned command')
        with self.assertRaises(RuntimeError):
            manager.install_manager(source, lib, 'systemd', self.root / 'manager', link)
        self.assertEqual(link.read_text(), 'user-owned command')

    def test_installed_manager_and_offline_uninstall(self):
        source = Path(__file__).with_name('antinatctl.py')
        lib = self.root / 'lib.sh'; lib.write_text('# fixture')
        dest = self.root / 'manager'; link = self.root / 'bin/antinatctl'
        manager.install_manager(source, lib, 'systemd', dest, link)
        self.assertEqual(link.resolve(), dest / 'antinatctl.py')
        self.assertEqual((dest / 'libinstall.sh').read_text(), '# fixture')
        help_result = subprocess.run([str(link), '--help'], text=True, capture_output=True, check=True)
        self.assertIn('reset-admin', help_result.stdout)
        with patch.object(manager, 'ask', return_value='no'), patch.object(manager.subprocess, 'run') as run:
            manager.uninstall(dest, link)
            run.assert_not_called()
            self.assertTrue(link.exists())
        with patch.object(manager, 'ask', return_value='DELETE'), patch.object(manager.subprocess, 'run') as run:
            run.return_value.returncode = 1
            with self.assertRaises(RuntimeError):
                manager.uninstall(dest, link)
            self.assertTrue(link.exists())
            run.return_value.returncode = 7
            manager.uninstall(dest, link)
            self.assertFalse(link.exists())
            self.assertFalse(dest.exists())
            self.assertEqual(run.call_args.kwargs['env']['ANTINAT_ROLE'], 'both')


@unittest.skipUnless(os.environ.get('ANTINAT_CONTROLLER_TEST_BINARY'), 'optional real Controller binary')
class ControllerIntegrationTest(unittest.TestCase):
    def test_reset_login_and_session_revocation(self):
        binary = os.environ['ANTINAT_CONTROLLER_TEST_BINARY']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # The installed Controller runs as an unprivileged service user.
            root.chmod(0o755)
            executable = root / 'controller'
            shutil.copyfile(binary, executable)
            executable.chmod(0o755)
            data = root / 'data'; data.mkdir(mode=0o700)
            identity = {}
            if os.geteuid() == 0:
                os.chown(data, 65534, 65534)
                identity = {'user': 65534, 'group': 65534}
            database = data / 'controller.db'
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            proc = None
            def start():
                log = (root / 'controller.log').open('w')
                process = subprocess.Popen([str(executable), '-listen', '127.0.0.1:0', '-store', str(database),
                    '-keydir', str(data / 'keys')], stdout=log, stderr=log, **identity)
                log.close()
                for _ in range(100):
                    match = re.search(r'listening on (127\.0\.0\.1:\d+)', (root / 'controller.log').read_text())
                    if match:
                        return process, 'http://' + match[1]
                    if process.poll() is not None:
                        raise RuntimeError('Controller startup failed')
                    time.sleep(.05)
                process.terminate(); process.wait(timeout=10)
                raise RuntimeError('Controller startup timed out')
            def request(path, data=None, cookie=None):
                headers = {'Content-Type': 'application/json'}
                if cookie:
                    headers['Cookie'] = cookie
                req = urllib.request.Request(endpoint + path, data=None if data is None else json.dumps(data).encode(), headers=headers)
                try:
                    with client.open(req, timeout=10) as response:
                        return response.status, response.headers.get('Set-Cookie'), response.read()
                except urllib.error.HTTPError as error:
                    return error.code, None, error.read()
            try:
                proc, endpoint = start()
                original = {'username': 'oldadmin', 'password': 'OldPass123'}
                self.assertEqual(request('/api/v1/auth/init', original)[0], 201)
                code, cookie, _ = request('/api/v1/auth/login', original)
                self.assertEqual(code, 200)
                self.assertIsNotNone(cookie)
                with sqlite3.connect(database) as db:
                    user_id = db.execute('SELECT id FROM users').fetchone()[0]
                proc.terminate(); proc.wait(timeout=10)
                manager.reset_credentials(database, user_id, 'newadmin', manager.hash_password('NewPass123'))
                proc, endpoint = start()
                self.assertEqual(request('/api/v1/auth/login', original)[0], 401)
                self.assertEqual(request('/api/v1/auth/login', {'username': 'newadmin', 'password': 'NewPass123'})[0], 200)
                self.assertEqual(request('/api/v1/auth/me', cookie=cookie.split(';')[0])[0], 401)
            finally:
                if proc is not None and proc.poll() is None:
                    proc.terminate(); proc.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
