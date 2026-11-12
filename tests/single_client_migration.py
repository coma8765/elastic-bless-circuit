"""Exercise the migration's actual Ansible backup and admission guards over loopback."""
import contextlib
import http.server
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / 'deploy' / 'ansible'


@contextlib.contextmanager
def backup_api(directory, invalid=False):
    source = directory / 'live.db'
    with contextlib.closing(sqlite3.connect(source)) as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute('PRAGMA wal_autocheckpoint=0')
        for table in ('inbounds', 'clients', 'settings'):
            writer.execute(f'CREATE TABLE {table}(value TEXT)')
        writer.execute("INSERT INTO clients VALUES ('written during WAL mode')")
        writer.commit()

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, data, content_type='application/json', cookie=None):
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                if cookie:
                    self.send_header('Set-Cookie', cookie + '; Path=/; HttpOnly')
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == '/csrf-token':
                    self.reply(b'{"success": true, "obj": "csrf-value"}', cookie='csrf=test')
                elif self.path == '/panel/api/server/getDb' and 'session=admin' in self.headers['Cookie']:
                    if invalid:
                        self.reply(b'{"success": false}')
                        return
                    with tempfile.TemporaryDirectory(dir=directory) as db_dir:
                        snapshot = Path(db_dir) / 'download.db'
                        with contextlib.closing(sqlite3.connect(source)) as db:
                            with contextlib.closing(sqlite3.connect(snapshot)) as dest:
                                db.backup(dest)
                        self.reply(snapshot.read_bytes(), 'application/octet-stream')
                else:
                    self.send_error(403)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if (self.path == '/login' and self.headers['Cookie'] == 'csrf=test'
                        and self.headers['X-CSRF-Token'] == 'csrf-value'
                        and body == {'username': 'test', 'password': 'fixture-password'}):
                    self.reply(b'{"success": true}', cookie='session=admin')
                else:
                    self.send_error(403)

        with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                yield server.server_port
            finally:
                server.shutdown()
                worker.join()


def playbook(*args):
    return subprocess.run([str(ROOT / 'scripts/ansible.sh'), *map(str, args)], cwd=ROOT,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)


class Migration(unittest.TestCase):
    def backup(self, invalid):
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            (directory / 'panel-password').write_text('fixture-password')
            with backup_api(directory, invalid) as port:
                play = directory / 'backup.yml'
                play.write_text(yaml.safe_dump([{
                    'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                    'vars': {'panel_host_port': port, 'controller_state_dir': str(directory),
                             'ansible_remote_tmp': str(directory / 'ansible-tmp'),
                             'panel_username': 'test', 'ansible_python_interpreter': '{{ ansible_playbook_python }}'},
                    'tasks': [{'ansible.builtin.include_tasks': str(DEPLOY / 'tasks/single-client-backup.yml')}],
                }]))
                result = playbook('-i', 'localhost,', play)
            backup_root = directory / 'single-client-backups'
            self.assertTrue(backup_root.is_dir(), result.stdout)
            backups = list(backup_root.iterdir())
            if invalid:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Migration stopped before upgrading', result.stdout)
                self.assertEqual(backups, [])
            else:
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(len(backups), 1)
                self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)
                target = backups[0] / 'x-ui.db'
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                with contextlib.closing(sqlite3.connect(target)) as db:
                    self.assertEqual(db.execute('SELECT value FROM clients').fetchone(), ('written during WAL mode',))

    def test_valid_backup(self):
        self.backup(False)

    def test_invalid_export_stops_before_any_cutover(self):
        self.backup(True)

    def test_regular_site_rejects_explicit_migration(self):
        result = playbook('-i', DEPLOY / 'inventory.local.yml', DEPLOY / 'site.yml',
                          '-e', 'migrate_single_clients=true')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Use migrate-single-client.yml', result.stdout)
        self.assertNotIn('TASK [Prepare the deployment controller]', result.stdout)

    def test_partial_fleet_cannot_cut_over(self):
        result = playbook('-i', DEPLOY / 'inventory.local.yml', DEPLOY / 'migrate-single-client.yml',
                          '--limit', 'control', '-e', 'panel_client_mode=single migrate_single_clients=true')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Use the full existing inventory', result.stdout)
        self.assertNotIn('TASK [Allocate a unique recovery point]', result.stdout)


if __name__ == '__main__':
    unittest.main()
