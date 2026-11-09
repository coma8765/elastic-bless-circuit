#!/usr/bin/env python3
"""Offline safety checks for the optional nginx SNI adapter.

Exercises real temporary config files with Docker calls stubbed; never opens
SSH, reads live credentials, changes DNS or accesses the running deployment.
"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
# Keep these offline tests independent of an installed Ansible controller.
basic = types.ModuleType('ansible.module_utils.basic')
basic.AnsibleModule = object
with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'),
                             'ansible.module_utils': types.ModuleType('ansible.module_utils'),
                             'ansible.module_utils.basic': basic}):
    spec = importlib.util.spec_from_file_location('edge_route', ROOT / 'deploy/ansible/library/vless_nginx_sni_route.py')
    edge_route = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(edge_route)
    audit_spec = importlib.util.spec_from_file_location('edge_audit', ROOT / 'deploy/ansible/library/vless_edge_audit.py')
    edge_audit = importlib.util.module_from_spec(audit_spec)
    audit_spec.loader.exec_module(edge_audit)

CONFIG = '''events {}
http { server { listen 8000; } }
stream {
map $ssl_preread_server_name $unrelated {
  reserved.example.test 127.0.0.1:4443;
  default 127.0.0.1:4443;
}
map $ssl_preread_server_name $selected {
  existing.example.test 127.0.0.1:4443;
  # Keep unknown names on their existing fallback.
  default 127.0.0.1:4089;
}
server { listen 8443; ssl_preread on; proxy_pass $selected; }
}
'''
ADDITION = '  new.example.test 127.0.0.1:443;\n'


class ModuleExit(Exception):
    def __init__(self, failed, result):
        self.failed, self.result = failed, result


class FakeModule:
    def __init__(self, params, check_mode=False):
        self.params, self.check_mode = params, check_mode

    def exit_json(self, **result):
        raise ModuleExit(False, result)

    def fail_json(self, **result):
        raise ModuleExit(True, result)


class RouteSafety(unittest.TestCase):
    def execute(self, content=CONFIG, *, check=False, reject_config=False, overrides=None):
        with tempfile.TemporaryDirectory(prefix='vless-edge-test-') as directory:
            path = Path(directory) / 'nginx.conf'
            path.write_text(content)
            inode = path.stat().st_ino
            params = {'path': str(path), 'container': 'test-front', 'map_variable': 'selected',
                      'hostname': 'new.example.test', 'backend': '127.0.0.1:443'}
            params.update(overrides or {})
            calls = []

            def run(command, **kwargs):
                calls.append(command)
                if command[1] == 'inspect':
                    return subprocess.CompletedProcess(command, 0, 'fixed-id 1234\n', '')
                if command[-1] == '-t' and reject_config:
                    return subprocess.CompletedProcess(command, 1, '', 'invalid config')
                return subprocess.CompletedProcess(command, 0, '', '')

            fake = FakeModule(params, check)
            with patch.object(edge_route, 'AnsibleModule', return_value=fake), \
                    patch.object(edge_route.subprocess, 'run', side_effect=run):
                with self.assertRaises(ModuleExit) as raised:
                    edge_route.main()
            backup = path.with_name(path.name + '.vless-edge-before')
            return {'failed': raised.exception.failed, 'result': raised.exception.result,
                    'content': path.read_text(), 'inode_unchanged': path.stat().st_ino == inode,
                    'backup': backup.read_text() if backup.exists() else None,
                    'backup_mode': backup.stat().st_mode & 0o777 if backup.exists() else None,
                    'calls': calls}

    def test_only_selected_map_entry_changes_and_bind_inode_is_preserved(self):
        result = self.execute()
        self.assertFalse(result['failed'])
        self.assertTrue(result['result']['changed'])
        self.assertEqual(result['content'], CONFIG.replace('  default 127.0.0.1:4089;', ADDITION + '  default 127.0.0.1:4089;'))
        self.assertTrue(result['inode_unchanged'])
        self.assertEqual(result['backup'], CONFIG)
        self.assertEqual(result['backup_mode'], 0o600)
        self.assertEqual([c[-1] for c in result['calls'] if c[1] == 'exec'], ['-t', 'reload'])

    def test_validation_failure_rolls_back_and_never_reloads(self):
        result = self.execute(reject_config=True)
        self.assertTrue(result['failed'])
        self.assertEqual(result['content'], CONFIG)
        self.assertTrue(result['inode_unchanged'])
        self.assertEqual([c[-1] for c in result['calls'] if c[1] == 'exec'], ['-t'])

    def test_existing_owned_route_is_idempotent(self):
        content = CONFIG.replace('  default 127.0.0.1:4089;', ADDITION + '  default 127.0.0.1:4089;')
        result = self.execute(content)
        self.assertFalse(result['failed'])
        self.assertFalse(result['result']['changed'])
        self.assertEqual(result['content'], content)
        self.assertIsNone(result['backup'])
        self.assertFalse(any(c[1] == 'exec' for c in result['calls']))

    def test_conflicting_route_is_not_adopted_or_overwritten(self):
        content = CONFIG.replace('  default 127.0.0.1:4089;', '  new.example.test 127.0.0.1:9999;\n  default 127.0.0.1:4089;')
        result = self.execute(content)
        self.assertTrue(result['failed'])
        self.assertEqual(result['content'], content)
        self.assertIsNone(result['backup'])

    def test_an_identical_hostname_in_another_map_is_preserved(self):
        content = CONFIG.replace('reserved.example.test', 'new.example.test')
        result = self.execute(content)
        self.assertFalse(result['failed'])
        self.assertIn('map $ssl_preread_server_name $unrelated {\n  new.example.test 127.0.0.1:4443;', result['content'])
        self.assertEqual(result['content'].count('new.example.test'), 2)

    def test_missing_ambiguous_and_nested_maps_fail_closed(self):
        cases = [CONFIG.replace('$selected {', '$another {'),
                 CONFIG.replace('stream {', 'stream {\nmap $ssl_preread_server_name $selected {\n default 127.0.0.1:8888;\n}'),
                 CONFIG.replace('  default 127.0.0.1:4089;', '  default 127.0.0.1:4089;\n  default 127.0.0.1:9999;'),
                 CONFIG.replace('  default 127.0.0.1:4089;', ''),
                 CONFIG.replace('  default 127.0.0.1:4089;', '  nested { bad; }\n  default 127.0.0.1:4089;')]
        for content in cases:
            with self.subTest(content=content):
                result = self.execute(content)
                self.assertTrue(result['failed'])
                self.assertEqual(result['content'], content)
                self.assertIsNone(result['backup'])

    def test_duplicate_requested_routes_fail_closed(self):
        content = CONFIG.replace('  default 127.0.0.1:4089;', ADDITION + ADDITION + '  default 127.0.0.1:4089;')
        self.assertTrue(self.execute(content)['failed'])

    def test_untrusted_directive_values_are_rejected_before_docker(self):
        cases = [{'hostname': 'new.example.test; injected'}, {'hostname': 'new\n.example.test'},
                 {'backend': '192.0.2.1:443'}, {'backend': '127.0.0.1:443; malicious'},
                 {'map_variable': 'selected; injected'}, {'container': '--all'}]
        for params in cases:
            with self.subTest(params=params):
                result = self.execute(overrides=params)
                self.assertTrue(result['failed'])
                self.assertEqual(result['content'], CONFIG)
                self.assertEqual(result['calls'], [])

    def test_check_mode_does_not_write_or_reload(self):
        result = self.execute(check=True)
        self.assertFalse(result['failed'])
        self.assertTrue(result['result']['changed'])
        self.assertEqual(result['content'], CONFIG)
        self.assertIsNone(result['backup'])
        self.assertFalse(any(c[1] == 'exec' for c in result['calls']))


class ExistingVhostOwnership(unittest.TestCase):
    def test_quoted_and_case_insensitive_names_block_a_duplicate_hostname(self):
        for directive in ['server_name "MESH.Example.COM";',
                          "server_name 'MESH.Example.COM';",
                          'server_name existing.example.com MESH.EXAMPLE.COM;']:
            with self.subTest(directive=directive):
                names = edge_audit.exact_server_names('server { ' + directive + ' }')
                # This is the same exact-name membership used before mutation
                # by the external-edge playbook's ownership assertion.
                self.assertIn('mesh.example.com', names)

    def test_multiline_aliases_are_normalized(self):
        names = edge_audit.exact_server_names("""server {
            server_name
                "MESH.Example.COM"
                'SECOND.Example.COM'
                third.example.com;
        }""")
        self.assertEqual(names, ['mesh.example.com', 'second.example.com', 'third.example.com'])

    def test_comments_and_response_text_do_not_claim_hostnames(self):
        names = edge_audit.exact_server_names("""
        # server_name commented.example.com;
        server {
            return 200 "server_name response.example.com;";
            server_name actual.example.com; # server_name ignored.example.com;
        }
        """)
        self.assertEqual(names, ['actual.example.com'])

    def test_regex_wildcard_and_variable_names_are_not_exact_ownership(self):
        names = edge_audit.exact_server_names("""server {
            server_name *.example.com .example.net $hostname
                "~^regex[.]example[.]org$" Exact.Example.TEST;
        }""")
        self.assertEqual(names, ['exact.example.test'])

    def test_unterminated_quotes_fail_closed(self):
        with self.assertRaises(ValueError):
            edge_audit.exact_server_names('server { server_name "mesh.example.com; }')


if __name__ == '__main__':
    unittest.main(verbosity=2)
