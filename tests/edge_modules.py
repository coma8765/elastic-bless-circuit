#!/usr/bin/env python3
"""Offline safety checks for the optional nginx SNI adapter.

Exercises real temporary config files with Docker calls stubbed; never opens
SSH, reads live credentials, changes DNS or accesses the running deployment.
"""
import importlib.util
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

try:
    from jinja2 import Environment, StrictUndefined
    import yaml
except ImportError:
    Environment = None

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

    def test_expected_previous_backend_replaces_only_one_token_and_preserves_inode(self):
        for spelling in ['new.example.test 8.8.8.8:443;',
                         '"NEW.EXAMPLE.TEST"\n # preserve this\n "8.8.8.8:443" ;']:
            entry = '  ' + spelling + '\n'
            content = CONFIG.replace('  default 127.0.0.1:4089;', entry + '  default 127.0.0.1:4089;')
            for check in [False, True]:
                result = self.execute(content, check=check, overrides={'previous_backend': '8.8.8.8:443'})
                self.assertFalse(result['failed'])
                self.assertTrue(result['result']['changed'])
                expected = content.replace('"8.8.8.8:443"', '127.0.0.1:443').replace('8.8.8.8:443', '127.0.0.1:443')
                self.assertEqual(result['content'], content if check else expected)
                self.assertTrue(result['inode_unchanged'])
                self.assertEqual(result['backup'], None if check else content)

    def test_previous_backend_mismatch_missing_and_duplicate_routes_refuse_writes(self):
        entry = '  new.example.test 8.8.8.8:443;\n'
        for content in [CONFIG, CONFIG.replace('  default 127.0.0.1:4089;',
                                               entry + '  default 127.0.0.1:4089;'),
                        CONFIG.replace('  default 127.0.0.1:4089;',
                                       entry + entry + '  default 127.0.0.1:4089;')]:
            expected = '8.8.4.4:443' if content.count(entry) == 1 else '8.8.8.8:443'
            result = self.execute(content, overrides={'previous_backend': expected})
            self.assertTrue(result['failed'])
            self.assertEqual(result['content'], content)
            self.assertIsNone(result['backup'])
            self.assertFalse(any(c[1] == 'exec' for c in result['calls']))

    def test_previous_backend_is_strict_unicast_comparison_only(self):
        for old in ['', '8.8.8.8:0', '8.8.8.8:65536', '::1:443', '0.0.0.0:443',
                    '224.1.1.1:443', '255.255.255.255:443', '169.254.1.1:443',
                    '8.8.8.8:443; injected']:
            result = self.execute(overrides={'previous_backend': old})
            self.assertTrue(result['failed'])
            self.assertEqual(result['calls'], [])
        # Public addresses may be compared, but never installed as desired backends.
        result = self.execute(overrides={'previous_backend': '8.8.8.8:443', 'backend': '8.8.4.4:443'})
        self.assertTrue(result['failed'])
        self.assertEqual(result['calls'], [])

    def test_expected_previous_replacement_validation_failure_rolls_back(self):
        content = CONFIG.replace('existing.example.test 127.0.0.1:4443', 'new.example.test 8.8.8.8:443')
        result = self.execute(content, reject_config=True, overrides={'previous_backend': '8.8.8.8:443'})
        self.assertTrue(result['failed'])
        self.assertEqual(result['content'], content)
        self.assertEqual(result['backup'], content)
        self.assertTrue(result['inode_unchanged'])
        self.assertEqual([c[-1] for c in result['calls'] if c[1] == 'exec'], ['-t'])

    def test_desired_backend_is_idempotent_after_expected_previous_transition(self):
        content = CONFIG.replace('existing.example.test 127.0.0.1:4443', 'new.example.test 127.0.0.1:443')
        result = self.execute(content, overrides={'previous_backend': '8.8.8.8:443'})
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

    def test_equivalent_exact_keys_are_idempotent_or_refused_without_writes(self):
        for key in ['NEW.EXAMPLE.TEST', '"new.example.test"', "'NEW.EXAMPLE.TEST'"]:
            for layout in ['  {key} {backend};\n', '  {key}\n    # retained comment\n    "{backend}"\n    ;\n']:
                for backend in ['127.0.0.1:443', '127.0.0.1:9999']:
                    for check in [False, True]:
                        with self.subTest(key=key, layout=layout, backend=backend, check=check):
                            entry = layout.format(key=key, backend=backend)
                            content = CONFIG.replace('  default 127.0.0.1:4089;', entry + '  default 127.0.0.1:4089;')
                            result = self.execute(content, check=check)
                            self.assertEqual(result['failed'], backend != '127.0.0.1:443')
                            if not result['failed']:
                                self.assertFalse(result['result']['changed'])
                            self.assertEqual(result['content'], content)
                            self.assertIsNone(result['backup'])
                            self.assertFalse(any(c[1] == 'exec' for c in result['calls']))

    def test_duplicate_case_and_quote_variants_fail_closed(self):
        content = CONFIG.replace('  default 127.0.0.1:4089;',
                                 ADDITION + '  "NEW.EXAMPLE.TEST" 127.0.0.1:443;\n  default 127.0.0.1:4089;')
        result = self.execute(content, check=True)
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

    def test_rfc1918_backends_require_explicit_opt_in(self):
        for address in ['10.20.30.40', '172.16.0.1', '172.31.255.254', '192.168.20.30']:
            with self.subTest(address=address):
                backend = address + ':4333'
                rejected = self.execute(overrides={'backend': backend})
                self.assertTrue(rejected['failed'])
                self.assertEqual(rejected['calls'], [])
                allowed = self.execute(overrides={'backend': backend, 'allow_private_backend': True})
                self.assertFalse(allowed['failed'])
                self.assertIn('new.example.test ' + backend + ';', allowed['content'])
                self.assertTrue(allowed['inode_unchanged'])
                self.assertEqual(allowed['backup'], CONFIG)

    def test_opt_in_never_accepts_public_link_local_multicast_or_cgnat(self):
        for address in ['8.8.8.8', '192.0.2.1', '203.0.113.1', '169.254.1.1',
                        '224.0.0.1', '100.64.0.1', '172.15.255.255', '172.32.0.1',
                        '192.169.0.1', '127.0.0.2', '0.0.0.0', '255.255.255.255']:
            with self.subTest(address=address):
                result = self.execute(overrides={'backend': address + ':4333', 'allow_private_backend': True})
                self.assertTrue(result['failed'])
                self.assertEqual(result['calls'], [])
                self.assertEqual(result['content'], CONFIG)

    def test_all_backend_ports_are_validated_before_docker_access(self):
        for host in ['127.0.0.1', '10.20.30.40']:
            for port in ['0', '00000', '65536', '99999', '+443', 'https', '655350']:
                with self.subTest(host=host, port=port):
                    result = self.execute(overrides={'backend': host + ':' + port, 'allow_private_backend': True})
                    self.assertTrue(result['failed'])
                    self.assertEqual(result['calls'], [])
            for port in ['1', '65535']:
                with self.subTest(host=host, port=port):
                    result = self.execute(overrides={'backend': host + ':' + port, 'allow_private_backend': True})
                    self.assertFalse(result['failed'])

    def test_ipv6_and_malformed_backends_are_not_accepted_by_ipv4_opt_in(self):
        for backend in ['[::1]:443', '[fd00::1]:4333', '10.20.30.40', '10.20.30.40:4333:1',
                        '10.020.30.40:4333', '10.20.30.40:4333; injected']:
            with self.subTest(backend=backend):
                result = self.execute(overrides={'backend': backend, 'allow_private_backend': True})
                self.assertTrue(result['failed'])
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


@unittest.skipUnless(Environment is not None, 'template checks require the Ansible Jinja2/PyYAML dependencies')
class EdgeTemplateScope(unittest.TestCase):
    def setUp(self):
        self.env = Environment(undefined=StrictUndefined, trim_blocks=True, keep_trailing_newline=True)
        self.env.filters['b64decode'] = lambda value: base64.b64decode(value).decode()
        self.template = self.env.from_string((ROOT / 'deploy/ansible/templates/external-edge.conf.j2').read_text())
        self.context = {'external_edge_domain': 'subscriptions.example.test',
                        'edge_cert_name': 'vless-edge-subscriptions.example.test',
                        'edge_sub_upstream': '127.0.0.1:2096',
                        'edge_headscale_upstream': '127.0.0.1:18081'}
        self.tasks = yaml.safe_load((ROOT / 'deploy/ansible/external-edge.yml').read_text())[0]['tasks']

    def task(self, name):
        return next(task for task in self.tasks if task['name'] == name)

    def test_dns_management_defaults_on_and_explicit_false_skips_only_record_task(self):
        play = yaml.safe_load((ROOT / 'deploy/ansible/external-edge.yml').read_text())[0]
        self.env.filters['bool'] = lambda value: value in (True, 1, 'true', 'yes')
        setting = self.env.compile_expression(play['vars']['edge_manage_dns'][2:-2].strip())
        condition = self.env.compile_expression(self.task('Create only the authorized DNS-only A record')['when'])
        self.assertTrue(condition(edge_manage_dns=setting()))
        self.assertFalse(condition(edge_manage_dns=setting(external_edge_manage_dns=False)))
        for name in ['Issue or retain the isolated certificate using the existing ACME account',
                     'Install and validate only this edge vhost']:
            self.assertNotIn('when', self.task(name))
        self.assertEqual(self.task('Add an explicitly authorized SNI route on an existing stream frontend')['when'],
                         'external_edge_stream_config is defined')

    def test_skipped_dns_audit_does_not_claim_a_record_was_read_or_changed(self):
        self.env.filters['bool'] = bool
        self.env.filters['to_nice_json'] = json.dumps
        content = self.task('Preserve post-change audit and DNS status privately')['ansible.builtin.copy']['content']
        expression = self.env.compile_expression(content[2:-2].strip())
        common = {'edge_after': {'audit': {'verified': True}}}
        skipped = json.loads(expression(**common, edge_manage_dns=False,
                                                    edge_dns={'skipped': True, 'changed': False}))
        self.assertFalse(skipped['dns_managed'])
        self.assertFalse(skipped['dns_changed'])
        self.assertIsNone(skipped['record'])
        applied = json.loads(expression(**common, edge_manage_dns=True,
                                                    edge_dns={'changed': True, 'record': {'type': 'A'}}))
        self.assertTrue(applied['dns_managed'])
        self.assertTrue(applied['dns_changed'])
        self.assertEqual(applied['record'], {'type': 'A'})

    def test_default_combined_mode_keeps_the_existing_rendered_configuration(self):
        rendered = self.template.render(**self.context)
        # Captured from the combined template before adding subscription-only mode.
        self.assertEqual(hashlib.sha256(rendered.encode()).hexdigest(),
                         '2cf727e0217eac40136960327e39a5665a78aadf867debf6892da5b8a34e12f2')
        self.assertEqual(rendered, self.template.render(**dict(self.context, edge_subscription_only=False)))
        self.assertIn('proxy_set_header Upgrade $http_upgrade;', rendered)
        self.assertIn('proxy_pass http://127.0.0.1:18081;', rendered)

    def test_subscription_only_mode_has_no_admin_or_headscale_forwarding(self):
        rendered = self.template.render(**dict(self.context, edge_subscription_only=True))
        self.assertIn('location ^~ /sub/ {', rendered)
        self.assertIn('proxy_pass http://127.0.0.1:2096;', rendered)
        self.assertEqual(rendered.count('proxy_pass '), 1)
        self.assertEqual(rendered.count('location / { return 404; }'), 2)
        self.assertNotIn('18081', rendered)
        self.assertNotIn('2053', rendered)
        self.assertNotIn('Upgrade', rendered)
        self.assertNotIn('map $http_upgrade', rendered)
        self.assertNotIn('generate_204', rendered)
        self.assertEqual(rendered.count('access_log off;'), 2)

    def test_a_second_subscription_host_adds_no_conflicting_upgrade_map(self):
        combined = self.template.render(**self.context)
        second = self.template.render(**dict(self.context,
                                             external_edge_domain='second.example.test',
                                             edge_cert_name='vless-edge-second.example.test',
                                             edge_subscription_only=True))
        self.assertEqual((combined + second).count('map $http_upgrade'), 1)
        self.assertIn('/live/vless-edge-second.example.test/fullchain.pem;', second)
        self.assertIn('server_name second.example.test;', second)

    def test_an_owned_vhost_path_cannot_be_reused_for_a_different_hostname(self):
        task = self.task('Refuse reusing the vhost path for another hostname')
        conditions = task['ansible.builtin.assert']['that']
        context = {'edge_conf_path': '/etc/nginx/conf.d/owned.conf',
                   'external_edge_domain': 'new.example.test',
                   'edge_before': {'audit': {'nginx_configs': {
                       '/etc/nginx/conf.d/owned.conf': {'server_names': ['existing.example.test']}}}}}
        self.assertFalse(all(self.env.compile_expression(condition)(**context) for condition in conditions))
        context['external_edge_domain'] = 'existing.example.test'
        self.assertTrue(all(self.env.compile_expression(condition)(**context) for condition in conditions))

    def test_renewal_hook_cannot_be_reused_for_another_lineage(self):
        task = self.task('Refuse reusing a renewal hook for another certificate')
        expression = self.env.compile_expression(task['ansible.builtin.assert']['that'][0])
        existing = 'if [ "$RENEWED_LINEAGE" != "/etc/letsencrypt/live/first" ]; then exit 0; fi'
        saved = {'content': base64.b64encode(existing.encode()).decode()}
        self.assertFalse(expression(edge_lineage='/etc/letsencrypt/live/second', edge_saved_hook=saved))
        self.assertTrue(expression(edge_lineage='/etc/letsencrypt/live/first', edge_saved_hook=saved))

    def test_certificate_lineage_cannot_be_shared_with_another_vhost(self):
        task = self.task('Refuse sharing the managed certificate lineage with another vhost')
        expression = self.env.compile_expression(task['ansible.builtin.assert']['that'][0])
        context = {'edge_conf_path': '/etc/nginx/conf.d/second.conf',
                   'edge_lineage': '/etc/letsencrypt/live/first',
                   'item': {'key': '/etc/nginx/conf.d/first.conf', 'value': {
                       'directives': ['ssl_certificate "/etc/letsencrypt/live/first/fullchain.pem"']}}}
        self.assertFalse(expression(**context))
        context['edge_lineage'] = '/etc/letsencrypt/live/second'
        self.assertTrue(expression(**context))

    def test_ingress_dial_domain_is_independent_of_the_routed_reality_sni(self):
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/ingress-edge.yml').read_text())[0]['tasks']
        dns = next(task['vless_cloudflare_record'] for task in tasks if 'vless_cloudflare_record' in task)
        routes = [task['vless_nginx_sni_route'] for task in tasks if 'vless_nginx_sni_route' in task]
        context = {'ingress_edge_domain': 'dial.example.test', 'ingress_edge_sni': 'cover.example.test'}
        self.assertEqual(self.env.from_string(dns['name']).render(**context), 'dial.example.test')
        self.assertEqual(len(routes), 2)
        for route in routes:
            self.assertEqual(self.env.from_string(route['hostname']).render(**context), 'cover.example.test')

    def test_ingress_route_preflight_precedes_dns_and_performs_no_reload(self):
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/ingress-edge.yml').read_text())[0]['tasks']
        dns_index = next(index for index, task in enumerate(tasks) if 'vless_cloudflare_record' in task)
        route_tasks = [(index, task) for index, task in enumerate(tasks) if 'vless_nginx_sni_route' in task]
        self.assertLess(route_tasks[0][0], dns_index)
        self.assertTrue(route_tasks[0][1]['check_mode'])
        self.assertFalse(route_tasks[0][1]['changed_when'])
        self.assertGreater(route_tasks[1][0], dns_index)
        self.assertNotIn('check_mode', route_tasks[1][1])

    def test_ingress_passthrough_does_not_install_certificates_or_https_vhosts(self):
        playbook = yaml.safe_load((ROOT / 'deploy/ansible/ingress-edge.yml').read_text())[0]
        self.assertEqual(playbook['hosts'], 'ingress_edge')
        self.assertFalse(any('ansible.builtin.template' in task for task in playbook['tasks']))
        commands = [task['ansible.builtin.command'] for task in playbook['tasks'] if 'ansible.builtin.command' in task]
        self.assertFalse(any('certbot' in str(command) for command in commands))
        self.assertFalse(any('state' in task.get('ansible.builtin.systemd_service', {}) for task in playbook['tasks']))

    def test_scope_guards_run_before_dns_or_certificate_mutations(self):
        names = [task['name'] for task in self.tasks]
        boundary = names.index('Create only the authorized DNS-only A record')
        for name in ['Refuse reusing the vhost path for another hostname',
                     'Refuse reusing a renewal hook for another certificate',
                     'Refuse sharing the managed certificate lineage with another vhost']:
            self.assertLess(names.index(name), boundary)


if __name__ == '__main__':
    unittest.main(verbosity=2)
