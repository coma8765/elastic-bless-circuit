#!/usr/bin/env python3
"""Subscription exit expansion and real local Ansible identity/template contracts.

No remote hosts, live stands or container engines are contacted by default.
--with-renderer additionally checks generated routes using the cached node image.
"""
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WITH_RENDERER = '--with-renderer' in sys.argv
if WITH_RENDERER:
    sys.argv.remove('--with-renderer')
# tests/ansible.py must not shadow the deployment's installed Ansible package.
sys.path = [p for p in sys.path if Path(p or '.').resolve() != ROOT / 'tests']
spec = importlib.util.spec_from_file_location('vless_user_routes', ROOT / 'deploy/ansible/library/vless_user_routes.py')
routes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routes)
EXITS = ['out', 'prague', 'frankfurt', 'singapore']
spec = importlib.util.spec_from_file_location('vless_panel', ROOT / 'deploy/ansible/library/vless_panel.py')
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)

def canonical_users(users):
    params = {'url':'http://127.0.0.1:2053','directory_port':14443,'subscription_port':2096,
              'users':copy.deepcopy(users),'ingress_endpoints':[{'address':'node.example.com','port':443,'remark':'in','security':'tls'}]}
    panel.validate(params)
    return params['users']



class Expansion(unittest.TestCase):
    def test_preserves_original_and_expands_ordered_distinct_credentials(self):
        users = [{'email': 'owner', 'exit': 'out', 'additional_exits': EXITS[1:]}]
        before = copy.deepcopy(users)
        result = routes.expand(users, EXITS)
        self.assertEqual(users, before)
        self.assertEqual([r['email'] for r in result], ['owner', 'owner--prague', 'owner--frankfurt', 'owner--singapore'])
        self.assertEqual([r['exit'] for r in result], EXITS)
        self.assertTrue(all(r['base_email'] == 'owner' and r['enabled'] is True for r in result))

    def test_empty_users_and_legacy_users_remain_valid(self):
        self.assertEqual(routes.expand([], EXITS), [])
        self.assertEqual(routes.expand([{'email': 'owner', 'exit': 'out'}], EXITS),
                         [{'email': 'owner', 'base_email': 'owner', 'exit': 'out', 'enabled': True}])

    def test_disabling_base_revokes_all_derived_identities(self):
        result = routes.expand([{'email': 'owner', 'exit': 'out', 'additional_exits': EXITS[1:], 'enabled': False}], EXITS)
        self.assertEqual(len(result), 4)
        self.assertTrue(all(r['enabled'] is False for r in result))

    def test_rejects_malformed_duplicate_unknown_primary_and_colliding_choices(self):
        invalid = [None, {}, 'prague', ['prague', 'prague'], ['out'], ['unknown'], [None], [False], [['prague']]]
        for additional in invalid:
            with self.subTest(additional=additional), self.assertRaises(routes.ExpansionError):
                routes.expand([{'email': 'owner', 'exit': 'out', 'additional_exits': additional}], EXITS)
        for users in [[{'email': 'owner', 'exit': 'out', 'additional_exits': ['prague']},
                       {'email': 'owner--prague', 'exit': 'out'}],
                      [{'email': 'owner--prague', 'exit': 'out'},
                       {'email': 'owner', 'exit': 'out', 'additional_exits': ['prague']}],
                      [{'email': 'a'*60, 'exit': 'out', 'additional_exits': ['prague']}],
                      [{'email': 'owner', 'exit': 'out', 'enabled': 'false'}]]:
            with self.subTest(users=users), self.assertRaises(routes.ExpansionError):
                routes.expand(users, EXITS)

    def test_rejects_malformed_top_level_and_exit_inventory(self):
        for users, exits in [(None, EXITS), ({}, EXITS), ([None], EXITS),
                             ([], []), ([], 'out'), ([], ['out', 'out']), ([], ['../out'])]:
            with self.subTest(users=users, exits=exits), self.assertRaises(routes.ExpansionError):
                routes.expand(users, exits)



class GroupTokenValidation(unittest.TestCase):
    def fixture(self):
        return [dict(email='owner',uuid='11111111-1111-4111-8111-111111111111',sub_id='original-token',exit='out',enabled=True,subscription_owner='owner'),
                dict(email='owner--prague',uuid='22222222-2222-4222-8222-222222222222',sub_id='original-token',exit='prague',enabled=True,subscription_owner='owner')]

    def test_child_tokens_are_domain_separated_stable_and_do_not_rederive(self):
        users=self.fixture(); first=canonical_users(users); second=canonical_users(first)
        self.assertEqual(first,second)
        self.assertEqual(first[0]['sub_id'],'original-token')
        self.assertNotEqual(first[1]['sub_id'],first[0]['sub_id'])
        self.assertEqual(first[1]['sub_id'],panel.child_subscription_id('original-token','owner--prague'))
        self.assertNotEqual(first[1]['sub_id'],panel.child_subscription_id('other-token','owner--prague'))
        self.assertNotEqual(first[1]['sub_id'],panel.child_subscription_id('original-token','owner--frankfurt'))
        self.assertEqual(canonical_users(list(reversed(users)))[0]['sub_id'],first[1]['sub_id'])

    def test_unknown_owner_nested_groups_and_mismatched_activation_are_rejected(self):
        for owner,enabled in [('missing',True),('owner--prague',True),('owner',False)]:
            users=self.fixture();users[1].update(subscription_owner=owner,enabled=enabled)
            if owner=='owner--prague':
                users[0]['subscription_owner']='owner--prague'
                users[1]['subscription_owner']='owner'
            with self.subTest(owner=owner,enabled=enabled),self.assertRaises(panel.PanelError):
                canonical_users(users)


class ControllerPersistence(unittest.TestCase):
    def setUp(self):
        (ROOT / '.local').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='user-routes-', dir=ROOT / '.local')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.state = self.work / 'controller'
        self.users = [{'email': 'owner', 'exit': 'out'}]
        self.inventory = {'all': {'vars': {
            'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable,
            'ansible_remote_tmp': str(self.work / 'remote'), 'controller_state_dir': str(self.state),
            'deployment_id': 'route-test', 'headscale_url': 'https://headscale.example.com',
            'vless_users': self.users, 'node_role': 'in', 'mesh_udp_port': 41641,
            'container_name': 'route-test-in', 'sync_seconds': 10, 'max_stale_seconds': 3600,
            'ingress_port': 443, 'ingress_security': 'tls',
        }, 'children': {
            'headscale': {'hosts': {'headscale': {}}},
            'control': {'hosts': {'control': {'mesh_ip': '100.64.0.2', 'panel_directory': {'inbound_id': 1}}}},
            'exits': {'hosts': {name: {'mesh_ip': '100.64.0.' + str(10+i), 'transit_port': 8443} for i, name in enumerate(EXITS)}},
            'ingress': {'hosts': {'in': {}}},
        }}}
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/tasks/controller.yml').read_text())
        last = next(i for i,t in enumerate(tasks) if t['name'] == 'Read the private compatibility manifest for the ingress configuration')
        tasks = tasks[:last+1]
        tasks.append({'name': 'Inspect resulting fixture identities privately', 'ansible.builtin.copy': {
            'content': '{{ managed_users | to_json }}', 'dest': str(self.work / 'managed.json'), 'mode': '0600'},
            'no_log': True, 'changed_when': False})
        play = [{'hosts': 'headscale', 'gather_facts': False, 'tasks': tasks},
                {'hosts': 'ingress', 'gather_facts': False, 'tasks': [
                    {'name': 'Render the actual node route template', 'ansible.builtin.template': {
                        'src': str(ROOT / 'deploy/ansible/templates/node.yaml.j2'),
                        'dest': str(self.work / 'node.yaml')}}]}]
        self.playbook = self.work / 'playbook.yml'
        self.playbook.write_text(yaml.safe_dump(play, sort_keys=False))

    def run_play(self, success=True):
        inventory = self.work / 'inventory.json'
        inventory.write_text(json.dumps(self.inventory))
        result = subprocess.run([str(ROOT / 'scripts/ansible.sh'), '-i', str(inventory), str(self.playbook)],
                                cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result.stdout

    def managed(self):
        return canonical_users(json.loads((self.work / 'managed.json').read_text()))

    def test_persistence_unique_child_tokens_disable_and_remove_readd(self):
        self.run_play()
        base = self.managed()[0]
        self.users[0]['additional_exits'] = EXITS[1:]
        self.run_play()
        expanded = self.managed()
        self.assertEqual(expanded[0], base)
        self.assertEqual(len({u['uuid'] for u in expanded}), 4)
        self.assertEqual(len({u['sub_id'] for u in expanded}), 4)
        self.assertTrue(all(u['subscription_owner'] == 'owner' for u in expanded))
        self.assertEqual(sorted(p.name for p in (self.state / 'users').glob('*.sub')), ['owner.sub'])
        expected = {u['email']: u['exit'] for u in expanded}
        config = yaml.safe_load((self.work / 'node.yaml').read_text())
        self.assertEqual(config['routes'], expected)
        identities = {u['email']: (u['uuid'], u['sub_id']) for u in expanded}
        self.users[0]['additional_exits'].remove('frankfurt')
        self.run_play()
        self.assertNotIn('owner--frankfurt', yaml.safe_load((self.work / 'node.yaml').read_text())['routes'])
        self.assertTrue((self.state / 'users/owner--frankfurt.uuid').exists())
        self.users[0]['additional_exits'] = EXITS[1:]
        self.users[0]['enabled'] = False
        self.run_play()
        self.assertTrue(all(u['enabled'] is False for u in self.managed()))
        self.assertEqual({u['email']:(u['uuid'],u['sub_id']) for u in self.managed()}, identities)
        self.users[0]['enabled'] = True
        self.run_play()
        output = self.run_play()
        self.assertTrue(all(int(n) == 0 for n in re.findall(r'changed=(\d+)', output)), output)
        self.assertEqual(self.managed()[0], base)
        if WITH_RENDERER:
            self.assert_renderer(config, expanded)

    def test_single_mode_keeps_cached_credentials_after_inventory_handoff(self):
        variables = self.inventory['all']['vars']
        variables.update(panel_client_mode='single', migrate_single_clients=True,
                         vless_route_selectors={name: 16385 + i for i, name in enumerate(EXITS)},
                         ingress_subscription_exits=['prague'], ingress_security='reality',
                         ingress_reality_server_name='example.com', ingress_reality_target='example.com:443')
        self.users[0]['additional_exits'] = EXITS[1:]
        hosts = self.inventory['all']['children']
        hosts['headscale']['hosts']['headscale'] = {'reality_identities': {'in': {'short_id': '01020304'}}}
        hosts['control']['hosts']['control']['panel_directory'] = {'inbound_ids': {'in': 1}}
        # Choose the old credential's selector explicitly to avoid a random collision in the fixture.
        private = self.state / 'users'
        private.mkdir(parents=True, mode=0o700)
        (private / 'owner.uuid').write_text('11111111-1111-4ffe-8111-111111111111')
        self.run_play()
        expected = yaml.safe_load((self.work / 'node.yaml').read_text())['single_client']
        self.assertEqual(expected['selectors'], {'prague': 16386})
        self.assertEqual(len(expected['legacy']), 1)
        self.assertEqual(len(expected['legacy'][0]['aliases']), 3)
        self.assertEqual(expected['legacy'][0]['owner'], (private / 'owner.uuid').read_text())
        self.assertEqual((self.state / 'single-client-legacy.json').stat().st_mode & 0o777, 0o600)
        variables.update(migrate_single_clients=False, vless_users=[])
        self.run_play()
        self.assertEqual(yaml.safe_load((self.work / 'node.yaml').read_text())['single_client'], expected)

    def assert_renderer(self, config, users):
        spec = importlib.util.spec_from_file_location('renderer_contracts', ROOT / 'tests/validate.py')
        renderer = importlib.util.module_from_spec(spec); spec.loader.exec_module(renderer)
        config = copy.deepcopy(config)
        config['mesh'] = {'enabled': False}
        config.pop('panel'); config['listener'].pop('stream')
        config['allow_insecure_lab'] = True
        config['users'] = [{'email': u['email'], 'id': u['uuid']} for u in users]
        for exit in config['exits']:
            exit['uuid_file'] = '/test/transit-uuid'
        actual = renderer.RendererContracts().render(config, xray_validate=True)
        self.assertEqual({r['user'][0]:r['outboundTag'] for r in actual['routing']['rules']},
                         {u['email']:u['exit'] for u in users})
        self.assertNotIn('freedom', [r['protocol'] for r in actual['outbounds']])

    def test_bad_choices_fail_before_controller_secret_directory_is_created(self):
        for additional in [['prague','prague'], ['out'], ['missing'], 'prague', [None]]:
            with self.subTest(additional=additional):
                self.users[0]['additional_exits'] = additional
                self.run_play(success=False)
                self.assertFalse(self.state.exists(), 'invalid expansion wrote persistent secrets')


if __name__ == '__main__':
    unittest.main(verbosity=2)
