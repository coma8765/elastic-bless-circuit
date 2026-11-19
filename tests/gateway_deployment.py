#!/usr/bin/env python3
"""Exercise the real Ansible gateway topology, private credentials, templates, and ACLs."""
import json
from pathlib import Path
import subprocess
import sys
import uuid
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / 'deploy/ansible'
PANEL = {'inbound_ids': {'in-a': 1, 'in-b': 2, 'manual': 3}}


class GatewayDeployment(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.state = self.work / 'controller'
        self.remote = self.work / 'runtime'
        # controller.yml resolves its task paths relative to the invoking playbook.
        (self.work / 'tasks').symlink_to(DEPLOY / 'tasks', target_is_directory=True)
        old_owner = {'owner': '11111111-1111-4ee0-8111-111111111111',
                     'primary': 'out-a', 'aliases': []}
        self.state.mkdir()
        self.manifest = self.state / 'single-client-legacy.json'
        self.manifest.write_text(json.dumps([old_owner]))
        self.manifest.chmod(0o600)
        opts = {
            'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable,
            'ansible_remote_tmp': str(self.work / 'remote-tmp'),
            'deployment_id': 'geo-test', 'controller_state_dir': str(self.state),
            'deployment_root': str(self.remote), 'headscale_external_tls': True,
            'gateway_enabled': False, 'panel_client_mode': 'single', 'ingress_security': 'reality',
            'vless_route_selectors': {'out-a': 16385, 'out-b': 16386, 'out-c': 16387},
        }
        self.inventory = {'all': {'vars': opts, 'children': {
            'headscale': {'hosts': {'hs': {}}},
            'control': {'hosts': {'panel': {'mesh_ip': '100.64.0.2', 'panel_directory': PANEL}}},
            'exits': {'hosts': {n: {'mesh_ip': '100.64.0.' + str(i + 5),
                                     'exit_display_country': 'Country ' + n}
                                for i, n in enumerate(opts['vless_route_selectors'])}},
            'route_gateways': {'hosts': {'geo': {
                'mesh_ip': '100.64.0.20', 'transit_port': 8445,
                'route_gateway_countries': {'DE': ['out-a', 'out-b'], 'FR': ['out-b']}}}},
            'ingress': {'hosts': {
                n: dict(ingress_public_address=n + '.example.test', ingress_display_country=n,
                        **({'ingress_route_gateway': 'geo', 'ingress_auto_selector': 20479} if n != 'manual' else {}),
                        **({'ingress_subscription_exits': ['out-b']} if n == 'in-b' else {}))
                for n in PANEL['inbound_ids']}},
        }}}
        node_tasks = yaml.safe_load((DEPLOY / 'roles/node/tasks/main.yml').read_text())
        secrets_and_render = [t for t in node_tasks if t['name'] in {
            'Install panel credentials for control and ingress only',
            'Install authorized exit credentials on ingress and route gateways',
            "Install this ingress's gateway transit credential",
            "Install the gateway's authorized ingress identities", "Remove this ingress's Auto credential after detachment",
            'Remove retired gateway credentials', 'Render node YAML'}]
        self.assertEqual(len(secrets_and_render), 7)
        secrets_and_render[-1]['ansible.builtin.template']['src'] = str(DEPLOY / 'templates/node.yaml.j2')
        self.plays = [
            {'hosts': 'headscale:control:exits:route_gateways:ingress', 'gather_facts': False, 'roles': ['deployment_defaults']},
            {'hosts': 'headscale', 'gather_facts': False, 'tasks': [
                {'ansible.builtin.include_tasks': str(DEPLOY / 'tasks/controller.yml')},
                {'ansible.builtin.template': {'src': str(DEPLOY / 'templates/policy.json.j2'),
                                              'dest': str(self.work / 'policy.json')}},
                {'ansible.builtin.copy': {'content': '{{ ingress_endpoints | to_json }}',
                                          'dest': str(self.work / 'endpoints.json')}},
            ]},
            {'hosts': 'ingress:route_gateways', 'gather_facts': False,
             'vars': {'node_role': "{{ 'gateway' if inventory_hostname in groups.route_gateways else 'in' }}"},
             'tasks': [{'ansible.builtin.file': {'path': '{{ node_dir }}/secrets',
                                                 'state': 'directory', 'mode': '0700'}}] + secrets_and_render},
        ]

    def run_playbook(self, failure=None):
        inventory = self.work / 'inventory.yml'
        inventory.write_text(yaml.safe_dump(self.inventory))
        play = self.work / 'play.yml'
        play.write_text(yaml.safe_dump(self.plays, sort_keys=False))
        r = subprocess.run([str(ROOT / 'scripts/ansible.sh'), '-i', str(inventory), str(play)],
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        if failure:
            self.assertNotEqual(r.returncode, 0, r.stdout)
            self.assertIn(failure, r.stdout)
        else:
            self.assertEqual(r.returncode, 0, r.stdout)
        return r.stdout

    def test_render_credentials_and_idempotence(self):
        self.run_playbook()
        config = lambda n: yaml.safe_load((self.remote / n / 'config.yaml').read_text())
        gateway = config('geo')
        self.assertEqual(gateway['listener'], {'address': 'mesh', 'port': 8445})
        self.assertEqual([x['name'] for x in gateway['exits']], ['out-a', 'out-b'])
        self.assertEqual(gateway['gateway']['countries'], {'DE': ['out-a', 'out-b'], 'FR': ['out-b']})
        self.assertEqual({r['name']: r['exits'] for r in gateway['gateway']['ingresses']},
                         {'in-a': ['out-a', 'out-b'], 'in-b': ['out-b']})
        self.assertEqual(set(p.name for p in (self.remote / 'geo/secrets').iterdir()),
                         {'gateway-in-a.uuid', 'gateway-in-b.uuid', 'exit-out-a.uuid', 'exit-out-b.uuid'})
        self.assertNotIn('auto_gateway', config('manual'))
        self.assertFalse((self.remote / 'manual/secrets/gateway-transit.uuid').exists())
        credentials = []
        for name in ('in-a', 'in-b'):
            self.assertEqual(config(name)['auto_gateway'], dict(address='100.64.0.20', port=8445,
                selector=20479, uuid_file='/run/secrets/gateway-transit.uuid'))
            key = self.state / 'route-gateways/geo' / (name + '.uuid')
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            for dest in (self.remote / name / 'secrets/gateway-transit.uuid',
                         self.remote / 'geo/secrets' / ('gateway-' + name + '.uuid')):
                self.assertEqual(dest.read_bytes(), key.read_bytes())
            credentials.append(uuid.UUID(key.read_text()))
        self.assertNotEqual(*credentials)
        endpoints = json.loads((self.work / 'endpoints.json').read_text())
        self.assertEqual({e['remark']: e.get('auto_selector') for e in endpoints},
                         {'in-a': 20479, 'in-b': 20479, 'manual': None})
        policy = json.loads((self.work / 'policy.json').read_text())
        self.assertIn('tag:route-gateway', policy['tagOwners'])
        self.assertEqual([r['dst'] for r in policy['acls'] if 'tag:route-gateway' in r['src']], [['tag:out:8443']])
        self.assertIn(['tag:route-gateway:8445'], [r['dst'] for r in policy['acls'] if 'tag:in' in r['src']])
        self.assertNotRegex(self.run_playbook(), r'changed=[1-9]')
        children = self.inventory['all']['children']
        children['ingress']['hosts']['in-a'].pop('ingress_route_gateway')
        children['ingress']['hosts']['in-a'].pop('ingress_auto_selector')
        children['route_gateways']['hosts']['geo']['route_gateway_countries']['DE'] = ['out-b']
        self.run_playbook()
        self.assertEqual(set(p.name for p in (self.remote / 'geo/secrets').iterdir()),
                         {'gateway-in-b.uuid', 'exit-out-b.uuid'})
        self.assertFalse((self.remote / 'in-a/secrets/gateway-transit.uuid').exists())
        self.assertNotIn('auto_gateway', config('in-a'))

    def test_reject_unknown_exit_before_credentials(self):
        self.inventory['all']['children']['route_gateways']['hosts']['geo']['route_gateway_countries']['FR'] = ['missing']
        self.run_playbook('distinct exit inventory names')
        self.assertFalse((self.state / 'route-gateways').exists())

    def test_reject_legacy_selector_collision(self):
        self.inventory['all']['children']['ingress']['hosts']['in-b']['ingress_auto_selector'] = int('4ee0', 16)
        self.run_playbook('previously issued base profile')
        self.assertFalse(self.remote.exists())


if __name__ == '__main__':
    unittest.main()
