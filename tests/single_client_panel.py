#!/usr/bin/env python3
"""Panel contracts for a native client shared by managed directory inbounds."""
import copy
import importlib.util
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path = [p for p in sys.path if Path(p or '.').resolve() != ROOT / 'tests']
spec = importlib.util.spec_from_file_location('vless_panel', ROOT / 'deploy/ansible/library/vless_panel.py')
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)


def config():
    endpoints = []
    for name, country in [('in', 'Russia'), ('in-de', 'Germany')]:
        endpoints.append(dict(
            remark=name, display_country=country, address=name + '.example.test', port=443,
            security='reality', reality_public_key='K' * 43, reality_short_id='00',
            reality_server_name='cover.example.test', reality_target='cover.example.test:443',
        ))
    endpoints[1]['subscription_exits'] = ['west']
    users = [
        dict(email='alice', exit='east', uuid=str(uuid.UUID(int=1)), enabled=True,
             sub_id='original', subscription_owner='alice'),
        dict(email='alice--west', exit='west', uuid=str(uuid.UUID(int=2)), enabled=True,
             sub_id='original', subscription_owner='alice'),
    ]
    return dict(
        url='http://127.0.0.1:2053', directory_port=14443, subscription_port=2096,
        client_mode='single', route_selectors={'west': 16385, 'east': 16386},
        exit_countries={'west': 'Germany', 'east': 'Singapore'}, users=users, ingress_endpoints=endpoints,
    )


class MemoryPanel:
    def __init__(self, params, proxies):
        self.mutations = []
        ids = [1, 2]
        self.inbounds = [
            dict(id=i, remark=panel.DIRECTORY + ':' + endpoint['remark'], port=20000 + i,
                 listen='127.0.0.1', enable=True, excludeFromSub=True, protocol='vless',
                 disableFlow=False, expiryTime=0, total=0, sniffing={'enabled': False},
                 settings={'clients': [], 'decryption': 'none'}, streamSettings=panel.directory_stream(endpoint, proxy))
            for i, endpoint, proxy in zip(ids, params['ingress_endpoints'], proxies)
        ]
        self.clients = {
            user['email']: dict(email=user['email'], uuid=user['uuid'], subId=user['sub_id'],
                                enable=user['enabled'], expiryTime=0, inboundIds=ids,
                                comment=panel.comment_for(user['exit']))
            for user in params['users']
        }
        self.clients['operator'] = dict(
            email='operator', uuid=str(uuid.UUID(int=3)), subId='operator-token',
            enable=False, expiryTime=19, inboundIds=[2], comment='UI created',
        )
        self.links = {name: [] for name in self.clients}
        self.operator_link = dict(kind='subscription', value='https://other.example.test/sub/a',
                                  remark='extra', enable=False, expiryTime=1893456000000, namePrefix='operator')
        self.links['alice'] = [self.operator_link] + [
            dict(kind='link', value=f"vless://{record['uuid']}@in.example.test:443#label",
                 namePrefix=panel.LINK_PREFIX + name)
            for name, record in self.clients.items() if name.startswith('alice')
        ]

    def call(self, path, data=None):
        parsed = unquote(path).split('?', 1)[0]
        if data is None:
            if parsed.endswith('/inbounds/list'):
                return copy.deepcopy(self.inbounds)
            if parsed.endswith('/clients/list'):
                return copy.deepcopy(list(self.clients.values()))
            if '/clients/get/' in parsed:
                name = parsed.rsplit('/', 1)[1]
                return dict(copy.deepcopy(self.clients[name]), externalLinks=copy.deepcopy(self.links.get(name, [])))
            if '/clients/links/' in parsed:
                client = self.clients[parsed.rsplit('/', 1)[1]]
                base = uuid.UUID(client['uuid']).bytes
                links = []
                for directory in self.inbounds:
                    if directory['id'] not in client['inboundIds']:
                        continue
                    for proxy in directory['streamSettings']['externalProxy']:
                        selector = int(proxy['vlessRoute']).to_bytes(2, 'big')
                        key = uuid.UUID(bytes=base[:6] + selector + base[8:])
                        links.append(f"vless://{key}@{proxy['dest']}:{proxy['port']}#{quote(proxy['remark'])}")
                return links
        if parsed.endswith('/setting/all'):
            return dict(subEnable=True, subPort=2096, subPath='/sub/', subListen='0.0.0.0')
        self.mutations.append(parsed)
        if parsed.endswith('/externalLinks'):
            self.links[parsed.split('/')[-2]] = copy.deepcopy(data['externalLinks'])
        elif '/clients/del/' in parsed:
            assert path.endswith('?keepTraffic=1')
            name = parsed.rsplit('/', 1)[1]
            del self.clients[name]
            del self.links[name]
        elif parsed.endswith('/clients/bulkAttach'):
            for email in data['emails']:
                self.clients[email]['inboundIds'] = self.clients[email]['inboundIds'] + data['inboundIds']
            return {'attached': data['emails']}
        elif '/inbounds/update/' in parsed:
            index = next(i for i, row in enumerate(self.inbounds) if row['id'] == data['id'])
            self.inbounds[index] = copy.deepcopy(data)
        elif parsed.endswith('/inbounds/add'):
            created = dict(copy.deepcopy(data), id=max((row['id'] for row in self.inbounds), default=0) + 1)
            self.inbounds.append(created)
            return created
        else:
            raise AssertionError('Unexpected mutation: ' + path)


class SingleClient(unittest.TestCase):
    def setUp(self):
        self.params = config()
        self.api = MemoryPanel(self.params, panel.validate(self.params))

    def apply(self, check_mode=False):
        module = SimpleNamespace(params=self.params, check_mode=check_mode)
        return panel.reconcile(module, self.api, panel.validate(self.params))['changed']

    def test_migration_native_routes_ui_ownership_and_idempotence(self):
        owner = copy.deepcopy(self.api.clients['alice'])
        operator = copy.deepcopy(self.api.clients['operator'])
        with self.assertRaisesRegex(panel.PanelError, 'explicit'):
            self.apply()
        self.assertEqual(self.api.mutations, [])
        self.params['migrate_single_clients'] = True
        self.assertTrue(self.apply(check_mode=True))
        self.assertEqual(self.api.mutations, [])
        self.assertTrue(self.apply())
        self.assertEqual(self.api.clients, {'alice': owner, 'operator': operator})
        self.assertEqual(self.api.links['alice'], [self.api.operator_link])
        routes = [proxy for inbound in self.api.inbounds for proxy in inbound['streamSettings']['externalProxy']]
        self.assertEqual({(r['remark'], r['vlessRoute']) for r in routes}, {
            ('Russia -> Germany', '16385'), ('Russia -> Singapore', '16386'), ('Germany -> Germany', '16385'),
        })
        self.assertTrue(all(r['remarkFinal'] for r in routes))
        self.assertTrue(all(not inbound['excludeFromSub'] for inbound in self.api.inbounds))
        self.assertFalse(self.apply())
        self.params['migrate_single_clients'] = False
        self.api.clients['alice'].update(enable=False, expiryTime=123, comment='changed in UI', inboundIds=[2])
        expected = copy.deepcopy(self.api.clients)
        self.assertFalse(self.apply())
        self.assertEqual(self.api.clients, expected)
        del self.api.clients['alice']
        self.assertFalse(self.apply())
        self.assertNotIn('alice', self.api.clients)

    def test_auto_is_opt_in_and_published_only_after_gateway_is_ready(self):
        self.params['migrate_single_clients'] = True
        self.apply()
        self.params.update(migrate_single_clients=False, defer_new_auto=True)
        endpoint = self.params['ingress_endpoints'][0]
        endpoint['auto_selector'] = 16420
        endpoint['aliases'] = [dict(address='alias.example.test', port=8443, remark='alias',
                                    display_country='Alias')]
        self.apply()
        def auto_profiles():
            return [(p['dest'], p['remark'], p['vlessRoute']) for ib in self.api.inbounds
                    for p in ib['streamSettings']['externalProxy'] if p['remark'].endswith(' -> Auto')]
        self.assertEqual(auto_profiles(), [])
        self.params['defer_new_auto'] = False
        self.assertTrue(self.apply())
        self.assertEqual(auto_profiles(), [('in.example.test', 'Russia -> Auto', '16420'),
                                          ('alias.example.test', 'Alias -> Auto', '16420')])
        self.params['defer_new_auto'] = True
        self.assertFalse(self.apply())
        del endpoint['auto_selector']
        self.assertTrue(self.apply())
        self.assertEqual(auto_profiles(), [])

    def test_auto_selector_validation(self):
        for auto in [True, 16383, 20480, 16385, '16420']:
            with self.subTest(auto=auto), self.assertRaises(panel.PanelError):
                self.params['ingress_endpoints'][0]['auto_selector'] = auto
                panel.validate(self.params)
        self.params['ingress_endpoints'][0]['auto_selector'] = 16420
        self.params['exit_countries']['west'] = 'Auto'
        with self.assertRaises(panel.PanelError):
            panel.validate(self.params)

    def test_fresh_install_leaves_client_creation_to_panel(self):
        self.api.clients = {}
        self.api.inbounds = []
        self.assertTrue(self.apply())
        self.assertFalse(self.api.clients)
        self.assertFalse(self.apply())
        self.params['ingress_endpoints'][0]['advertise'] = False
        self.assertTrue(self.apply())
        self.assertTrue(self.api.inbounds[0]['excludeFromSub'])

    def test_refuse_ambiguous_migration_before_writes(self):
        cases = (
            'owner uuid', 'child token', 'foreign child', 'child links', 'unknown managed link',
            'link credential', 'link endpoint', 'unexpected child', 'masked collision', 'policy drift', 'membership drift',
        )
        for case in cases:
            with self.subTest(case=case):
                self.params = config()
                self.api = MemoryPanel(self.params, panel.validate(self.params))
                self.params['migrate_single_clients'] = True
                child = self.api.clients['alice--west']
                link = self.api.links['alice'][-1]
                if case == 'owner uuid':
                    self.api.clients['alice']['uuid'] = str(uuid.UUID(int=6))
                elif case == 'child token':
                    child['subId'] = 'operator-token'
                elif case == 'foreign child':
                    child['comment'] = 'human managed'
                elif case == 'child links':
                    self.api.links['alice--west'] = [self.api.operator_link]
                elif case == 'unknown managed link':
                    link['namePrefix'] = panel.LINK_PREFIX + 'unexpected'
                elif case == 'link credential':
                    link['value'] = 'vless://wrong@in.example.test:443'
                elif case == 'link endpoint':
                    link['value'] = link['value'].replace('in.example.test', 'wrong.test')
                elif case == 'unexpected child':
                    self.api.clients['removed--east'] = dict(child, email='removed--east',
                                                             comment=panel.comment_for('east'), uuid=str(uuid.UUID(int=8)))
                elif case == 'masked collision':
                    self.api.clients['operator']['uuid'] = '00000000-0000-4555-0000-000000000001'
                elif case == 'policy drift':
                    child['enable'] = False
                elif case == 'membership drift':
                    child['inboundIds'] = [2]
                with self.assertRaises(panel.PanelError):
                    self.apply()
                self.assertEqual(self.api.mutations, [])

    def test_migration_preserves_original_exit_entitlements(self):
        self.params['migrate_single_clients'] = True
        self.params['users'] = self.params['users'][:1]
        del self.api.clients['alice--west']
        del self.api.links['alice'][-1]
        with self.assertRaisesRegex(panel.PanelError, 'grant exits'):
            self.apply()
        self.assertEqual(self.api.mutations, [])

    def test_renamed_ingresses_cannot_bypass_migration_preflight(self):
        for endpoint in self.params['ingress_endpoints']:
            endpoint['remark'] += '-new'
        self.params['migrate_single_clients'] = False
        with self.assertRaisesRegex(panel.PanelError, 'populated grouped'):
            self.apply()
        self.assertEqual(self.api.mutations, [])

    def test_unrelated_retired_directory_membership_survives_reconcile(self):
        self.params['migrate_single_clients'] = True
        self.apply()
        retired = copy.deepcopy(self.api.inbounds[0])
        retired.update(id=3, remark=panel.DIRECTORY + ':retired', enable=False, excludeFromSub=True,
                       port=20003, streamSettings={'externalProxy': []})
        self.api.inbounds.append(retired)
        self.api.clients['operator']['inboundIds'].append(3)
        self.params['migrate_single_clients'] = False
        self.assertFalse(self.apply())
        self.assertEqual(self.api.clients['operator']['inboundIds'], [2, 3])

    def test_migration_input_guards(self):
        invalid = [
            dict(route_selectors={'west': 0, 'east': 16385}),
            dict(route_selectors={'west': 16384, 'east': 16384}),
            dict(route_selectors={'west': '16384', 'east': 16385}),
            dict(exit_countries={'west': 'Germany'}),
            dict(exit_countries={'west': 'Germany', 'east': 'Germany'}),
            dict(client_mode='grouped', migrate_single_clients=True),
        ]
        for update in invalid:
            with self.subTest(keys=list(update)):
                params = dict(config(), **update)
                with self.assertRaises(panel.PanelError):
                    panel.validate(params)

    def test_partial_delete_retry(self):
        self.params['migrate_single_clients'] = True
        original_call = self.api.call

        def interrupted(path, data=None):
            if '/clients/del/' in path:
                self.api.clients['alice--west']['inboundIds'] = [2]
                raise panel.PanelError('partial upstream detach')
            return original_call(path, data)

        self.api.call = interrupted
        with self.assertRaisesRegex(panel.PanelError, 'partial upstream'):
            self.apply()
        self.assertEqual(self.api.links['alice'], [self.api.operator_link])
        self.api.call = original_call
        self.assertTrue(self.apply())
        self.assertEqual(set(self.api.clients), {'alice', 'operator'})
        self.assertFalse(self.apply())

    def test_failed_native_publication_preserves_old_links_and_children(self):
        self.params['migrate_single_clients'] = True
        old_links = copy.deepcopy(self.api.links)
        original_call = self.api.call

        def missing_routes(path, data=None):
            if '/clients/links/' in path:
                return ['vless://bad@in.example.test:443#unrouted']
            return original_call(path, data)

        self.api.call = missing_routes
        with self.assertRaisesRegex(panel.PanelError, 'native VLESS route'):
            self.apply()
        self.assertEqual(self.api.links, old_links)
        self.assertIn('alice--west', self.api.clients)
        self.api.call = original_call
        self.assertTrue(self.apply())
        self.assertFalse(self.apply())

    def test_new_directory_attachment_retries_and_respects_panel_memberships(self):
        self.params['migrate_single_clients'] = True
        self.apply()
        self.params['migrate_single_clients'] = False
        third = dict(self.params['ingress_endpoints'][1], remark='in-fr', address='fr.example.test', display_country='France')
        self.params['ingress_endpoints'].append(third)
        original_call = self.api.call

        def interrupted(path, data=None):
            if path.endswith('/clients/bulkAttach'):
                raise panel.PanelError('bulk attach unavailable')
            return original_call(path, data)

        self.api.call = interrupted
        with self.assertRaisesRegex(panel.PanelError, 'bulk attach unavailable'):
            self.apply()
        new_directory = self.api.inbounds[-1]
        self.assertEqual(new_directory['streamSettings'][panel.ATTACH_FROM], [1, 2])
        self.api.call = original_call
        self.assertTrue(self.apply())
        self.assertEqual(self.api.clients['alice']['inboundIds'], [1, 2, 3])
        self.assertEqual(self.api.clients['operator']['inboundIds'], [2])
        self.assertNotIn(panel.ATTACH_FROM, self.api.inbounds[-1]['streamSettings'])
        self.api.clients['alice']['inboundIds'] = [1, 2]
        self.assertFalse(self.apply())
        self.assertEqual(self.api.clients['alice']['inboundIds'], [1, 2])


if __name__ == '__main__':
    unittest.main(verbosity=2)
