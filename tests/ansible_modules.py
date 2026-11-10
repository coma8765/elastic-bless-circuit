#!/usr/bin/env python3
"""Security preflight regressions; run with the deployment's Ansible venv Python."""
import copy
import base64
import importlib.util
from pathlib import Path
import shutil
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import types
import urllib.parse
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
# tests/ansible.py is a stand runner, not the installed Ansible package.
sys.path = [entry for entry in sys.path if Path(entry or '.').resolve() != ROOT / 'tests']


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy/ansible/library' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


tls = load('vless_tls_check')
panel = load('vless_panel')


class LocalModule:
    check_mode = True

    def __init__(self, cert, key, hostname):
        self.params = {'cert_path': str(cert), 'key_path': str(key), 'hostname': hostname}

    def get_bin_path(self, name, required=False):
        return shutil.which(name)

    def run_command(self, argv):
        result = subprocess.run(argv, text=True, capture_output=True)
        return result.returncode, result.stdout, result.stderr


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for real certificate fixtures')
class TLSPreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='vless-tls-module-')
        cls.root = Path(cls.directory.name)
        for name, days in [('valid', 3), ('other', 3), ('short', 1)]:
            cls.command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256',
                         '-nodes', '-days', str(days), '-subj', '/CN=ignored.example.com',
                         '-addext', 'subjectAltName=DNS:node.example.com,DNS:*.example.net,IP:127.0.0.1',
                         '-keyout', str(cls.root / (name + '.key')),
                         '-out', str(cls.root / (name + '.crt'))])
            (cls.root / (name + '.key')).chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @staticmethod
    def command(argv):
        result = subprocess.run(argv, capture_output=True)
        if result.returncode:
            raise RuntimeError('certificate fixture generation failed')

    def fixture(self, cert='valid', key='valid', hostname='node.example.com'):
        return LocalModule(self.root / (cert + '.crt'), self.root / (key + '.key'), hostname)

    def test_valid_pair_is_read_only_in_check_mode(self):
        paths = [self.root / 'valid.crt', self.root / 'valid.key']
        before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
        result = tls.verify(self.fixture())
        self.assertEqual(result['changed'], False)
        self.assertEqual(result['valid'], True)
        self.assertEqual(before, [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths])

    def test_wrong_hostname_rejected_even_when_common_name_matches(self):
        with self.assertRaisesRegex(tls.CertificateError, 'SAN'):
            tls.verify(self.fixture(hostname='ignored.example.com'))

    def test_mismatched_private_key_rejected(self):
        with self.assertRaisesRegex(tls.CertificateError, 'key-pair'):
            tls.verify(self.fixture(key='other'))

    def test_insufficient_remaining_validity_rejected(self):
        with self.assertRaisesRegex(tls.CertificateError, '24 hours'):
            tls.verify(self.fixture(cert='short', key='short'))

    def test_future_certificate_rejected(self):
        with mock.patch.object(tls.time, 'time', return_value=time.time() - 86400):
            with self.assertRaisesRegex(tls.CertificateError, 'not started'):
                tls.verify(self.fixture())

    def test_group_readable_private_key_rejected(self):
        target = self.root / 'group-readable.key'
        shutil.copyfile(self.root / 'valid.key', target)
        target.chmod(0o640)
        with self.assertRaisesRegex(tls.CertificateError, 'permissions'):
            tls.verify(LocalModule(self.root / 'valid.crt', target, 'node.example.com'))

    def test_missing_key_rejected(self):
        with self.assertRaisesRegex(tls.CertificateError, 'exist'):
            tls.verify(self.fixture(key='missing'))

    def test_ip_requires_ip_san_and_wildcard_matches_one_label(self):
        self.assertTrue(tls.verify(self.fixture(hostname='127.0.0.1'))['valid'])
        self.assertTrue(tls.verify(self.fixture(hostname='one.example.net'))['valid'])
        with self.assertRaisesRegex(tls.CertificateError, 'SAN'):
            tls.verify(self.fixture(hostname='two.one.example.net'))
        self.assertFalse(tls.identity_matches({'subjectAltName': [('DNS', '127.0.0.1')]}, '127.0.0.1'))
        self.assertFalse(tls.dns_matches('part*.example.net', 'partial.example.net'))


class PanelPreflight(unittest.TestCase):
    def fixture(self):
        return {'url': 'http://127.0.0.1:2053', 'directory_port': 14443, 'subscription_port': 2096,
                'users': [{'email': 'alice', 'uuid': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                           'sub_id': 'test-subscription', 'exit': 'out-a', 'enabled': True}],
                'ingress_endpoints': [{'address': 'node.example.com', 'port': 443,
                                       'remark': 'in', 'security': 'tls'}]}

    def test_remote_cleartext_and_embedded_credentials_rejected(self):
        for url in ['http://192.0.2.1:2053', 'https://admin:secret@example.com',
                    'https://example.com/?password=secret']:
            with self.subTest(url=url), self.assertRaises(panel.PanelError):
                params = self.fixture()
                params['url'] = url
                panel.validate(params)

    def test_duplicate_uuid_is_case_insensitive(self):
        params = self.fixture()
        second = copy.deepcopy(params['users'][0])
        second.update(email='bob', uuid=second['uuid'].upper())
        params['users'].append(second)
        with self.assertRaisesRegex(panel.PanelError, 'unique'):
            panel.validate(params)

    def test_public_tls_and_sni_are_pinned_in_advertisement(self):
        params = self.fixture()
        params['ingress_endpoints'][0]['tls_server_name'] = 'cert.example.net'
        entry = panel.validate(params)[0]
        self.assertEqual(entry['dest'], 'node.example.com')
        self.assertEqual(entry['forceTls'], 'tls')
        self.assertEqual(entry['sni'], 'cert.example.net')
        params['ingress_endpoints'][0]['security'] = 'none'
        with self.assertRaisesRegex(panel.PanelError, 'TLS'):
            panel.validate(params)

    def reality_fixture(self):
        params = self.fixture()
        params['ingress_endpoints'][0].update(
            security='reality', reality_target='www.microsoft.com:443',
            reality_server_name='www.microsoft.com', reality_short_id='0123456789abcdef',
            reality_public_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))
        return params

    def test_reality_profiles_keep_ingress_keys_out_of_control_private_settings(self):
        params = self.reality_fixture()
        proxy = panel.validate(params)[0]
        endpoint = params['ingress_endpoints'][0]
        stream = panel.directory_stream(endpoint, proxy)
        self.assertEqual(params['users'][0]['flow'], 'xtls-rprx-vision')
        reality = stream['realitySettings']
        self.assertEqual(stream['security'], 'reality')
        self.assertEqual(reality['settings']['publicKey'], endpoint['reality_public_key'])
        self.assertEqual(reality['shortIds'], [endpoint['reality_short_id']])
        self.assertEqual(reality['serverNames'], [endpoint['reality_server_name']])
        self.assertNotEqual(reality['privateKey'], endpoint['reality_public_key'])
        self.assertEqual(panel.directory_stream(endpoint, proxy, {'streamSettings': stream}), stream)

    def test_reality_rejects_mixed_profiles_or_missing_client_credentials(self):
        for field in ['reality_public_key', 'reality_short_id', 'reality_target', 'reality_server_name']:
            params = self.reality_fixture()
            del params['ingress_endpoints'][0][field]
            with self.subTest(field=field), self.assertRaises(panel.PanelError):
                panel.validate(params)
        params = self.reality_fixture()
        second = copy.deepcopy(params['ingress_endpoints'][0])
        second.update(address='another.example.com', security='tls')
        params['ingress_endpoints'].append(second)
        with self.assertRaisesRegex(panel.PanelError, 'mixed'):
            panel.validate(params)

    def test_managed_tls_rejects_vision_flow_in_its_plain_directory(self):
        params = self.fixture()
        params['users'][0]['flow'] = 'xtls-rprx-vision'
        with self.assertRaisesRegex(panel.PanelError, 'empty flow'):
            panel.validate(params)

    def test_reality_sni_rejects_ip_literals_but_target_ips_remain_valid(self):
        for address in ['1.1.1.1', '::1']:
            params = self.reality_fixture()
            params['ingress_endpoints'][0]['reality_server_name'] = address
            with self.subTest(server_name=address), self.assertRaisesRegex(panel.PanelError, 'SNI'):
                panel.validate(params)
        for target in ['1.1.1.1:443', '[2606:4700:4700::1111]:443']:
            params = self.reality_fixture()
            params['ingress_endpoints'][0]['reality_target'] = target
            self.assertEqual(len(panel.validate(params)), 1)

    def test_reality_target_rejects_url_query_and_fragment(self):
        for target in ['example.com:443?invalid=1', 'example.com:443#fragment',
                       'example.com:443?', 'example.com:443#', 'example.com:443\n']:
            params = self.reality_fixture()
            params['ingress_endpoints'][0]['reality_target'] = target
            with self.subTest(target=target), self.assertRaisesRegex(panel.PanelError, 'target'):
                panel.validate(params)

    def test_subscription_public_url_requires_an_https_origin(self):
        params = self.fixture()
        params['subscription_public_url'] = 'https://subscriptions.example.com/'
        panel.validate(params)
        self.assertEqual(params['subscription_public_url'], 'https://subscriptions.example.com')
        for url in ['http://subscriptions.example.com', 'https://admin:secret@example.com',
                    'https://example.com/sub/', 'https://example.com/?', 'https://example.com/#',
                    'https://example.com:65536', 'https://example.com\n', '']:
            params = self.fixture()
            params['subscription_public_url'] = url
            with self.subTest(url=url), self.assertRaisesRegex(panel.PanelError, 'HTTPS origin'):
                panel.validate(params)
        params = self.fixture()
        panel.validate(params)
        self.assertNotIn('subscription_public_url', params)

    def test_aliases_inherit_the_physical_tls_or_reality_profile(self):
        for fixture in [self.fixture, self.reality_fixture]:
            params = fixture()
            endpoint = params['ingress_endpoints'][0]
            endpoint['aliases'] = [{'address': 'public.example.com', 'port': 8443, 'remark': 'public'}]
            primary = panel.validate(params)[0]
            proxies = panel.endpoint_proxies(endpoint, primary)
            self.assertEqual(proxies[0], primary)
            self.assertEqual(proxies[1], dict(primary, dest='public.example.com', port=8443, remark='public'))
            if endpoint['security'] == 'reality':
                stream = panel.directory_stream(endpoint, primary)
                self.assertEqual(stream['externalProxy'], proxies)
                self.assertEqual(stream['realitySettings']['settings']['publicKey'], endpoint['reality_public_key'])

    def test_aliases_reject_collisions_and_invalid_labels_or_addresses(self):
        for override in [{'address': 'bad/path'}, {'port': 0}, {'port': 65536},
                         {'remark': ''}, {'remark': 'x' * 65}, {'remark': 'bad label'},
                         {'security': 'none'}]:
            params = self.reality_fixture()
            alias = dict(address='public.example.com', port=443, remark='public')
            alias.update(override)
            params['ingress_endpoints'][0]['aliases'] = [alias]
            with self.subTest(override=override), self.assertRaises(panel.PanelError):
                panel.validate(params)
        params = self.reality_fixture()
        first = params['ingress_endpoints'][0]
        first['aliases'] = [{'address': first['address'].upper(), 'port': first['port'], 'remark': 'public'}]
        with self.assertRaisesRegex(panel.PanelError, 'unique'):
            panel.validate(params)
        for same_label in [True, False]:
            params = self.reality_fixture()
            first = params['ingress_endpoints'][0]
            first['aliases'] = [{'address': 'public.example.com', 'port': 443, 'remark': 'public'},
                                {'address': 'other.example.com' if same_label else 'PUBLIC.example.com',
                                 'port': 443, 'remark': 'public' if same_label else 'other'}]
            with self.subTest(same_label=same_label), self.assertRaisesRegex(panel.PanelError, 'unique'):
                panel.validate(params)
        params = self.reality_fixture()
        params['ingress_endpoints'][0]['aliases'] = [{'address': 'public.example.com', 'port': 443, 'remark': 'public'}]
        second = copy.deepcopy(params['ingress_endpoints'][0])
        second.update(address='public.example.com', remark='second', aliases=[])
        params['ingress_endpoints'].append(second)
        with self.assertRaisesRegex(panel.PanelError, 'unique'):
            panel.validate(params)


class CountryLabels(unittest.TestCase):
    """Country naming changes publication only, preserving directory identities."""
    def fixture(self):
        params = PanelPreflight().reality_fixture()
        countries = ['Russia', 'Czechia', 'Germany', 'Singapore']
        params['ingress_endpoints'] = [dict(params['ingress_endpoints'][0],
            remark='ingress-' + str(i), address='ingress-' + str(i) + '.example.com',
            display_country=country, aliases=[], advertise=True,
            reality_public_key=base64.urlsafe_b64encode(bytes([i + 1]) * 32).decode().rstrip('='),
            reality_short_id=('0' + str(i + 1)) * 8) for i, country in enumerate(countries)]
        params['users'] = [dict(email='owner' if i == 0 else 'owner--exit-' + str(i),
            uuid=str(uuid.UUID(int=i + 1)), sub_id='original-owner-token',
            exit='exit-' + str(i), exit_display_country=country,
            enabled=True, expiry_time=4102444800000, subscription_owner='owner')
            for i, country in enumerate(['Kyrgyzstan', 'Czechia', 'Germany', 'Singapore'])]
        panel.validate(params)
        return params

    def test_opt_in_complete_unique_labels_and_legacy_defaults(self):
        legacy = PanelPreflight().fixture()
        self.assertFalse(panel.country_labels(legacy)[0])
        params = self.fixture()
        enabled, ingress, exits = panel.country_labels(params)
        self.assertTrue(enabled)
        self.assertEqual(len(ingress), 4)
        self.assertEqual(set(exits.values()), {'Kyrgyzstan', 'Czechia', 'Germany', 'Singapore'})
        for mutation in ['partial_ingress', 'partial_exit', 'duplicate_ingress', 'duplicate_exit', 'arrow', 'control', 'oversize', 'whitespace', 'all_hidden', 'string_advertise']:
            bad = copy.deepcopy(params)
            if mutation == 'partial_ingress': bad['ingress_endpoints'][0]['display_country'] = ''
            elif mutation == 'partial_exit': bad['users'][0]['exit_display_country'] = ''
            elif mutation == 'duplicate_ingress': bad['ingress_endpoints'][0]['display_country'] = 'Germany'
            elif mutation == 'duplicate_exit': bad['users'][0]['exit_display_country'] = 'Germany'
            elif mutation == 'arrow': bad['ingress_endpoints'][0]['display_country'] = 'A -> B'
            elif mutation == 'control': bad['ingress_endpoints'][0]['display_country'] = 'A\nB'
            elif mutation == 'oversize': bad['ingress_endpoints'][0]['display_country'] = 'x' * 65
            elif mutation == 'whitespace': bad['ingress_endpoints'][0]['display_country'] = ' Russia'
            elif mutation == 'all_hidden':
                for endpoint in bad['ingress_endpoints']: endpoint['advertise'] = False
            else: bad['ingress_endpoints'][0]['advertise'] = 'false'
            with self.subTest(mutation=mutation), self.assertRaises(panel.PanelError):
                panel.validate(bad)

    def generated(self, params):
        return {user['email']: [
            'vless://' + user['uuid'] + '@' + endpoint['address'] + ':443?' +
            urllib.parse.urlencode({'security': 'reality', 'flow': 'xtls-rprx-vision',
                'sni': endpoint['reality_server_name'], 'fp': endpoint.get('reality_fingerprint', 'chrome'),
                'pbk': endpoint['reality_public_key'], 'sid': endpoint['reality_short_id']}) + '#native-label'
            for endpoint in params['ingress_endpoints']] for user in params['users']}

    def fake(self, params, operator=True):
        generated = self.generated(params)
        external = [{'kind': 'link', 'value': 'operator-kept', 'remark': 'operator',
                     'enable': True, 'expiryTime': 0, 'namePrefix': 'operator:'}] if operator else []
        state = {'external': copy.deepcopy(external), 'calls': [], 'generated': generated}
        def call(path, data=None):
            if path == '/panel/api/clients/list':
                return [dict(user, inboundIds=[1, 2, 3, 4]) for user in params['users']]
            if path.startswith('/panel/api/clients/get/'):
                return {'inboundIds': [1, 2, 3, 4], 'externalLinks': copy.deepcopy(state['external']) if path.endswith('/owner') else []}
            if path.startswith('/panel/api/clients/links/'):
                return generated[urllib.parse.unquote(path.rsplit('/', 1)[1])]
            if path == '/panel/api/clients/owner/externalLinks':
                state['calls'].append((path, copy.deepcopy(data)))
                state['external'] = copy.deepcopy(data['externalLinks'])
                return None
            raise AssertionError('unexpected mutation or lookup: ' + path)
        return types.SimpleNamespace(call=call), state, external

    def test_four_by_four_exact_labels_preserve_query_keys_and_user_state(self):
        params = self.fixture()
        before = copy.deepcopy(params['users'])
        api, state, operator = self.fake(params)
        module = types.SimpleNamespace(check_mode=False, params=params)
        self.assertTrue(panel.reconcile_subscription_links(module, api, [1, 2, 3, 4]))
        owned = state['external'][len(operator):]
        self.assertEqual(len(owned), 16)
        self.assertEqual(state['external'][:len(operator)], operator)
        self.assertEqual({row['remark'] for row in owned}, {
            endpoint['display_country'] + ' -> ' + user['exit_display_country']
            for endpoint in params['ingress_endpoints'] for user in params['users']})
        originals = {link.split('#', 1)[0] for links in state['generated'].values() for link in links}
        self.assertEqual({row['value'].split('#', 1)[0] for row in owned}, originals)
        for row in owned:
            self.assertEqual(urllib.parse.unquote(urllib.parse.urlsplit(row['value']).fragment), row['remark'])
        self.assertEqual(params['users'], before)
        self.assertFalse(panel.reconcile_subscription_links(module, api, [1, 2, 3, 4]))
        self.assertEqual(len(state['calls']), 1)

    def test_hidden_ingress_is_synchronized_but_not_published_until_enabled(self):
        params = self.fixture()
        before = copy.deepcopy(params['users'])
        for endpoint in params['ingress_endpoints'][1:]: endpoint['advertise'] = False
        api, state, _ = self.fake(params, operator=False)
        module = types.SimpleNamespace(check_mode=False, params=params)
        self.assertTrue(panel.reconcile_subscription_links(module, api, [1, 2, 3, 4]))
        self.assertEqual(len(state['external']), 4)
        self.assertTrue(all(urllib.parse.urlsplit(row['value']).hostname == 'ingress-0.example.com' for row in state['external']))
        for endpoint in params['ingress_endpoints']: endpoint['advertise'] = True
        self.assertTrue(panel.reconcile_subscription_links(module, api, [1, 2, 3, 4]))
        self.assertEqual(len(state['external']), 16)
        self.assertEqual(params['users'], before)
        self.assertFalse(panel.reconcile_subscription_links(module, api, [1, 2, 3, 4]))

    def test_disabled_group_disables_all_owned_links_and_preserves_operator_rows(self):
        params = self.fixture()
        api, state, operator = self.fake(params)
        module = types.SimpleNamespace(check_mode=False, params=params)
        panel.reconcile_subscription_links(module, api, [1, 2, 3, 4])
        for user in params['users']: user['enabled'] = False
        before = copy.deepcopy(params['users'])
        self.assertTrue(panel.reconcile_subscription_links(module, api, [1, 2, 3, 4]))
        self.assertEqual(len(state['external']), 17)
        self.assertEqual(state['external'][0], operator[0])
        self.assertTrue(all(not row['enable'] for row in state['external'][1:]))
        self.assertEqual(params['users'], before)

    def test_unknown_generated_endpoint_rejected_before_external_link_mutation(self):
        params = self.fixture()
        api, state, _ = self.fake(params)
        state['generated']['owner'][0] = state['generated']['owner'][0].replace('ingress-0.example.com', 'unexpected.example.com')
        with self.assertRaisesRegex(panel.PanelError, 'outside'):
            panel.reconcile_subscription_links(types.SimpleNamespace(check_mode=False, params=params), api, [1, 2, 3, 4])
        self.assertEqual(state['calls'], [])

    def test_country_mode_suppresses_native_directory_profiles_without_renaming(self):
        params = self.fixture()
        params['users'] = []
        captured = []
        def call(path, data=None):
            if path in ['/panel/api/inbounds/list', '/panel/api/clients/list']: return []
            if path == '/panel/api/inbounds/add':
                captured.append(copy.deepcopy(data)); return {'id': len(captured)}
            if path == '/panel/api/setting/all': return {'subEnable': True, 'subPort': 2096, 'subPath': '/sub/', 'subListen': '0.0.0.0'}
            raise AssertionError('unexpected panel operation: ' + path)
        result = panel.reconcile(types.SimpleNamespace(check_mode=False, params=params), types.SimpleNamespace(call=call), panel.validate(params))
        self.assertEqual(len(captured), 4)
        self.assertTrue(all(row['excludeFromSub'] for row in captured))
        self.assertEqual({row['remark'] for row in captured}, {panel.DIRECTORY + ':' + e['remark'] for e in params['ingress_endpoints']})
        self.assertEqual(len({row['streamSettings']['realitySettings']['settings']['publicKey'] for row in captured}), 4)
        self.assertEqual(set(result['inbound_ids']), {e['remark'] for e in params['ingress_endpoints']})

    def migration_panel(self):
        params = self.fixture()
        params['users'] = []
        params['ingress_endpoints'] = params['ingress_endpoints'][:1]
        proxies = panel.validate(params)
        endpoint = params['ingress_endpoints'][0]
        existing = {'id': 7, 'remark': panel.DIRECTORY + ':' + endpoint['remark'],
                    'listen': '127.0.0.1', 'port': 14443, 'protocol': 'vless',
                    'enable': True, 'excludeFromSub': False, 'disableFlow': False,
                    'expiryTime': 0, 'total': 0, 'sniffing': {'enabled': False},
                    'settings': {'clients': [], 'decryption': 'none'},
                    'streamSettings': panel.directory_stream(endpoint, proxies[0])}
        state = {'inbound': existing, 'events': []}
        def call(path, data=None):
            if path == '/panel/api/inbounds/list':
                state['events'].append('read_inbounds')
                return [copy.deepcopy(state['inbound'])]
            if path == '/panel/api/clients/list': return []
            if path == '/panel/api/inbounds/update/7':
                state['events'].append(('update', copy.deepcopy(data)))
                state['inbound'] = copy.deepcopy(data)
                return None
            if path == '/panel/api/setting/all': return {'subEnable': True, 'subPort': 2096, 'subPath': '/sub/', 'subListen': '0.0.0.0'}
            raise AssertionError('unexpected mutation: ' + path)
        return params, proxies, types.SimpleNamespace(call=call), state

    def test_existing_native_entries_are_hidden_only_after_links_and_fresh_client_read(self):
        params, proxies, api, state = self.migration_panel()
        fresh_client = {'id': str(uuid.UUID(int=91)), 'email': 'newly-attached'}
        def installed(*args):
            state['events'].append('links_installed')
            state['inbound']['settings']['clients'].append(fresh_client)
            return True
        module = types.SimpleNamespace(check_mode=False, params=params)
        with mock.patch.object(panel, 'reconcile_subscription_links', side_effect=installed):
            self.assertTrue(panel.reconcile(module, api, proxies)['changed'])
        events = state['events']
        link_index = events.index('links_installed')
        hide_index = next(i for i, event in enumerate(events) if isinstance(event, tuple) and event[1]['excludeFromSub'])
        self.assertLess(link_index, hide_index)
        self.assertIn('read_inbounds', events[link_index + 1:hide_index])
        self.assertEqual(state['inbound']['settings']['clients'], [fresh_client])
        with mock.patch.object(panel, 'reconcile_subscription_links', return_value=False):
            self.assertFalse(panel.reconcile(module, api, proxies)['changed'])
        params['ingress_endpoints'][0]['display_country'] = ''
        with mock.patch.object(panel, 'reconcile_subscription_links', return_value=False):
            self.assertTrue(panel.reconcile(module, api, panel.validate(params))['changed'])
            self.assertFalse(state['inbound']['excludeFromSub'])
            self.assertEqual(state['inbound']['settings']['clients'], [fresh_client])
            self.assertFalse(panel.reconcile(module, api, panel.validate(params))['changed'])

    def test_failed_static_link_install_leaves_existing_native_subscription_visible(self):
        params, proxies, api, state = self.migration_panel()
        with mock.patch.object(panel, 'reconcile_subscription_links', side_effect=panel.PanelError('fixture link failure')):
            with self.assertRaisesRegex(panel.PanelError, 'fixture link failure'):
                panel.reconcile(types.SimpleNamespace(check_mode=False, params=params), api, proxies)
        self.assertFalse(state['inbound']['excludeFromSub'])
        self.assertFalse(any(isinstance(event, tuple) and event[1]['excludeFromSub'] for event in state['events']))


    def test_missing_published_endpoint_fails_before_external_mutation_or_native_hide(self):
        params = self.fixture()
        api, state, operator = self.fake(params)
        state['generated']['owner'].pop()
        link_module = types.SimpleNamespace(check_mode=False, params=params)
        migration_params, proxies, migration_api, migration_state = self.migration_panel()
        original = panel.reconcile_subscription_links
        def incomplete_generated_links(*unused):
            return original(link_module, api, [1, 2, 3, 4])
        with mock.patch.object(panel, 'reconcile_subscription_links', side_effect=incomplete_generated_links):
            with self.assertRaises(panel.PanelError):
                panel.reconcile(types.SimpleNamespace(check_mode=False, params=migration_params),
                                migration_api, proxies)
        self.assertEqual(state['calls'], [])
        self.assertEqual(state['external'], operator)
        self.assertFalse(migration_state['inbound']['excludeFromSub'])
        self.assertFalse(any(isinstance(event, tuple) and event[1]['excludeFromSub']
                             for event in migration_state['events']))


class NodeResourceOmission(unittest.TestCase):
    """Evaluate actual role limits through local Ansible without any engine call."""
    def test_optional_limits_omit_cleanly_and_invalid_bounds_fail_before_engine(self):
        import yaml
        import json
        node = ROOT / 'deploy/ansible/roles/node/tasks'
        limits = [task for task in yaml.safe_load((node / 'main.yml').read_text())
                  if task['name'] in ['Validate optional Docker node resource limits',
                                      'Validate Docker node memory and combined memory-swap bounds']]
        self.assertEqual(len(limits), 2)
        docker = yaml.safe_load((node / 'container-docker.yml').read_text())[0]['community.docker.docker_container']
        expressions = {key: docker[key] for key in ['memory', 'memory_swap', 'pids_limit']}
        with tempfile.TemporaryDirectory(prefix='resource-contract-', dir=ROOT / '.local') as directory:
            work = Path(directory)
            inventory = work / 'inventory.json'
            inventory.write_text(json.dumps({'all': {'hosts': {'localhost': {
                'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable,
                'ansible_remote_tmp': str(work / 'remote'), 'container_engine': 'docker'}}}}))
            output = work / 'rendered.json'
            playbook = work / 'play.yml'
            tasks = copy.deepcopy(limits) + [
                {'name': 'Resolve actual module arguments', 'ansible.builtin.set_fact': {'resolved': expressions}},
                {'name': 'Inspect omitted arguments', 'ansible.builtin.copy': {'content': '{{ resolved | to_json }}', 'dest': str(output), 'mode': '0600'}}]
            playbook.write_text(yaml.safe_dump([{'hosts': 'localhost', 'gather_facts': False, 'tasks': tasks}], sort_keys=False))
            cases = [({}, {}), ({'node_memory': '128m', 'node_memory_swap': '256m', 'node_pids_limit': 128},
                               {'memory': '128m', 'memory_swap': '256m', 'pids_limit': 128}),
                     ({'node_memory_swap': '256m'}, None),
                     ({'node_memory': '128m', 'node_memory_swap': '64m'}, None),
                     ({'node_pids_limit': True}, None)]
            for variables, expected in cases:
                with self.subTest(variables=variables):
                    vars_path = work / 'vars.json'; vars_path.write_text(json.dumps(variables))
                    result = subprocess.run([str(ROOT / 'scripts/ansible.sh'), '-i', str(inventory), '-e', '@' + str(vars_path), str(playbook)],
                                            cwd=ROOT, text=True, capture_output=True, timeout=45)
                    if expected is None:
                        self.assertNotEqual(result.returncode, 0)
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(json.loads(output.read_text()), expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
