#!/usr/bin/env python3
"""Security and routing contracts, exercised against the compiled C++ renderer.

These tests start only disposable renderer containers, not the integration stand.
Set NODE_IMAGE to validate another locally built image.
Set CONTAINER_ENGINE=docker to exercise a Docker image instead of Podman.
"""
import copy
import base64
import json
import os
import secrets
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get('NODE_IMAGE', 'localhost/vless-node:dev')
ENGINE = os.environ.get('CONTAINER_ENGINE', 'podman')
if ENGINE not in ('podman', 'docker'):
    raise RuntimeError('CONTAINER_ENGINE must be podman or docker')
USER_UUID = '11111111-1111-4111-8111-111111111111'
OTHER_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
TRANSIT_UUID = '22222222-2222-4222-8222-222222222222'


def ingress():
    return {
        'role': 'in', 'allow_insecure_lab': True,
        'listener': {'address': '0.0.0.0', 'port': 443},
        'users': [{'id': USER_UUID, 'email': 'alice-a'}],
        'routes': {'alice-a': 'out-a'},
        'exits': [{'name': 'out-a', 'address': '100.64.0.2', 'port': 8443,
                   'uuid_file': '/test/transit-uuid'}],
    }


def egress():
    return {'role': 'out', 'listener': {'address': '100.64.0.2', 'port': 8443},
            'transit_uuid_file': '/test/transit-uuid'}


def reality_ingress():
    config = ingress()
    config.pop('allow_insecure_lab')
    config['users'][0]['flow'] = 'xtls-rprx-vision'
    config['listener']['stream'] = {
        'network': 'tcp', 'security': 'reality',
        'realitySettings': {'show': False, 'target': 'www.microsoft.com:443',
                            'serverNames': ['www.microsoft.com'],
                            'shortIds': ['12345678'], 'xver': 0,
                            'private_key_file': '/test/reality-private-key'}}
    return config


class RendererContracts(unittest.TestCase):
    def mesh_port(self, config, expected=None):
        (ROOT / '.local').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.local') as directory:
            path = Path(directory)
            (path / 'config.yaml').write_text(json.dumps(config))
            result = subprocess.run(
                [ENGINE, 'run', '--rm', '--no-healthcheck', '-v', str(path) + ':/test:ro',
                 IMAGE, 'node-agent', 'mesh-port', '/test/config.yaml'],
                text=True, capture_output=True, timeout=30)
            if expected is None:
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr.strip(), 'Invalid mesh port requires a diagnostic')
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), str(expected))

    def test_mesh_udp_port_defaults_without_a_data_plane_role(self):
        self.mesh_port({}, 41641)
        self.mesh_port({'panel_settings': {'port': 2053}, 'mesh': {'enabled': True}}, 41641)

    def test_mesh_udp_port_uses_yaml_and_validates_its_bounds(self):
        for value in [1, 41642, 65535]:
            with self.subTest(port=value):
                self.mesh_port({'mesh': {'udp_port': value}}, value)
        for value in [0, -1, 65536, 'not-a-port', True, 1.5]:
            with self.subTest(port=value):
                self.mesh_port({'mesh': {'udp_port': value}})

    def render(self, config, valid=True, transit=TRANSIT_UUID, xray_validate=False,
               reality_key=None):
        (ROOT / '.local').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.local') as directory:
            path = Path(directory)
            (path / 'config.yaml').write_text(json.dumps(config))
            (path / 'transit-uuid').write_text(transit)
            if reality_key is None:
                reality_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            (path / 'reality-private-key').write_text(reality_key)
            (path / 'reality-private-key').chmod(0o600)
            command = [ENGINE, 'run', '--rm', '-v', str(path) + ':/test:ro',
                       IMAGE, 'node-agent', 'render', '/test/config.yaml']
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode == 0, valid,
                             'Renderer result did not match expected validity: ' + result.stderr)
            if not valid:
                self.assertTrue(result.stderr.strip(), 'A rejected configuration needs a diagnostic')
                return None
            rendered = json.loads(result.stdout)
            if xray_validate:
                (path / 'xray.json').write_text(result.stdout)
                check = subprocess.run(
                    [ENGINE, 'run', '--rm', '-v', str(path) + ':/test:ro',
                     IMAGE, 'xray', 'run', '-test', '-config', '/test/xray.json'],
                    text=True, capture_output=True, timeout=30)
                self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            return rendered

    def test_ingress_defaults_to_deny_without_internet_outbound(self):
        config = self.render(ingress(), xray_validate=True)
        self.assertEqual(config['outbounds'][0]['protocol'], 'blackhole')
        self.assertNotIn('freedom', [item['protocol'] for item in config['outbounds']])
        self.assertEqual(config['routing']['rules'], [
            {'type': 'field', 'user': ['alice-a'], 'outboundTag': 'out-a'}])

    def test_distinct_client_credentials_select_distinct_exits(self):
        config = ingress()
        config['users'].append({'id': OTHER_UUID, 'email': 'alice-b'})
        config['routes']['alice-b'] = 'out-b'
        second = copy.deepcopy(config['exits'][0])
        second.update(name='out-b', address='100.64.0.3')
        config['exits'].append(second)
        result = self.render(config, xray_validate=True)
        self.assertEqual({tuple(r['user']): r['outboundTag']
                          for r in result['routing']['rules']},
                         {('alice-a',): 'out-a', ('alice-b',): 'out-b'})
        self.assertEqual([u['id'] for u in result['inbounds'][0]['settings']['clients']],
                         [USER_UUID, OTHER_UUID])

    def test_transit_alias_resolution_is_pinned_to_operator_mesh_addresses(self):
        config = ingress()
        second = copy.deepcopy(config['exits'][0])
        second.update(name='out-b', address='100.64.0.3')
        config['exits'].append(second)
        result = self.render(config, xray_validate=True)
        for outbound, expected_address in zip(result['outbounds'][1:],
                                               ['100.64.0.2', '100.64.0.3']):
            alias = outbound['settings']['vnext'][0]['address']
            self.assertNotEqual(alias, expected_address)
            self.assertEqual(result['dns']['hosts'][alias], expected_address)
            self.assertEqual(outbound['streamSettings']['sockopt']['domainStrategy'],
                             'UseIPv4')

    def test_mesh_transit_is_bound_to_tailscale_interface(self):
        config = ingress()
        config['mesh'] = {'enabled': True}
        result = self.render(config, xray_validate=True)
        self.assertEqual(result['outbounds'][1]['streamSettings']['sockopt']['interface'],
                         'tailscale0')

    def test_quoted_numeric_yaml_strings_remain_strings(self):
        # json.dumps emits quoted YAML scalars; yaml-cpp must retain that tag.
        config = reality_ingress()
        config['users'][0]['email'] = '12345678'
        config['routes'] = {'12345678': 'out-a'}
        config['listener']['stream']['realitySettings']['serverNames'] = ['true']
        result = self.render(config)
        self.assertEqual(result['inbounds'][0]['settings']['clients'][0]['email'], '12345678')
        settings = result['inbounds'][0]['streamSettings']['realitySettings']
        self.assertEqual(settings['shortIds'], ['12345678'])
        self.assertEqual(settings['serverNames'], ['true'])

    def test_reality_key_file_and_vision_render_a_valid_server_config(self):
        config = reality_ingress()
        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
        result = self.render(config, xray_validate=True, reality_key=key)
        inbound = result['inbounds'][0]
        self.assertEqual(inbound['settings']['clients'][0]['flow'], 'xtls-rprx-vision')
        reality = inbound['streamSettings']['realitySettings']
        self.assertEqual(reality['privateKey'], key)
        self.assertNotIn('private_key_file', reality)
        self.assertEqual(reality['serverNames'], ['www.microsoft.com'])
        self.assertEqual(result['outbounds'][1]['streamSettings']['security'], 'none')
        self.assertNotIn('flow', result['outbounds'][1]['settings']['vnext'][0]['users'][0])

    def test_reality_rejects_missing_inline_or_invalid_private_key(self):
        config = reality_ingress()
        del config['listener']['stream']['realitySettings']['private_key_file']
        self.render(config, valid=False)
        config = reality_ingress()
        config['listener']['stream']['realitySettings']['privateKey'] = 'inline-not-allowed'
        self.render(config, valid=False)
        self.render(reality_ingress(), valid=False, reality_key='invalid')

    def test_reality_rejects_invalid_short_ids_and_server_names(self):
        for ids in [[], ['abc'], ['g0'], ['11' * 9], [12345678], ['aa', 'aa00']]:
            with self.subTest(short_ids=ids):
                config = reality_ingress()
                config['listener']['stream']['realitySettings']['shortIds'] = ids
                self.render(config, valid=False)
        for names in [[], [''], ['*.example.com'], ['bad name'], [True],
                      ['1.1.1.1'], ['::1']]:
            with self.subTest(server_names=names):
                config = reality_ingress()
                config['listener']['stream']['realitySettings']['serverNames'] = names
                self.render(config, valid=False)

    def test_reality_target_accepts_ip_addresses_with_a_dns_server_name(self):
        for target in ['1.1.1.1:443', '[2606:4700:4700::1111]:443']:
            with self.subTest(target=target):
                config = reality_ingress()
                config['listener']['stream']['realitySettings']['target'] = target
                self.render(config, xray_validate=True)

    def test_reality_rejects_invalid_target_or_non_raw_transport(self):
        for target in ['', 'example.com', 'https://example.com:443', 'example.com:0',
                       'example.com:65536', 'example.com:not-a-port']:
            with self.subTest(target=target):
                config = reality_ingress()
                config['listener']['stream']['realitySettings']['target'] = target
                self.render(config, valid=False)
        config = reality_ingress()
        config['listener']['stream']['network'] = 'ws'
        self.render(config, valid=False)

    def test_public_and_transit_credentials_remain_separate(self):
        result = self.render(ingress())
        self.assertEqual(result['inbounds'][0]['settings']['clients'][0]['id'], USER_UUID)
        self.assertEqual(result['outbounds'][1]['settings']['vnext'][0]['users'][0]['id'],
                         TRANSIT_UUID)
        self.assertNotIn(USER_UUID, json.dumps(result['outbounds']))
        self.assertNotIn(TRANSIT_UUID, json.dumps(result['inbounds']))

    def test_public_plaintext_requires_explicit_lab_opt_in(self):
        config = ingress()
        del config['allow_insecure_lab']
        self.render(config, valid=False)

    def test_unrecognized_role_is_rejected(self):
        config = ingress()
        config['role'] = 'unknown'
        self.render(config, valid=False)

    def test_every_user_requires_an_explicit_existing_route(self):
        for routes in [{}, {'alice-a': 'missing-exit'}]:
            with self.subTest(routes=routes):
                config = ingress()
                config['routes'] = routes
                self.render(config, valid=False)

    def test_duplicate_uuid_or_email_is_rejected(self):
        for user in [{'id': USER_UUID, 'email': 'alice-b'},
                     {'id': OTHER_UUID, 'email': 'alice-a'}]:
            with self.subTest(user=user):
                config = ingress()
                config['users'].append(user)
                config['routes']['alice-b'] = 'out-a'
                self.render(config, valid=False)

    def test_uuid_duplicate_check_is_case_insensitive(self):
        config = ingress()
        config['users'] = [{'id': OTHER_UUID, 'email': 'alice-a'},
                           {'id': OTHER_UUID.upper(), 'email': 'alice-b'}]
        config['routes']['alice-b'] = 'out-a'
        self.render(config, valid=False)

    def test_invalid_ports_are_rejected(self):
        for port in [0, -1, 65536]:
            with self.subTest(port=port):
                config = ingress()
                config['listener']['port'] = port
                self.render(config, valid=False)
                config = ingress()
                config['exits'][0]['port'] = port
                self.render(config, valid=False)

    def test_empty_reserved_or_missing_exit_definitions_are_rejected(self):
        for exits in [[], {}, [{'name': ''}], [{'name': 'block'}]]:
            with self.subTest(exits=exits):
                config = ingress()
                if isinstance(exits, list) and exits:
                    config['exits'][0]['name'] = exits[0]['name']
                else:
                    config['exits'] = exits
                self.render(config, valid=False)

    def test_user_set_must_be_an_array(self):
        for users in [{}, 'alice-a', 1]:
            with self.subTest(users=users):
                config = ingress()
                config['users'] = users
                self.render(config, valid=False)

    def test_vision_flow_is_preserved_and_requires_compatible_transport(self):
        config = ingress()
        config['users'][0]['flow'] = 'xtls-rprx-vision'
        self.render(config, valid=False)
        config['listener']['stream'] = {'network': 'tcp', 'security': 'tls'}
        result = self.render(config)
        self.assertEqual(result['inbounds'][0]['settings']['clients'][0]['flow'],
                         'xtls-rprx-vision')
        config['listener']['stream']['network'] = 'ws'
        self.render(config, valid=False)
        config['users'][0]['flow'] = 'unknown-flow'
        self.render(config, valid=False)

    def test_missing_or_empty_identity_is_rejected(self):
        for user in [{'id': USER_UUID}, {'email': 'alice-a'},
                     {'id': USER_UUID, 'email': ''}, {'id': '', 'email': 'alice-a'}]:
            with self.subTest(user=user):
                config = ingress()
                config['users'] = [user]
                self.render(config, valid=False)

    def test_duplicate_exit_names_are_rejected(self):
        config = ingress()
        config['exits'].append(copy.deepcopy(config['exits'][0]))
        self.render(config, valid=False)

    def test_invalid_user_and_transit_uuids_are_rejected(self):
        config = ingress()
        config['users'][0]['id'] = 'not-a-uuid'
        self.render(config, valid=False)
        self.render(ingress(), valid=False, transit='not-a-uuid')
        self.render(egress(), valid=False, transit='not-a-uuid')

    def test_empty_or_expired_user_set_leaves_no_authorized_clients(self):
        for users in [[], [{'id': USER_UUID, 'email': 'alice-a', 'expiryTime': 1}]]:
            with self.subTest(users=users):
                config = ingress()
                config['users'] = users
                result = self.render(config, xray_validate=True)
                self.assertEqual(result['inbounds'][0]['settings']['clients'], [])
                self.assertEqual(result['routing']['rules'], [])
                self.assertNotIn('freedom', [o['protocol'] for o in result['outbounds']])

    def test_exit_accepts_only_transit_identity_and_blocks_private_destinations(self):
        result = self.render(egress(), xray_validate=True)
        self.assertEqual(result['inbounds'][0]['settings']['clients'], [{'id': TRANSIT_UUID}])
        self.assertEqual(result['inbounds'][0]['listen'], '100.64.0.2')
        self.assertEqual(result['routing']['rules'], [
            {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'block'}])
        self.assertEqual(result['outbounds'][0]['protocol'], 'freedom')

    def test_exit_dns_is_opt_in_and_legacy_resolution_remains_unchanged(self):
        result = self.render(egress(), xray_validate=True)
        self.assertNotIn('dns', result)
        self.assertEqual(result['outbounds'][0], {
            'tag': 'internet', 'protocol': 'freedom', 'settings': {}})

    def test_exit_dns_cache_uses_public_ipv4_resolvers_without_weakening_policy(self):
        for servers in [['1.1.1.1'], ['1.1.1.1', '8.8.8.8', '9.9.9.9', '8.8.4.4']]:
            with self.subTest(servers=servers):
                config = egress()
                config['dns'] = {'servers': servers}
                result = self.render(config, xray_validate=True)
                self.assertEqual(result['dns'], {
                    'servers': servers, 'queryStrategy': 'UseIPv4', 'disableCache': False})
                self.assertEqual(result['outbounds'][0]['streamSettings']['sockopt']['domainStrategy'],
                                 'ForceIPv4')
                self.assertEqual(result['inbounds'][0]['settings']['clients'], [{'id': TRANSIT_UUID}])
                self.assertEqual(result['inbounds'][0]['listen'], '100.64.0.2')
                self.assertEqual(result['routing']['rules'], [
                    {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'block'}])
                self.assertEqual(result['outbounds'][1], {'tag': 'block', 'protocol': 'blackhole'})
                self.assertEqual(result['outbounds'][0]['settings'], {})

    def test_exit_dns_rejects_malformed_empty_oversized_or_duplicate_configuration(self):
        invalid = [None, [], '', '1.1.1.1', {}, {'servers': None}, {'servers': []},
                   {'servers': '1.1.1.1'}, {'servers': {'address': '1.1.1.1'}},
                   {'servers': ['1.1.1.1', '1.1.1.1']},
                   {'servers': ['1.1.1.1', '8.8.8.8', '9.9.9.9', '8.8.4.4', '1.0.0.1']},
                   {'servers': ['1.1.1.1'], 'disableCache': True}]
        for dns in invalid:
            with self.subTest(dns=dns):
                config = egress()
                config['dns'] = dns
                self.render(config, valid=False)

    def test_exit_dns_rejects_nonpublic_literals_and_external_resolution_syntax(self):
        invalid = [None, True, 1, ['1.1.1.1'], {'address': '1.1.1.1'}, '', 'localhost',
                   'https://dns.example.com/dns-query', '1.1.1.1:53', '1.1.1.01', '::1',
                   '2606:4700:4700::1111', '0.0.0.0', '10.0.0.1', '127.0.0.1',
                   '100.64.0.1', '100.127.255.254', '169.254.1.1', '172.16.0.1',
                   '172.31.255.254', '192.168.1.1', '192.0.0.1', '192.0.2.1',
                   '192.88.99.1', '198.18.0.1', '198.19.255.254', '198.51.100.1',
                   '203.0.113.1', '224.0.0.1', '239.1.2.3', '240.0.0.1', '255.255.255.255']
        for server in invalid:
            with self.subTest(server=server):
                config = egress()
                config['dns'] = {'servers': [server]}
                self.render(config, valid=False)

    def test_ingress_cannot_enable_exit_dns_or_change_pinned_mesh_resolution(self):
        config = ingress()
        config['dns'] = {'servers': ['1.1.1.1']}
        self.render(config, valid=False)

    def test_exit_binding_is_limited_to_the_mesh_cgnat_range(self):
        for address in ['0.0.0.0', '127.0.0.1', '100.1.0.2', '100.63.255.255',
                        '100.128.0.1', '192.168.1.1', '::', 'not-an-ip']:
            with self.subTest(address=address):
                config = egress()
                config['listener']['address'] = address
                self.render(config, valid=False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
