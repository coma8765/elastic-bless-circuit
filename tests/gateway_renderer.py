#!/usr/bin/env python3
"""Validate gateway policy and Auto credential boundaries in the compiled renderer."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid


class GatewayRenderer(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        self.exits = []
        for i in range(12):
            self.exits.append({'name': f'out-{i}', 'address': f'100.64.0.{i + 1}', 'port': 8000,
                               'uuid_file': self.secret(f'exit-{i}')})
        self.peer = {'name': 'ingress', 'uuid_file': self.secret('peer'), 'exits': ['out-1', 'out-10']}
        self.config = {'role': 'gateway', 'listener': {'address': '100.64.0.100', 'port': 8111},
                       'exits': self.exits,
                       'gateway': {'probe_url': 'https://probe.example/health', 'probe_interval_seconds': 5,
                                   'countries': {'DE': ['out-1', 'out-10', 'out-11'], 'US': ['out-11']},
                                   'ingresses': [self.peer]}}

    def secret(self, name, value=None):
        path = self.directory / name
        path.write_text(value or str(uuid.uuid4()))
        return str(path)

    def render(self, config, valid=True):
        path = self.directory / 'config.yaml'
        path.write_text(json.dumps(config))
        proc = subprocess.run([str(AGENT), 'render', str(path)], capture_output=True, text=True, timeout=10)
        if valid:
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(proc.stdout)
        self.assertNotEqual(proc.returncode, 0)

    def test_country_intersection_and_prefix_isolation(self):
        restricted = dict(self.peer, name='restricted', uuid_file=self.secret('restricted'), exits=['out-1'])
        self.config['gateway']['ingresses'].append(restricted)
        cfg = self.render(self.config)
        self.assertEqual(cfg['routing']['domainStrategy'], 'IPOnDemand')
        inbounds = cfg['inbounds'][0]['settings']['clients']
        rules = cfg['routing']['rules']
        self.assertEqual(rules[0]['ip'], ['geoip:private'])
        self.assertEqual(rules[0]['outboundTag'], 'block')
        self.assertEqual(rules[-1]['outboundTag'], 'block')
        self.assertEqual(len(rules), 5)
        # Keep the unused US asset in xray -test without routing any caller.
        self.assertEqual(rules[-2]['ip'], ['ext:country-geoip.dat:us'])
        self.assertEqual(rules[-2]['outboundTag'], 'block')
        balances = {b['tag']: b for b in cfg['routing']['balancers']}
        for rule, user, eligible in zip(rules[1:-2], inbounds, [['out-1', 'out-10'], ['out-1']]):
            self.assertEqual(rule['ip'], ['ext:country-geoip.dat:de'])
            self.assertEqual(rule['user'], [user['email']])
            pool = balances[rule['balancerTag']]
            self.assertEqual(pool['strategy']['type'], 'leastPing')
            self.assertEqual(pool['fallbackTag'], 'block')
            tags = [out['tag'] for out in cfg['outbounds'][1:]]
            matched = [peer['name'] for peer, tag in zip(self.exits, tags)
                       if any(tag.startswith(s) for s in pool['selector'])]
            self.assertEqual(matched, eligible)
        self.assertEqual(cfg['outbounds'][0]['protocol'], 'blackhole')
        self.assertFalse(any(o['protocol'] == 'freedom' for o in cfg['outbounds']))

    def test_rejects_unsafe_bindings_and_invalid_policy(self):
        for change in [{'probe_url': 'http://example.com/health'},
                       {'probe_url': 'https://example.com/%z'},
                       {'probe_url': 'https://user@example.com/'},
                       {'probe_interval_seconds': 0}, {'countries': {'DE': ['missing']}},
                       {'countries': {'de': ['out-1'], 'DE': ['out-2']}},
                       {'countries': {'DE': []}}, {'ingresses': [dict(self.peer, exits=[])]}]:
            with self.subTest(change=change):
                cfg = copy.deepcopy(self.config)
                cfg['gateway'].update(change)
                self.render(cfg, valid=False)
        self.config['listener']['address'] = '0.0.0.0'
        self.render(self.config, valid=False)
        self.config['listener']['address'] = '100.64.0.100'
        self.config['exits'][0]['address'] = '203.0.113.1'
        self.render(self.config, valid=False)

    def test_normalized_gateway_transit_ids_cannot_collide(self):
        value = uuid.UUID(Path(self.peer['uuid_file']).read_text())
        wire = bytearray(value.bytes)
        wire[6] ^= 1
        other = self.secret('other', str(uuid.UUID(bytes=bytes(wire))))
        self.config['gateway']['ingresses'].append(dict(self.peer, name='other', uuid_file=other))
        self.render(self.config, valid=False)

    def test_auto_and_manual_selections_remain_distinct(self):
        owner = 'dddddddd-dddd-4abc-bddd-dddddddddddd'
        cfg = {'role': 'in', 'allow_insecure_lab': True,
               'listener': {'address': '127.0.0.1', 'port': 8112}, 'exits': self.exits[:1],
               'single_client': {'selectors': {'out-0': 16385},
                                 'legacy': [{'owner': owner, 'primary': 'out-0'}]},
               'auto_gateway': {'address': '100.64.0.100', 'port': 8111, 'uuid_file': self.peer['uuid_file'],
                                'selector': 16386},
               'users': [{'id': owner}]}
        rendered = self.render(cfg)
        self.assertEqual({r['vlessRoute']: r['outboundTag'] for r in rendered['routing']['rules']},
                         {16385: 'out-0', 16386: 'auto-gateway', 0x4abc: 'out-0'})
        self.assertEqual(rendered['outbounds'][-1]['targetStrategy'], 'ForceIP')
        for collision in [16385, 0x4abc, 0, '16386']:
            with self.subTest(selector=collision):
                cfg['auto_gateway']['selector'] = collision
                self.render(cfg, valid=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--agent', type=Path, default=Path('build/ci/node-agent'))
    args, test_args = parser.parse_known_args()
    AGENT = args.agent.resolve()
    unittest.main(argv=[sys.argv[0], *test_args])
