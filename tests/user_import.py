#!/usr/bin/env python3
"""Migration contracts using synthetic users and the real local Ansible controller.

No production hosts, user exports or panel databases are accessed by this suite.
The real panel API behavior is additionally covered by tests/reality_panel.py.
"""
import copy
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path = [p for p in sys.path if Path(p or '.').resolve() != ROOT / 'tests']
spec = importlib.util.spec_from_file_location('route_contracts', ROOT / 'tests/user_routes.py')
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
routes, panel = legacy.routes, legacy.panel
EXITS = legacy.EXITS
EXPIRY = 4102444800000
IMPORTED_UUID = '12345678-1234-4234-8234-123456789abc'
IMPORTED_TOKEN = 'preserved-import-subscription-token'


def imported_user(**extra):
    result = {'email': 'import@example.test', 'identity_key': 'imported-user',
              'exit': 'out', 'additional_exits': EXITS[1:], 'expiry_time': EXPIRY,
              'metadata': {'comment': 'Original operator note', 'tg_id': '123456789',
                           'source_email': 'original display name', 'source_uuid': 'legacy-short-id',
                           'original_expiry_time': -7776000000,
                           'created_at': 1700000000000, 'updated_at': 1700000001000}}
    result.update(extra)
    return result


class ImportExpansion(unittest.TestCase):
    def test_email_and_storage_key_are_independent_and_expiry_reaches_every_exit(self):
        source = imported_user()
        before = copy.deepcopy(source)
        expanded = routes.expand([source], EXITS)
        self.assertEqual(source, before)
        self.assertEqual([r['email'] for r in expanded],
                         [source['email']] + [source['email'] + '--' + e for e in EXITS[1:]])
        self.assertEqual([r['identity_key'] for r in expanded],
                         ['imported-user'] + ['imported-user--' + e for e in EXITS[1:]])
        self.assertTrue(all(r['expiry_time'] == EXPIRY and r['base_identity_key'] == 'imported-user'
                            for r in expanded))
        self.assertEqual(expanded[0]['metadata'], source['metadata'])
        self.assertTrue(all('metadata' not in r for r in expanded[1:]), 'account metadata was duplicated to synthetic children')

    def test_disabled_first_use_policy_is_preserved_and_cannot_be_enabled(self):
        source = imported_user(enabled=False, expiry_time=-2592000000)
        expanded = routes.expand([source], EXITS)
        self.assertTrue(all(not r['enabled'] and r['expiry_time'] == -2592000000 for r in expanded))
        source['enabled'] = True
        with self.assertRaises(routes.ExpansionError):
            routes.expand([source], EXITS)

    def test_unsafe_labels_and_storage_collisions_are_rejected(self):
        invalid = [imported_user(identity_key='../outside'), imported_user(identity_key='name/child'),
                   imported_user(email='has whitespace'), imported_user(email='has/slash'),
                   imported_user(email='has\\slash'), imported_user(email='has\tcontrol')]
        for source in invalid:
            with self.subTest(source=source['email']), self.assertRaises(routes.ExpansionError):
                routes.expand([source], EXITS)
        for second in [imported_user(email='different@example.test'),
                       {'email':'different', 'identity_key':'imported-user--prague', 'exit':'out'},
                       {'email':'import@example.test--prague', 'identity_key':'different', 'exit':'out'}]:
            with self.subTest(second=second['email']), self.assertRaises(routes.ExpansionError):
                routes.expand([imported_user(), second], EXITS)

    def test_unsupported_policies_and_metadata_fail_before_expansion(self):
        invalid = [{'expiry_time': True}, {'expiry_time': '4102444800000'},
                   {'expiry_time': 2**63}, {'expiry_time': -(2**63)-1},
                   {'total_gb': 1}, {'totalGB': 1}, {'limit_ip': 1}, {'limitIp': 1},
                   {'limit_hwid': 1}, {'limitHwid': 1}, {'metadata': []},
                   {'metadata': {'enable': True}}, {'metadata': {'reset': -1}},
                   {'metadata': {'comment': 42}}, {'metadata': {'tg_id': True}},
                   {'metadata': {'tg_id': 'not-a-number'}}, {'metadata': {'tg_id': str(2**63)}}]
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(routes.ExpansionError):
                routes.expand([imported_user(**change)], EXITS)


class ImportController(unittest.TestCase):
    setUp = legacy.ControllerPersistence.setUp
    run_play = legacy.ControllerPersistence.run_play
    managed = legacy.ControllerPersistence.managed

    def test_seeded_identities_metadata_expiry_and_exact_route_labels_survive_reruns(self):
        self.users[:] = [imported_user()]
        state_users = self.state / 'users'
        state_users.mkdir(parents=True)
        (state_users / 'imported-user.uuid').write_text(IMPORTED_UUID)
        (state_users / 'imported-user.sub').write_text(IMPORTED_TOKEN)
        for path in state_users.iterdir():
            path.chmod(0o600)
        self.run_play()
        first = self.managed()
        self.assertEqual(first[0]['uuid'], IMPORTED_UUID)
        self.assertEqual(first[0]['sub_id'], IMPORTED_TOKEN)
        self.assertEqual(first[0]['email'], 'import@example.test')
        self.assertEqual(first[0]['metadata'], self.users[0]['metadata'])
        self.assertTrue(all(row['expiry_time'] == EXPIRY for row in first))
        self.assertEqual(len({row['uuid'] for row in first}), 4)
        self.assertEqual(len({row['sub_id'] for row in first}), 4)
        self.assertEqual(sorted(p.name for p in state_users.glob('*.sub')), ['imported-user.sub'])
        self.assertTrue(all('@' not in p.name for p in state_users.iterdir()))
        config = legacy.yaml.safe_load((self.work / 'node.yaml').read_text())
        self.assertEqual(config['routes'], {row['email']: row['exit'] for row in first})
        self.users[0]['enabled'] = False
        self.run_play()
        second = self.managed()
        self.assertTrue(all(not row['enabled'] for row in second))
        self.assertEqual([(r['uuid'], r['sub_id'], r['expiry_time']) for r in first],
                         [(r['uuid'], r['sub_id'], r['expiry_time']) for r in second])
        output = self.run_play()
        self.assertTrue(all(int(value) == 0 for value in re.findall(r'changed=(\d+)', output)))
        self.assertEqual(self.managed(), second)

    def test_invalid_policy_does_not_create_controller_identity_files(self):
        for change in [{'expiry_time': -86400000}, {'limit_ip': 1},
                       {'metadata': {'limitHwid': 1}}, {'identity_key': '../escape'}]:
            with self.subTest(change=change):
                self.users[:] = [imported_user(**change)]
                self.run_play(success=False)
                self.assertFalse(self.state.exists())


class ImportPanelPreflight(unittest.TestCase):
    def users(self):
        return [dict(email='import@example.test', uuid=IMPORTED_UUID, sub_id=IMPORTED_TOKEN,
                     exit='out', enabled=True, expiry_time=EXPIRY),
                dict(email='import@example.test--prague', uuid='87654321-4321-4321-8321-cba987654321',
                     sub_id=IMPORTED_TOKEN, exit='prague', enabled=True,
                     subscription_owner='import@example.test', expiry_time=EXPIRY)]

    def test_children_cannot_outlive_their_owner(self):
        for expiry in [0, EXPIRY+1, -86400000]:
            users = self.users()
            users[1]['expiry_time'] = expiry
            with self.subTest(expiry=expiry), self.assertRaises(panel.PanelError):
                legacy.canonical_users(users)

    def test_disabled_first_use_policy_is_valid_but_activation_is_rejected(self):
        users = self.users()
        for user in users:
            user.update(enabled=False, expiry_time=-2592000000)
        canonical = legacy.canonical_users(users)
        self.assertTrue(all(not user['enabled'] and user['expiry_time'] == -2592000000 for user in canonical))
        for user in users:
            user['enabled'] = True
        with self.assertRaises(panel.PanelError):
            legacy.canonical_users(users)

    def test_panel_boundary_rejects_invalid_metadata_and_limits(self):
        for change in [{'metadata': []}, {'metadata': False}, {'metadata': {'comment': 3}},
                       {'metadata': {'tg_id': 'not-a-number'}}, {'metadata': {'tg_id': str(2**63)}},
                       {'totalGB': 10}, {'limitHwid': 1}, {'expiry_time': True}]:
            users = self.users()
            users[0].update(change)
            with self.subTest(change=change), self.assertRaises(panel.PanelError):
                legacy.canonical_users(users)


if __name__ == '__main__':
    unittest.main(verbosity=2)
