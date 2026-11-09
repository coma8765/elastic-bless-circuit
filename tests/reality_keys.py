#!/usr/bin/env python3
"""Controller REALITY identity security and persistence contracts (no live keys)."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path = [entry for entry in sys.path if Path(entry or '.').resolve() != ROOT / 'tests']
spec = importlib.util.spec_from_file_location('reality_key_under_test', ROOT / 'deploy/ansible/library/vless_reality_key.py')
keys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(keys)


class RealityIdentityContracts(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='reality-identity-')
        self.root = Path(self.directory.name)
        self.path = self.root / 'ingress.json'

    def tearDown(self):
        self.directory.cleanup()

    def store(self, record, path=None):
        path = path or self.path
        path.write_text(json.dumps(record))
        path.chmod(0o600)

    def test_new_identity_has_private_permissions_and_valid_raw_keys(self):
        record, changed = keys.identity(str(self.path))
        self.assertTrue(changed)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(len(base64.urlsafe_b64decode(record['private_key'] + '=')), 32)
        self.assertEqual(len(base64.urlsafe_b64decode(record['public_key'] + '=')), 32)
        self.assertRegex(record['short_id'], r'^[0-9a-f]{16}$')
        self.assertEqual(set(record), {'private_key', 'public_key', 'short_id'})

    def test_rerun_preserves_identity_bytes_and_timestamp(self):
        first, _ = keys.identity(str(self.path))
        before = self.path.read_bytes(), self.path.stat().st_mtime_ns
        second, changed = keys.identity(str(self.path))
        self.assertFalse(changed)
        self.assertTrue(first == second, 'identity rotated on an unchanged rerun')
        self.assertTrue(before == (self.path.read_bytes(), self.path.stat().st_mtime_ns))

    def test_independent_ingress_identities_are_distinct(self):
        first, _ = keys.identity(str(self.path))
        second, _ = keys.identity(str(self.root / 'other.json'))
        self.assertTrue(first['private_key'] != second['private_key'])
        self.assertNotEqual(first['public_key'], second['public_key'])
        self.assertNotEqual(first['short_id'], second['short_id'])

    def test_invalid_json_and_unexpected_record_types_are_not_overwritten(self):
        for content in ['{invalid', '[]', 'null', '123', '"text"']:
            with self.subTest(content=content):
                self.path.write_text(content)
                self.path.chmod(0o600)
                with self.assertRaises(ValueError):
                    keys.identity(str(self.path))
                self.assertTrue(self.path.read_text() == content)

    def test_invalid_fields_fail_closed_without_rotating_identity(self):
        original, _ = keys.identity(str(self.path))
        changes = [{'private_key': None}, {'private_key': 123}, {'private_key': []},
                   {'private_key': 'bad'}, {'public_key': {}}, {'public_key': '!' * 43},
                   {'short_id': None}, {'short_id': 123}, {'short_id': 'ABCDEF1234567890'},
                   {'short_id': '0123'}, {'short_id': ' ' * 16}]
        for change in changes:
            with self.subTest(field=next(iter(change))):
                record = copy.deepcopy(original)
                record.update(change)
                self.store(record)
                before = self.path.read_bytes()
                with self.assertRaises(ValueError):
                    keys.identity(str(self.path))
                self.assertTrue(self.path.read_bytes() == before, 'invalid identity was silently replaced')

    def test_mismatched_key_pair_is_rejected(self):
        record, _ = keys.identity(str(self.path))
        other, _ = keys.identity(str(self.root / 'other.json'))
        record['public_key'] = other['public_key']
        self.store(record)
        with self.assertRaisesRegex(ValueError, 'does not match'):
            keys.identity(str(self.path))

    def test_group_or_other_access_is_rejected(self):
        keys.identity(str(self.path))
        for mode in [0o640, 0o604, 0o660, 0o666]:
            with self.subTest(mode=oct(mode)):
                self.path.chmod(mode)
                with self.assertRaisesRegex(ValueError, 'private file'):
                    keys.identity(str(self.path))

    def test_symlinks_and_non_regular_files_are_rejected(self):
        target = self.root / 'target.json'
        keys.identity(str(target))
        before = target.read_bytes()
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):
            keys.identity(str(self.path))
        self.assertTrue(target.read_bytes() == before)
        self.path.unlink()
        self.path.symlink_to(self.root / 'missing.json')
        with self.assertRaises(ValueError):
            keys.identity(str(self.path))
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaises(ValueError):
            keys.identity(str(self.path))

    def test_exclusive_publication_never_overwrites_a_concurrent_winner(self):
        winner_path = self.root / 'winner.json'
        keys.identity(str(winner_path))
        winner = winner_path.read_bytes()
        def race(_source, destination):
            with open(destination, 'xb') as stream:
                stream.write(winner)
            os.chmod(destination, 0o600)
            raise FileExistsError('a concurrent controller already published its identity')
        with mock.patch.object(keys.os, 'link', side_effect=race):
            with self.assertRaises(FileExistsError):
                keys.identity(str(self.path))
        self.assertTrue(self.path.read_bytes() == winner)
        self.assertEqual(list(self.root.glob('.reality-*')), [])
        _, changed = keys.identity(str(self.path))
        self.assertFalse(changed)

    def test_publication_syncs_both_file_contents_and_directory_entry(self):
        kinds = []
        real_fsync = os.fsync
        def synced(fd):
            kinds.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            real_fsync(fd)
        with mock.patch.object(keys.os, 'fsync', side_effect=synced):
            keys.identity(str(self.path))
        self.assertIn(False, kinds, 'identity content was not fsynced')
        self.assertIn(True, kinds, 'published identity filename was not fsynced')

    def test_module_returns_public_metadata_only(self):
        class Finished(Exception):
            pass
        class FakeModule:
            params = {'path': str(self.path)}
            result = None
            def exit_json(self, **result):
                self.result = result
                raise Finished()
            def fail_json(self, **result):
                self.fail = result
                raise AssertionError('valid test identity unexpectedly failed')
        module = FakeModule()
        with mock.patch.object(keys, 'AnsibleModule', return_value=module):
            with self.assertRaises(Finished):
                keys.main()
        self.assertEqual(set(module.result), {'changed', 'public_key', 'short_id'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
