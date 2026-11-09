#!/usr/bin/env python3
"""Cleanup ownership regressions; these tests never contact the container engine."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ansible as deployment


class OwnershipGuards(unittest.TestCase):
    def test_name_prefix_does_not_claim_an_unrelated_container(self):
        record = {'Id': 'unrelated', 'Config': {'Labels': {'io.vless.deployment': 'other'}}}
        self.assertFalse(deployment.is_owned('va-other', record))
        self.assertFalse(deployment.is_owned('va-control', record))

    def test_deployment_label_requires_matching_namespace(self):
        record = {'Id': 'owned', 'Config': {'Labels': {'io.vless.deployment': 'va'}}}
        self.assertTrue(deployment.is_owned('va-control', record))
        self.assertFalse(deployment.is_owned('unrelated-control', record))

    def test_legacy_helper_receipt_requires_the_exact_container_id(self):
        with patch.object(deployment, 'helper_receipt', return_value={'va-client': 'original'}):
            self.assertTrue(deployment.is_owned('va-client', {
                'Id': 'original', 'Config': {'Labels': {}}}))
            self.assertFalse(deployment.is_owned('va-client', {
                'Id': 'replacement', 'Config': {'Labels': {}}}))

    def test_cleanup_refuses_a_reused_container_name_before_removal(self):
        with tempfile.TemporaryDirectory(dir=deployment.ROOT / '.local') as directory:
            root = Path(directory)
            (root / 'resources.json').write_text(json.dumps({
                'containers': [{'name': 'va-client', 'id': 'original'}],
                'volumes': [], 'network': deployment.NETWORK}))
            actual = {'Id': 'replacement', 'Config': {'Labels': {}}}
            with patch.object(deployment, 'STATE', root), \
                 patch.object(deployment, 'unrelated_snapshot', return_value={}), \
                 patch.object(deployment, 'containers', return_value=['va-client']), \
                 patch.object(deployment.stand, 'pod', return_value=json.dumps([actual])) as engine:
                with self.assertRaisesRegex(AssertionError, 'name was reused'):
                    deployment.down()
                self.assertEqual(engine.call_args_list[0].args, ('inspect', 'va-client'))
                self.assertEqual(engine.call_count, 1, 'cleanup reached a mutation after rejecting ownership')


if __name__ == '__main__':
    unittest.main(verbosity=2)
