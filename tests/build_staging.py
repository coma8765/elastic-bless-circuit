#!/usr/bin/env python3
"""Run real Ansible staging/build decisions for roles sharing one physical host.

The builder is a local fixture that records invocations, not a container engine.
The production prepare tasks themselves decide what changes and when to build.
Run with the project's Ansible virtual environment; no live containers are used.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class SharedHostBuildStaging(unittest.TestCase):
    def test_all_roles_receive_source_upgrades_without_repeat_builds(self):
        (ROOT / '.local').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='build-staging-', dir=ROOT / '.local') as directory:
            work = Path(directory)
            source = work / 'source'
            source.mkdir()
            for name in ['src', 'infra', 'scripts']:
                (source / name).mkdir()
            (source / 'CMakeLists.txt').write_text('fixture-build-input\n')
            (source / 'src/main.cpp').write_text('source-version-1\n')
            (source / 'infra/Dockerfile.common').write_text('image-version-1\n')
            trace = work / 'builds.jsonl'
            (source / 'scripts/build.sh').write_text('''#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
"$BUILD_TEST_PYTHON" - <<'PYTHON'
import json, os
from pathlib import Path
record = {'targets': os.environ['BUILD_IMAGES'], 'cwd': str(Path.cwd()),
          'source': Path('src/main.cpp').read_text(),
          'image': Path('infra/Dockerfile.common').read_text()}
with open(os.environ['BUILD_TEST_TRACE'], 'a') as stream:
    stream.write(json.dumps(record) + '\\n')
PYTHON
''')
            prepare = yaml.safe_load((ROOT / 'deploy/ansible/roles/prepare/tasks/main.yml').read_text())
            selected_names = [
                'Create private runtime and build directories',
                'Select only the images required by this logical service',
                'Copy build inputs without credentials or local artifacts',
                'Build the required deployment images on the target architecture',
            ]
            selected = [next(task for task in prepare if task['name'] == name)
                        for name in selected_names]
            play = [{'hosts': 'headscale:control:ingress', 'gather_facts': False,
                     'serial': 1, 'tasks': selected}]
            playbook = work / 'playbook.yml'
            playbook.write_text(yaml.safe_dump(play, sort_keys=False))
            inventory_path = work / 'inventory.json'
            inventory = {'all': {'vars': {
                'ansible_connection': 'local',
                'ansible_python_interpreter': sys.executable,
                'ansible_remote_tmp': str(work / 'remote-tmp'),
                'deployment_root': str(work / 'deployment'),
                'node_dir': '{{ deployment_root }}/{{ inventory_hostname }}',
                'repo_root': str(source), 'build_images': True,
                'prepare_images_by_role': True, 'gateway_enabled': False,
                'container_engine': 'podman', 'headscale_image': 'fixture-headscale',
                'control_image': 'fixture-control', 'node_image': 'fixture-node',
                'gateway_image': 'fixture-gateway',
                'container_cli_environment': {'BUILD_TEST_TRACE': str(trace),
                                              'BUILD_TEST_PYTHON': sys.executable},
                # Images already exist: only actual source-copy changes should
                # trigger the initial/upgrade builds.
                'existing_images': {'results': [{'rc': 0}]},
            }, 'children': {
                'headscale': {'hosts': {'headscale': {}}},
                'control': {'hosts': {'control': {}}},
                'ingress': {'hosts': {'in': {}}},
            }}}

            def run(label):
                inventory_path.write_text(json.dumps(inventory))
                process = subprocess.run(
                    [str(ROOT / 'scripts/ansible.sh'), '-i', str(inventory_path), str(playbook)],
                    cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
                (work / (label + '.log')).write_text(process.stdout)
                self.assertEqual(process.returncode, 0, process.stdout)
                recap = {host: int(changed) for host, changed in re.findall(
                    r'^(headscale|control|in)\s*:\s*ok=\d+\s+changed=(\d+)',
                    process.stdout, re.MULTILINE)}
                self.assertEqual(set(recap), {'headscale', 'control', 'in'})
                records = [json.loads(line) for line in trace.read_text().splitlines()]
                return recap, records

            def check_batch(records, source_version, image_version):
                self.assertEqual({record['targets'] for record in records}, {'headscale', 'control', 'node'})
                self.assertEqual(len({record['cwd'] for record in records}), 3,
                                 'cohosted roles share staging and consume each other\'s changes')
                self.assertTrue(all(record['source'] == source_version for record in records))
                self.assertTrue(all(record['image'] == image_version for record in records))

            _, first = run('initial')
            self.assertEqual(len(first), 3)
            check_batch(first, 'source-version-1\n', 'image-version-1\n')
            recap, unchanged = run('unchanged')
            self.assertTrue(all(changed == 0 for changed in recap.values()), recap)
            self.assertEqual(len(unchanged), 3, 'unchanged roles rebuilt images')

            (source / 'src/main.cpp').write_text('source-version-2\n')
            _, upgraded = run('source-upgrade')
            self.assertEqual(len(upgraded), 6)
            check_batch(upgraded[3:], 'source-version-2\n', 'image-version-1\n')

            (source / 'infra/Dockerfile.common').write_text('image-version-2\n')
            _, image_upgrade = run('image-upgrade')
            self.assertEqual(len(image_upgrade), 9)
            check_batch(image_upgrade[6:], 'source-version-2\n', 'image-version-2\n')

            inventory['all']['children']['control']['hosts']['control']['existing_images'] = {
                'results': [{'rc': 1}]}
            _, missing = run('missing-image')
            self.assertEqual(len(missing), 10)
            self.assertEqual(missing[-1]['targets'], 'control')
            inventory['all']['children']['control']['hosts']['control']['existing_images'] = {
                'results': [{'rc': 0}]}
            recap, final = run('final-unchanged')
            self.assertTrue(all(changed == 0 for changed in recap.values()), recap)
            self.assertEqual(len(final), 10)


if __name__ == '__main__':
    unittest.main(verbosity=2)
