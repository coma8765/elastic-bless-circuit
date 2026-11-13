#!/usr/bin/env python3
"""Opt-in real-engine DNS/extra-host reconciliation, using one disposable container.

Run with the Ansible venv: python tests/container_overrides.py --engine podman.
No application stand is used; only a unique labeled sleeping Debian fixture is
created. The production node task supplies the actual override expressions and
Docker comparison settings exercised by this test.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]


def run(engine, image, ssh_target=None, ssh_port=22):
    nonce = uuid.uuid4().hex[:12]
    name = 'vless-dns-regression-' + nonce
    label = 'io.vless.test-instance'
    module = 'containers.podman.podman_container' if engine == 'podman' else 'community.docker.docker_container'
    source = yaml.safe_load((ROOT / 'deploy/ansible/roles/node/tasks' /
                             ('container-' + engine + '.yml')).read_text())[0][module]
    dns_key = 'dns' if engine == 'podman' else 'dns_servers'
    args = {'name': name, 'image': image, 'state': 'started', 'command': ['sleep', '300'],
            dns_key: source[dns_key], 'etc_hosts': source['etc_hosts']}
    if engine == 'podman':
        args['label'] = {label: nonce}
        args['pull'] = 'never'
    else:
        args.update(labels={label: nonce}, pull='never', container_default_behavior='no_defaults',
                    comparisons=copy.deepcopy(source['comparisons']))
    (ROOT / '.local').mkdir(exist_ok=True)

    target_user = target_host = None
    if ssh_target:
        if engine != 'docker' or not re.fullmatch(r'[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+', ssh_target):
            raise ValueError('SSH mode requires Docker and an explicit user@host target')
        target_user, target_host = ssh_target.split('@', 1)

    def cli(*arguments, check=True):
        command = [engine, *arguments]
        if ssh_target:
            command = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                       '-o', 'ConnectTimeout=10', '-p', str(ssh_port), ssh_target,
                       ' '.join(shlex.quote(part) for part in command)]
        p = subprocess.run(command, text=True, capture_output=True)
        if check and p.returncode:
            raise RuntimeError(p.stderr)
        return p

    if engine == 'podman' and cli('container', 'exists', name, check=False).returncode == 0:
        raise RuntimeError('refusing existing fixture name')
    existing = cli('container', 'inspect', name, check=False)
    if existing.returncode == 0:
        raise RuntimeError('refusing existing fixture name')
    cli('image', 'inspect', image)  # Deliberately do not pull images or install an engine.
    with tempfile.TemporaryDirectory(prefix='container-overrides-', dir=ROOT / '.local') as directory:
        work = Path(directory)
        inventory = work / 'inventory.json'
        fixture_host = 'fixture' if ssh_target else 'localhost'
        host_vars = ({'ansible_connection': 'ssh', 'ansible_host': target_host,
                      'ansible_user': target_user, 'ansible_port': ssh_port,
                      'ansible_python_interpreter': '/usr/bin/python3',
                      'ansible_ssh_common_args': '-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10'}
                     if ssh_target else {'ansible_connection': 'local',
                         'ansible_python_interpreter': sys.executable,
                         'ansible_remote_tmp': str(work / 'remote-tmp')})
        inventory.write_text(json.dumps({'all': {'hosts': {fixture_host: host_vars}}}))
        playbook = work / 'playbook.yml'
        playbook.write_text(yaml.safe_dump([{'hosts': fixture_host, 'gather_facts': False,
                                           'tasks': [{'name': 'Reconcile fixture overrides', module: args}]}],
                                          sort_keys=False))

        def apply(dns, hosts):
            variables = work / 'vars.json'
            variables.write_text(json.dumps({'container_dns_servers': dns, 'container_extra_hosts': hosts}))
            p = subprocess.run([str(ROOT / 'scripts/ansible.sh'), '-i', str(inventory),
                                '-e', '@' + str(variables), str(playbook)], cwd=ROOT,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
            if p.returncode:
                raise RuntimeError(p.stdout)
            match = re.search(re.escape(fixture_host) + r'\s*:\s*ok=\d+\s+changed=(\d+)', p.stdout)
            assert match, p.stdout
            record = json.loads(cli('inspect', name).stdout)[0]
            return int(match.group(1)), record

        try:
            changed, created = apply(['192.0.2.53'], {'override.vless.invalid': '192.0.2.10'})
            assert changed == 1
            assert not created.get('Mounts') and not created['HostConfig'].get('PortBindings'), 'fixture unexpectedly mounted volumes or published ports'
            assert '192.0.2.53' in cli('exec', name, 'cat', '/etc/resolv.conf').stdout
            assert 'override.vless.invalid' in cli('exec', name, 'cat', '/etc/hosts').stdout
            changed, same = apply(['192.0.2.53'], {'override.vless.invalid': '192.0.2.10'})
            assert changed == 0 and same['Id'] == created['Id'], 'unchanged overrides recreated the fixture'

            changed, cleared = apply([], {})
            assert changed == 1 and cleared['Id'] != created['Id'], 'old immutable overrides were retained'
            assert '192.0.2.53' not in cli('exec', name, 'cat', '/etc/resolv.conf').stdout
            assert 'override.vless.invalid' not in cli('exec', name, 'cat', '/etc/hosts').stdout
            config = cleared['HostConfig']
            assert not config.get('Dns') and not config.get('ExtraHosts'), config
            changed, stable = apply([], {})
            assert changed == 0 and stable['Id'] == cleared['Id'], 'empty defaults were not idempotent'
            print('PASS ' + engine + ': live DNS/extra-host addition, removal and unchanged reruns')
        finally:
            found = cli('inspect', name, check=False)
            if found.returncode == 0:
                actual = json.loads(found.stdout)[0]
                assert (actual.get('Config', {}).get('Labels') or {}).get(label) == nonce, \
                    'refusing cleanup after fixture ownership changed'
                cli('rm', '-f', '-v', actual['Id'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=['podman', 'docker'], required=True)
    parser.add_argument('--image', default='docker.io/library/debian:stable-slim')
    parser.add_argument('--ssh-target', help='Optional explicit Docker host user@host; user needs Docker socket access')
    parser.add_argument('--ssh-port', type=int, default=22)
    options = parser.parse_args()
    run(options.engine, options.image, options.ssh_target, options.ssh_port)
