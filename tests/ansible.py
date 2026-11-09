#!/usr/bin/env python3
"""Exercise the real local Ansible deployment without touching the original stand.

Default command runs site.yml, checks the live TLS/VLESS deployment, reruns the
same playbook and requires zero changes and no container restarts. It then
adds a user and another ingress, proves account continuity and repeats the
expanded deployment without changes. Generated state/results stay under .local/ansible-test. `verify` checks an existing
Ansible stand; `down` removes only resources recorded in its test manifest.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import stand

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local/ansible-test'
CONTROLLER = STATE / 'controller'
PLAYBOOK_DIR = ROOT / 'deploy/ansible'
NETWORK = 'vless-ansible-lab'
PREFIX = 'va-'
HELPERS = ['va-client', 'va-target']
EXPECTED_HOSTS = {'headscale', 'control', 'out-a', 'out-b', 'in'}


def names(container):
    value = container.get('Names', [])
    return [value] if isinstance(value, str) else value


def containers(prefix=None):
    entries = json.loads(stand.pod('ps', '-a', '--format', 'json'))
    result = []
    for entry in entries:
        result.extend(name for name in names(entry)
                      if prefix is None or name.startswith(prefix))
    return sorted(result)


def helper_receipt():
    path = STATE / 'helper-ownership.json'
    return json.loads(path.read_text()) if path.is_file() else {}


def is_owned(name, record=None):
    record = record or json.loads(stand.pod('inspect', name))[0]
    labels = record.get('Config', {}).get('Labels') or {}
    return (name.startswith(PREFIX) and labels.get('io.vless.deployment') == 'va') or (
        name in HELPERS and helper_receipt().get(name) == record['Id'])


def owned_containers():
    return [name for name in containers() if is_owned(name)]


def reject_name_collisions():
    reserved = set(HELPERS + [PREFIX + node for node in
        ['headscale', 'control', 'gateway', 'in', 'in-extra', 'out-a', 'out-b', 'out-c']])
    for name in reserved.intersection(containers()):
        if not is_owned(name):
            raise RuntimeError('refusing to reuse an unowned container name: ' + name)


def snapshot(selected):
    result = {}
    for name in selected:
        record = json.loads(stand.pod('inspect', name))[0]
        result[name] = {'id': record['Id'], 'started': record['State']['StartedAt']}
        if name.startswith(PREFIX) and record['State'].get('Running'):
            steady = {'xray', 'tailscaled', 'node-agent', 'x-ui', 'headscale', 'caddy', 'nginx'}
            processes = stand.pod('top', name, 'hpid', 'comm').splitlines()[1:]
            result[name]['processes'] = sorted(
                ' '.join(line.split()) for line in processes
                if line.split() and line.split()[-1] in steady)
    return result


def unrelated_snapshot():
    return snapshot([name for name in containers() if not is_owned(name)])


def assert_unrelated_unchanged(before):
    for name, record in before.items():
        assert snapshot([name])[name] == record, 'unrelated container changed: ' + name


def deployment_manifest():
    selected = owned_containers()
    volumes = set()
    for name in selected:
        record = json.loads(stand.pod('inspect', name))[0]
        for mount in record.get('Mounts', []):
            volume = mount.get('Name', '')
            if mount.get('Type') == 'volume' and volume.startswith(PREFIX):
                volumes.add(volume)
    network = json.loads(stand.pod('network', 'inspect', NETWORK))[0]
    manifest = {'containers': [{'name': name, 'id': json.loads(stand.pod('inspect', name))[0]['Id']}
                               for name in selected],
                'volumes': sorted(volumes), 'network': NETWORK,
                'network_id': network.get('id', network.get('Id'))}
    stand.write(STATE / 'resources.json', manifest)
    return manifest


def playbook(label, inventory=None):
    executable = Path(os.environ.get(
        'ANSIBLE_PLAYBOOK', ROOT / 'scripts/ansible.sh'))
    if not executable.is_file():
        raise RuntimeError('Ansible executable missing: ' + str(executable))
    environment = dict(os.environ, ANSIBLE_FORCE_COLOR='0', ANSIBLE_NOCOLOR='1', PY_COLORS='0',
                       ANSIBLE_CONFIG=str(PLAYBOOK_DIR / 'ansible.cfg'),
                       ANSIBLE_HOME=str(ROOT / '.local/ansible-home'))
    process = subprocess.run(
        [str(executable), '-i', str(inventory or PLAYBOOK_DIR / 'inventory.local.yml'),
         str(PLAYBOOK_DIR / 'site.yml')],
        cwd=PLAYBOOK_DIR, env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = process.stdout
    log = STATE / (label + '.log')
    stand.write(log, output)
    if process.returncode:
        raise RuntimeError('Ansible ' + label + ' failed; inspect ' + str(log))
    recap = {}
    clean = re.sub(r'\x1b\[[0-9;]*m', '', output)
    for host, details in re.findall(r'^([^\s:]+)\s*:\s*(ok=\d+\s+changed=\d+[^\n]*)$',
                                    clean, re.MULTILINE):
        recap[host] = {key: int(value) for key, value in re.findall(r'(\w+)=(\d+)', details)}
    assert EXPECTED_HOSTS.issubset(recap), 'Ansible recap missing expected deployment hosts: ' + str(recap)
    for host, details in recap.items():
        for counter in ['failed', 'unreachable', 'rescued', 'ignored']:
            assert details.get(counter, 0) == 0, 'Ansible '+host+' '+counter+' was nonzero'
    return recap


def read_identity(email):
    directory = CONTROLLER / 'users'
    return ((directory / (email + '.uuid')).read_text().strip(),
            (directory / (email + '.sub')).read_text().strip())


def start_helper(name, image, args, mounts=(), options=()):
    command = ['run', '-d', '--name', name, '--network', NETWORK,
               '--restart=unless-stopped', '--label', 'io.vless.deployment=va']
    if name == 'va-client':
        command.append('--no-healthcheck')
    for source, destination in mounts:
        command += ['-v', str(source) + ':' + destination]
    stand.pod(*command, *options, image, *args)
    if name in HELPERS:
        receipt = helper_receipt()
        receipt[name] = json.loads(stand.pod('inspect', name))[0]['Id']
        stand.write(STATE / 'helper-ownership.json', receipt)


def helpers():
    reject_name_collisions()
    existing = set(containers(PREFIX))
    cert = CONTROLLER / 'tls/in.crt'
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    identity = [read_identity(email)[0] for email in ['alice-a', 'alice-b']]
    config = {'log': {'loglevel': 'warning'}, 'inbounds': [], 'outbounds': [],
              'routing': {'rules': []}}
    for index in range(3):
        config['inbounds'].append({
            'tag': str(index), 'listen': '0.0.0.0', 'port': 1080 + index,
            'protocol': 'socks', 'settings': {'auth': 'noauth'}})
        config['outbounds'].append({
            'tag': str(index), 'protocol': 'vless',
            'settings': {'vnext': [{'address': 'va-in', 'port': 443,
                                    'users': [{'id': identity[index] if index < 2 else str(uuid.uuid4()),
                                               'encryption': 'none'}]}]},
            'streamSettings': {'network': 'tcp', 'security': 'tls',
                               'tlsSettings': {'serverName': 'ingress.vless.test',
                                               'pinnedPeerCertSha256': fingerprint}}})
        config['routing']['rules'].append({
            'type': 'field', 'inboundTag': [str(index)], 'outboundTag': str(index)})
    # The inventory's host publication is 24443; the node listens on 443.
    client_file = STATE / 'test-client.json'
    if 'va-client' not in existing:
        stand.write(client_file, config)
        start_helper('va-client', 'localhost/vless-node:dev',
                     ['xray', 'run', '-config', '/client.json'],
                     mounts=[(client_file, '/client.json:ro')],
                     options=['-p', '127.0.0.1:21080:1080', '-p', '127.0.0.1:21081:1081'])
    if 'va-target' not in existing:
        start_helper('va-target', 'docker.io/library/python:3.13-slim',
                     ['python', '/server.py'],
                     mounts=[(ROOT / 'tests/http_server.py', '/server.py:ro')])


def fetch(index, url='http://va-target:8080'):
    return stand.pod('exec', 'va-client', 'curl', '-fsS', '--max-time', '10',
                     '--socks5-hostname', '127.0.0.1:' + str(1080 + index), url)


def subscriptions(emails=('alice-a', 'alice-b'), expected_ports=(24443,)):
    context = ssl.create_default_context(cafile=str(CONTROLLER / 'tls/control.crt'))
    for email in emails:
        identity, subscription = read_identity(email)
        request = urllib.request.Request('https://127.0.0.1:22443/sub/' +
                                         urllib.parse.quote(subscription, safe=''))
        raw = urllib.request.urlopen(request, context=context, timeout=15).read()
        decoded = raw.decode() if raw.startswith(b'vless://') else base64.b64decode(raw).decode()
        links = [urllib.parse.urlsplit(line) for line in decoded.splitlines()
                 if line.startswith('vless://')]
        assert links, 'subscription has no VLESS entries for ' + email
        matches = [link for link in links if link.username == identity]
        assert matches, 'subscription does not contain expected user identity for ' + email
        assert {link.port for link in matches} == set(expected_ports), \
            'subscription has incorrect ingress node set for ' + email
        for link in matches:
            parameters = urllib.parse.parse_qs(link.query)
            assert link.hostname == '127.0.0.1', 'subscription has wrong public ingress address'
            assert link.port in expected_ports, 'subscription has wrong public ingress port'
            assert parameters.get('security') == ['tls'], 'subscription does not require TLS'
            assert parameters.get('sni') == ['ingress.vless.test'], 'subscription has wrong TLS SNI'


def boundary_checks():
    # Curl's remote_ip is set as soon as TCP connects, even if the VLESS server
    # later rejects the HTTP probe. Requiring it empty avoids treating an
    # application timeout/refusal as proof that the mesh ACL denied connection.
    targets = [('va-control', 2053), ('va-out-b', 8443)]
    for node, port in targets:
        address = stand.pod('exec', node, 'tailscale', 'ip', '-4')
        result = subprocess.run(
            ['podman', 'exec', 'va-out-a', 'curl', '--silent', '--show-error',
             '--connect-timeout', '2', '--max-time', '3', '--output', '/dev/null',
             '--write-out', '%{remote_ip}', 'http://' + address + ':' + str(port)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        assert result.returncode in (7, 28) and result.stdout.strip() == '', \
            'exit unexpectedly established TCP to restricted mesh target ' + node
    context = ssl.create_default_context(cafile=str(CONTROLLER / 'tls/control.crt'))
    for path in ['/', '/login', '/panel/']:
        try:
            urllib.request.urlopen('https://127.0.0.1:22443' + path,
                                   context=context, timeout=10)
        except urllib.error.HTTPError as error:
            assert error.code == 404, 'gateway returned unexpected status on ' + path
        else:
            raise AssertionError('subscription gateway exposed a non-subscription route: ' + path)
    return ['mesh ACL denies exit-to-control and exit-to-exit TCP connections',
            'HTTPS subscription gateway returns 404 for root and admin routes']


def expanded_exit_b():
    inventory_file = STATE / 'expanded-inventory.json'
    if inventory_file.is_file():
        inventory = json.loads(inventory_file.read_text())
        users = inventory['all']['children']['vless']['vars']['vless_users']
        return next(user['exit'] for user in users if user['email'] == 'alice-b')
    return 'out-b'


def verify(expanded=False):
    checks = []
    exit_b = expanded_exit_b() if expanded else 'out-b'
    for index, node in [(0, 'out-a'), (1, exit_b)]:
        assert stand.wait(lambda: fetch(index)) == stand.ip('va-' + node)
    checks.append('generated client UUIDs select their assigned exits over pinned public TLS')
    for label in ['a', 'b']:
        address = stand.pod('exec', 'va-out-' + label, 'tailscale', 'ip', '-4')
        result = stand.pod('exec', 'va-in', 'tailscale', 'ping', '--c', '5',
                           '--until-direct=true', address)
        assert 'via ' in result and 'DERP(' not in result.splitlines()[-1], result
    checks.append('Ansible-enrolled ingress reaches both exits by direct mesh P2P')
    try:
        fetch(2)
    except RuntimeError:
        assert fetch(1) == stand.ip('va-' + exit_b)
    else:
        raise AssertionError('unknown UUID was accepted')
    checks.append('unknown UUID is rejected while a legitimate route remains available')
    assert 'Example Domain' in fetch(0, 'https://example.com')
    checks.append('internet HTTPS succeeds through ingress and mesh exit')
    if expanded:
        for index, node in [(3, 'out-a'), (4, 'out-a'), (5, exit_b), (6, 'out-a')]:
            assert stand.wait(lambda: fetch(index)) == stand.ip('va-' + node)
        stand.wait(lambda: subscriptions(('alice-a', 'alice-b', 'charlie'), (24443, 24444)) is None)
        checks.append('new and existing accounts work through both ingress nodes')
    else:
        stand.wait(lambda: subscriptions() is None)
    checks.append('verified HTTPS gateway serves matching TLS ingress subscription links')
    checks += boundary_checks()
    for check in checks:
        print('PASS ' + check, flush=True)
    return checks


def base_inventory():
    interpreter = ROOT / '.local/ansible-venv/bin/python'
    result = subprocess.run(
        [str(interpreter), '-c',
         'import json,sys,yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))',
         str(PLAYBOOK_DIR / 'inventory.local.yml')],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return json.loads(result.stdout)


def add_client_route(config, index, identity, node, certificate):
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest()
    config['inbounds'].append({
        'tag': str(index), 'listen': '0.0.0.0', 'port': 1080 + index,
        'protocol': 'socks', 'settings': {'auth': 'noauth'}})
    config['outbounds'].append({
        'tag': str(index), 'protocol': 'vless',
        'settings': {'vnext': [{'address': node, 'port': 443,
                                'users': [{'id': identity, 'encryption': 'none'}]}]},
        'streamSettings': {'network': 'tcp', 'security': 'tls',
                           'tlsSettings': {'serverName': 'ingress.vless.test',
                                           'pinnedPeerCertSha256': fingerprint}}})
    config['routing']['rules'].append({
        'type': 'field', 'inboundTag': [str(index)], 'outboundTag': str(index)})


def replace_test_client(config):
    client_file = STATE / 'test-client.json'
    stand.write(client_file, config)
    assert is_owned('va-client'), 'refusing to replace an unowned test client'
    stand.pod('rm', '-f', '-v', 'va-client')
    start_helper('va-client', 'localhost/vless-node:dev',
                 ['xray', 'run', '-config', '/client.json'],
                 mounts=[(client_file, '/client.json:ro')],
                 options=['-p', '127.0.0.1:21080:1080', '-p', '127.0.0.1:21081:1081'])


def growth():
    checks = []
    original_identities = {email: read_identity(email) for email in ['alice-a', 'alice-b']}
    inventory = base_inventory()
    inventory['all']['children']['vless']['vars']['vless_users'].append({'email': 'charlie', 'exit': 'out-a'})
    user_inventory = STATE / 'new-user-inventory.json'
    stand.write(user_inventory, inventory)
    user_recap = playbook('new-user-run', user_inventory)
    for email, identity in original_identities.items():
        assert read_identity(email) == identity, 'adding a user changed an existing account identity'
    config = json.loads((STATE / 'test-client.json').read_text())
    # Only this helper container is replaced; deployment containers remain owned
    # entirely by Ansible. Indices 0/1 are existing users, 2 is the unknown UUID.
    config['inbounds'] = [entry for entry in config['inbounds'] if int(entry['tag']) < 3]
    config['outbounds'] = [entry for entry in config['outbounds'] if int(entry['tag']) < 3]
    config['routing']['rules'] = [entry for entry in config['routing']['rules']
                                  if int(entry['outboundTag']) < 3]
    charlie = read_identity('charlie')[0]
    add_client_route(config, 3, charlie, 'va-in', CONTROLLER / 'tls/in.crt')
    replace_test_client(config)
    for index, label in [(0, 'a'), (1, 'b'), (3, 'a')]:
        assert stand.wait(lambda: fetch(index)) == stand.ip('va-out-' + label)
    subscriptions(('alice-a', 'alice-b', 'charlie'))
    checks.append('Ansible adds a new user with a working assigned exit and subscription')
    checks.append('adding a user preserves existing UUIDs, subscription IDs and working routes')

    inventory['all']['children']['vless']['children']['ingress']['hosts']['in-extra'] = {
        'ingress_public_address': '127.0.0.1',
        'ingress_server_name': 'ingress.vless.test',
        'ingress_public_port': 24444,
        'ingress_publish': ['127.0.0.1:24444:443/tcp']}
    expanded_inventory = STATE / 'expanded-inventory.json'
    stand.write(expanded_inventory, inventory)
    node_recap = playbook('new-node-run', expanded_inventory)
    for email, identity in original_identities.items():
        assert read_identity(email) == identity, 'adding a node changed an existing account identity'
    assert read_identity('charlie')[0] == charlie, 'adding a node changed the new user UUID'
    for index, email in [(4, 'alice-a'), (5, 'alice-b'), (6, 'charlie')]:
        add_client_route(config, index, read_identity(email)[0], 'va-in-extra',
                         CONTROLLER / 'tls/in-extra.crt')
    replace_test_client(config)
    for index, label in [(0, 'a'), (1, 'b'), (3, 'a'), (4, 'a'), (5, 'b'), (6, 'a')]:
        assert stand.wait(lambda: fetch(index)) == stand.ip('va-out-' + label)
    subscriptions(('alice-a', 'alice-b', 'charlie'), (24443, 24444))
    checks.append('a new ingress accepts every existing account without issuing replacement UUIDs')
    checks.append('all user subscriptions advertise both original and newly added ingress ports')

    # Also attach a new exit to an existing account. Client credentials and
    # ingress endpoints remain unchanged; only Ansible's authorized route moves.
    inventory['all']['children']['vless']['children']['exits']['hosts']['out-c'] = {}
    for user in inventory['all']['children']['vless']['vars']['vless_users']:
        if user['email'] == 'alice-b':
            user['exit'] = 'out-c'
    stand.write(expanded_inventory, inventory)
    exit_recap = playbook('new-exit-run', expanded_inventory)
    for email, identity in original_identities.items():
        assert read_identity(email) == identity, 'adding an exit changed an existing account identity'
    for index, node in [(0, 'out-a'), (1, 'out-c'), (3, 'out-a'),
                        (4, 'out-a'), (5, 'out-c'), (6, 'out-a')]:
        assert stand.wait(lambda: fetch(index)) == stand.ip('va-' + node)
    subscriptions(('alice-a', 'alice-b', 'charlie'), (24443, 24444))
    checks.append('a newly added exit is attached to an existing account without changing UUID or subscription ID')
    checks.append('the reassigned account uses the new exit through both ingress nodes while other routes stay intact')
    for index in [1, 5]:
        assert 'Example Domain' in fetch(index, 'https://example.com')
    checks.append('the existing account reaches internet HTTPS through the new exit via both ingresses')
    peer = stand.pod('exec', 'va-out-c', 'tailscale', 'ip', '-4')
    for ingress in ['va-in', 'va-in-extra']:
        result = stand.pod('exec', ingress, 'tailscale', 'ping', '--c', '5',
                           '--until-direct=true', peer)
        assert 'via ' in result and 'DERP(' not in result.splitlines()[-1], result
    checks.append('the new exit is reached by direct P2P from both ingress nodes')

    before = snapshot(owned_containers())
    expanded_recap = playbook('expanded-second-run', expanded_inventory)
    assert all(record.get('changed') == 0 for record in expanded_recap.values()), \
        'identical expanded deployment changed resources: ' + str(expanded_recap)
    assert snapshot(owned_containers()) == before, \
        'identical expanded deployment recreated a container or restarted a daemon'
    for index, node in [(0, 'out-a'), (1, 'out-c'), (3, 'out-a'),
                        (4, 'out-a'), (5, 'out-c'), (6, 'out-a')]:
        assert stand.wait(lambda: fetch(index)) == stand.ip('va-' + node)
    subscriptions(('alice-a', 'alice-b', 'charlie'), (24443, 24444))
    checks += boundary_checks()
    checks.append('expanded deployment rerun reports zero changes and preserves daemon/container identities')
    for check in checks:
        print('PASS ' + check, flush=True)
    return checks, {'new_user_recap': user_recap, 'new_node_recap': node_recap, 'new_exit_recap': exit_recap,
                    'expanded_second_recap': expanded_recap}


def run():
    STATE.mkdir(parents=True, exist_ok=True)
    reject_name_collisions()
    original = unrelated_snapshot()
    try:
        first = playbook('first-run')
        helpers()
        deployment_manifest()
        checks = verify()
        before = snapshot(owned_containers())
        second = playbook('second-run')
        assert all(record.get('changed') == 0 for record in second.values()), \
            'identical second deployment changed resources: ' + str(second)
        after = snapshot(owned_containers())
        assert before == after, 'identical deployment recreated or restarted a container'
        checks += ['identical second Ansible run reports changed=0 on every host',
                   'identical second deployment preserves container IDs, start times and daemon PIDs']
        verify()
        checks.append('both VLESS routes and subscriptions still work after the idempotent rerun')
        growth_checks, growth_results = growth()
        checks += growth_checks
        assert_unrelated_unchanged(original)
        checks.append('original stand and unrelated containers remain unchanged')
        stand.write(STATE / 'test-results.json', {
            'passed': checks, 'first_recap': first, 'second_recap': second,
            'container_snapshot': snapshot(owned_containers()), **growth_results,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})
        for check in checks[-4:]:
            print('PASS ' + check, flush=True)
    finally:
        # Record partial deployments too, allowing narrowly scoped cleanup after
        # a failed first run without touching the existing original stand.
        if owned_containers():
            deployment_manifest()


def down():
    manifest_file = STATE / 'resources.json'
    if not manifest_file.exists():
        raise RuntimeError('No test resource manifest; refusing broad cleanup')
    manifest = json.loads(manifest_file.read_text())
    original = unrelated_snapshot()
    recorded_names = []
    for entry in manifest['containers']:
        name = entry['name'] if isinstance(entry, dict) else entry
        recorded_names.append(name)
        assert name.startswith(PREFIX), 'refusing container outside isolated prefix'
        if name not in containers():
            continue
        actual = json.loads(stand.pod('inspect', name))[0]
        if isinstance(entry, dict):
            assert actual['Id'] == entry['id'], 'container name was reused since the test: ' + name
        else:
            assert is_owned(name, actual), 'legacy manifest cannot authorize unowned container: ' + name
        stand.pod('rm', '-f', '-v', name, check=False)
    for volume in manifest['volumes']:
        assert volume.startswith(PREFIX), 'refusing volume outside isolated prefix'
        stand.pod('volume', 'rm', volume, check=False)
    assert manifest['network'] == NETWORK
    current_network = json.loads(stand.pod('network', 'inspect', NETWORK))[0]
    if manifest.get('network_id'):
        assert current_network.get('id', current_network.get('Id')) == manifest['network_id'], \
            'isolated network name was reused since the test'
    stand.pod('network', 'rm', NETWORK, check=False)
    assert not set(recorded_names).intersection(containers()), \
        'some recorded test containers remain after cleanup'
    remaining_volumes = set(stand.pod('volume', 'ls', '--format', '{{.Name}}').splitlines())
    assert not set(manifest['volumes']).intersection(remaining_volumes), \
        'some recorded test volumes remain after cleanup'
    assert NETWORK not in stand.pod('network', 'ls', '--format', '{{.Name}}').splitlines(), \
        'isolated test network remains after cleanup'
    # State volumes are now gone; their consumed single-use enrollment keys
    # cannot enroll fresh identities into a new coordination database.
    for name in recorded_names:
        logical_name = name[len(PREFIX):]
        enrollment = CONTROLLER / 'enrollment' / (logical_name + '.key')
        if enrollment.is_file():
            enrollment.unlink()
    assert_unrelated_unchanged(original)
    print('PASS removed only recorded Ansible test resources; unrelated containers unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['run', 'verify', 'down'], default='run', nargs='?')
    args = parser.parse_args()
    if args.command == 'verify':
        helpers()
        verify(expanded='va-in-extra' in containers(PREFIX))
    else:
        globals()[args.command]()
