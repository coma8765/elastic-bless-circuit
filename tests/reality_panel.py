#!/usr/bin/env python3
"""Test REALITY/Vision subscriptions against a fresh, isolated real 3x-ui container.

Run with the deployment's Ansible venv Python after building vless-control:dev.
No TUN, host networking, external target requests or existing stands are needed.
All users, passwords, keys and tokens are generated in memory. The uniquely named
container and private database volume are removed in finally, including failures.
"""
import argparse
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
# tests/ansible.py must not shadow the installed Ansible package.
sys.path = [entry for entry in sys.path if Path(entry or '.').resolve() != ROOT / 'tests']
spec = importlib.util.spec_from_file_location('vless_panel', ROOT / 'deploy/ansible/library/vless_panel.py')
panel_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel_module)


class Module:
    check_mode = False

    def __init__(self, params):
        self.params = params


def wait(operation, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = operation()
            if value is not None:
                return value
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError('isolated control fixture did not become ready')


def endpoint(label):
    return {'address': label + '.example.com', 'port': 443, 'remark': label,
            'security': 'reality', 'reality_target': 'www.microsoft.com:443',
            'reality_server_name': 'www.microsoft.com',
            'reality_public_key': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='),
            'reality_short_id': secrets.token_hex(8), 'reality_fingerprint': 'chrome'}


def user(label):
    return {'email': label, 'uuid': str(uuid.uuid4()), 'sub_id': secrets.token_urlsafe(24),
            'exit': 'exit-' + label, 'enabled': True}


def run(engine, image):
    name = 'vless-reality-panel-test-' + uuid.uuid4().hex[:12]
    volume = name + '-db'
    password = secrets.token_urlsafe(32)
    checks = []

    def cli(*args, required=True):
        try:
            result = subprocess.run([engine, *args], text=True, capture_output=True, timeout=90)
        except (OSError, subprocess.TimeoutExpired):
            # TimeoutExpired embeds argv, including initialization credentials.
            raise RuntimeError('isolated container command did not complete: ' + args[0]) from None
        if required and result.returncode:
            # Container initialization can print passwords; raw output stays private.
            raise RuntimeError('isolated container operation failed: ' + args[0])
        return result.stdout.strip(), result.returncode

    def published(port):
        output, _ = cli('port', name, str(port) + '/tcp')
        return int(output.splitlines()[0].rsplit(':', 1)[1])

    def subscription(record):
        raw = urllib.request.urlopen('http://127.0.0.1:' + str(subscription_port) + '/sub/' +
                                     urllib.parse.quote(record['sub_id'], safe=''), timeout=15).read()
        body = raw.decode() if raw.startswith(b'vless://') else base64.b64decode(raw).decode()
        links = [urllib.parse.urlsplit(line) for line in body.splitlines() if line.startswith('vless://')]
        assert links, 'subscription has no VLESS entries'
        assert all(link.username == record['uuid'] for link in links), 'subscription changed the assigned UUID'
        return links

    def verify_entries(records, endpoints):
        for record in records:
            links = wait(lambda: subscription(record))
            found = {link.hostname: urllib.parse.parse_qs(link.query) for link in links}
            assert set(found) == {entry['address'] for entry in endpoints}, 'subscription endpoint set differs'
            for entry in endpoints:
                query = found[entry['address']]
                assert query.get('security') == ['reality'], 'REALITY security was lost'
                assert query.get('flow') == ['xtls-rprx-vision'], 'Vision flow was lost'
                assert query.get('pbk') == [entry['reality_public_key']], 'wrong per-ingress client key'
                assert query.get('sid') == [entry['reality_short_id']], 'wrong per-ingress short ID'
                assert query.get('sni') == [entry['reality_server_name']], 'wrong camouflage SNI'
                assert query.get('fp') == [entry['reality_fingerprint']], 'wrong fingerprint'

    try:
        cli('run', '--rm', '--no-healthcheck', '-v', volume + ':/etc/x-ui', '--entrypoint', '/app/x-ui',
            image, 'setting', '-username', 'fixture-admin', '-password', password,
            '-port', '2053', '-webBasePath', '/')
        cli('run', '-d', '--rm', '--no-healthcheck', '--name', name,
            '--label', 'io.vless.test=reality-panel',
            '-p', '127.0.0.1::2053', '-p', '127.0.0.1::2096',
            '-v', volume + ':/etc/x-ui', '--entrypoint', '/usr/bin/tini', image, '--', '/app/x-ui')
        api_port, subscription_port = published(2053), published(2096)
        client = wait(lambda: panel_module.Panel('http://127.0.0.1:' + str(api_port), 'fixture-admin', password))
        alice, bob = user('alice'), user('bob')
        ingress_a, ingress_b = endpoint('ingress-a'), endpoint('ingress-b')
        module = Module({'url': 'http://127.0.0.1:' + str(api_port), 'username': 'fixture-admin',
                         'password': password, 'users': [alice], 'ingress_endpoints': [ingress_a],
                         'directory_port': 14443, 'subscription_port': 2096})

        def reconcile():
            return panel_module.reconcile(module, client, panel_module.validate(module.params))

        module.check_mode = True
        initial = reconcile()
        assert initial['changed'] and initial['inbound_id'] is None
        assert client.call('/panel/api/inbounds/list') == [], 'check mode created an inbound'
        checks.append('check mode leaves a fresh control database unchanged')
        module.check_mode = False
        created = reconcile()
        first_id = created['inbound_ids']['ingress-a']
        assert created['changed'] and not reconcile()['changed'], 'initial rerun was not idempotent'
        directory = client.call('/panel/api/inbounds/get/' + str(first_id))
        assert directory['disableFlow'] is False
        assert directory['settings']['clients'][0]['flow'] == 'xtls-rprx-vision'
        first_key = directory['streamSettings']['realitySettings']['privateKey']
        verify_entries([alice], [ingress_a])
        checks.append('real 3x-ui preserves REALITY, Vision, SNI, fingerprint and client credentials')

        def account_state():
            return {record['email']: (record['uuid'], record['subId'], record['enable'],
                                     tuple(record.get('inboundIds', [])))
                    for record in client.call('/panel/api/clients/list')}

        before_accounts = account_state()
        before_directories = client.call('/panel/api/inbounds/list')
        api_calls = []
        original_call = client.call

        def recorded_call(path, data=None):
            api_calls.append(path)
            return original_call(path, data)

        client.call = recorded_call
        module.params['subscription_public_url'] = 'https://subscriptions.example.com/'
        advertised = reconcile()
        assert advertised['changed'] and advertised['inbound_ids'] == created['inbound_ids']
        assert '/panel/api/setting/restartPanel' not in api_calls, 'URL-only update restarted the panel'
        assert client.call('/panel/api/setting/defaultSettings', {})['subURI'] == 'https://subscriptions.example.com/sub/'
        assert not reconcile()['changed'], 'public subscription URL rerun was not idempotent'
        module.params.pop('subscription_public_url')
        assert not reconcile()['changed'], 'omitting the public URL changed its stored override'
        fresh = panel_module.Panel(module.params['url'], module.params['username'], password)
        assert fresh.call('/panel/api/setting/all', {})['subURI'] == 'https://subscriptions.example.com/sub/'
        assert account_state() == before_accounts, 'public URL update changed existing identities'
        after_directories = client.call('/panel/api/inbounds/list')
        assert [(entry['id'], entry['settings'], entry['streamSettings']) for entry in after_directories] == [
            (entry['id'], entry['settings'], entry['streamSettings']) for entry in before_directories], 'public URL update changed directory profiles'
        verify_entries([alice], [ingress_a])
        checks.append('public HTTPS subscription metadata persists without panel restart or identity/profile changes')

        original = copy.deepcopy(alice)
        module.params['users'].append(bob)
        assert reconcile()['changed'] and not reconcile()['changed']
        assert alice == original, 'adding an account altered the original identity'
        verify_entries([alice, bob], [ingress_a])
        checks.append('adding an account retains the existing UUID and subscription ID')

        module.params['ingress_endpoints'].append(ingress_b)
        expanded = reconcile()
        assert expanded['changed'] and expanded['inbound_ids']['ingress-a'] == first_id
        assert not reconcile()['changed'], 'expanded rerun was not idempotent'
        verify_entries([alice, bob], [ingress_a, ingress_b])
        assert client.call('/panel/api/inbounds/get/' + str(first_id))['streamSettings']['realitySettings']['privateKey'] == first_key
        checks.append('adding a distinct-key ingress attaches all existing accounts and preserves old profile identities')

        module.params['ingress_endpoints'] = [ingress_b]
        assert reconcile()['changed'] and not reconcile()['changed']
        verify_entries([alice, bob], [ingress_b])
        checks.append('removing an owned ingress retires only its subscription profile')

        module.params['ingress_endpoints'] = [{'address': 'tls.example.com', 'port': 443,
                                             'remark': 'tls', 'security': 'tls'}]
        for record in module.params['users']:
            record.pop('flow', None)
        assert reconcile()['changed'] and not reconcile()['changed']
        for record in [alice, bob]:
            links = wait(lambda: subscription(record))
            assert len(links) == 1
            query = urllib.parse.parse_qs(links[0].query)
            assert query.get('security') == ['tls'] and 'pbk' not in query and 'flow' not in query
        checks.append('the original TLS mode remains compatible after owned-profile migration')
        for check in checks:
            print('PASS ' + check, flush=True)
        return checks
    finally:
        _, container_rc = cli('rm', '-f', '-v', name, required=False)
        _, volume_rc = cli('volume', 'rm', volume, required=False)
        if volume_rc:
            raise RuntimeError('isolated private fixture cleanup failed; inspect io.vless.test=reality-panel containers')
        print('PASS removed the isolated control container and its private database volume', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=['podman', 'docker'], default='podman')
    parser.add_argument('--image', default=os.environ.get('CONTROL_IMAGE', 'localhost/vless-control:dev'))
    args = parser.parse_args()
    try:
        run(args.engine, args.image)
        return 0
    except Exception as error:
        print('FAIL isolated REALITY panel integration: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
