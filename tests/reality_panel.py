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

    def subscription(record, allowed_uuids=None, allow_empty=False):
        raw = urllib.request.urlopen('http://127.0.0.1:' + str(subscription_port) + '/sub/' +
                                     urllib.parse.quote(record['sub_id'], safe=''), timeout=15).read()
        body = raw.decode() if raw.startswith(b'vless://') else base64.b64decode(raw).decode()
        links = [urllib.parse.urlsplit(line) for line in body.splitlines() if line.startswith('vless://')]
        if not allow_empty:
            assert links, 'subscription has no VLESS entries'
        allowed = set(allowed_uuids) if allowed_uuids is not None else {record['uuid']}
        assert all(link.username in allowed for link in links), 'subscription changed the assigned UUID'
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

        alias = {'address': 'public-alias.example.com', 'port': 8443, 'remark': 'public'}
        ingress_a['aliases'] = [alias]
        aliased = reconcile()
        assert aliased['changed'] and aliased['inbound_ids'] == created['inbound_ids']
        assert not reconcile()['changed'], 'alias addition rerun was not idempotent'
        expected_alias = dict(ingress_a, address=alias['address'], port=alias['port'])
        verify_entries([alice], [ingress_a, expected_alias])
        links = subscription(alice)
        assert len(links) == 2 and {(link.hostname, link.port) for link in links} == {
            (ingress_a['address'], ingress_a['port']), (alias['address'], alias['port'])}
        assert account_state() == before_accounts, 'alias addition changed UUID, subscription ID or membership'
        directories = client.call('/panel/api/inbounds/list')
        assert len(directories) == 1 and directories[0]['id'] == first_id
        assert directories[0]['streamSettings']['realitySettings']['privateKey'] == first_key
        checks.append('adding an advertised alias emits two same-key profiles without changing directory or user identities')
        ingress_a['aliases'] = []
        assert reconcile()['changed'] and not reconcile()['changed'], 'alias removal was not idempotent'
        verify_entries([alice], [ingress_a])
        assert account_state() == before_accounts
        assert client.call('/panel/api/inbounds/get/' + str(first_id))['streamSettings']['realitySettings']['privateKey'] == first_key
        checks.append('removing an alias retires only its advertised link and retains the physical ingress')

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
        tls = module.params['ingress_endpoints'][0]
        tls['aliases'] = [{'address': 'tls-alias.example.com', 'port': 8443, 'remark': 'public'}]
        before_tls_accounts = account_state()
        tls_ids = reconcile()['inbound_ids']
        assert not reconcile()['changed']
        for record in [alice, bob]:
            links = wait(lambda: subscription(record))
            assert len(links) == 2 and {(link.hostname, link.port) for link in links} == {
                ('tls.example.com', 443), ('tls-alias.example.com', 8443)}
            for link in links:
                query = urllib.parse.parse_qs(link.query)
                assert query.get('security') == ['tls'] and query.get('sni') == ['tls.example.com']
                assert 'pbk' not in query and 'flow' not in query
        assert account_state() == before_tls_accounts
        tls['aliases'] = []
        assert reconcile()['inbound_ids'] == tls_ids and not reconcile()['changed']
        assert all(len(subscription(record)) == 1 for record in [alice, bob])
        checks.append('TLS aliases inherit the primary SNI and retain the same directory and user memberships')

        # One existing account exposes independent outbound choices through one
        # unchanged token. The original protocol identity remains the first choice.
        route_spec = importlib.util.spec_from_file_location('vless_user_routes', ROOT / 'deploy/ansible/library/vless_user_routes.py')
        route_module = importlib.util.module_from_spec(route_spec)
        route_spec.loader.exec_module(route_module)
        ingress_a['aliases'] = [{'address': 'public.example.com', 'port': 443, 'remark': 'public'}]
        module.params['ingress_endpoints'] = [ingress_a]
        module.params['users'] = [alice, bob]
        migration = reconcile()
        api_calls.clear()
        repeated = reconcile()
        assert migration['changed'], 'grouped baseline migration should change the profile'
        assert not repeated['changed'], 'grouped baseline migration repeated writes: ' + ','.join(api_calls)
        grouped_id = reconcile()['inbound_ids']['ingress-a']
        grouped_key = client.call('/panel/api/inbounds/get/' + str(grouped_id))['streamSettings']['realitySettings']['privateKey']
        original_owner = (alice['uuid'], alice['sub_id'])
        choices = ['exit-alice', 'prague', 'frankfurt', 'singapore']
        base = {'email': alice['email'], 'exit': choices[0], 'additional_exits': choices[1:]}
        persisted_uuids = {alice['email']: alice['uuid']}
        def grouped_users():
            expanded = route_module.expand([base], choices)
            result = []
            for item in expanded:
                identity = persisted_uuids.setdefault(item['email'], str(uuid.uuid4()))
                result.append(dict(email=item['email'], exit=item['exit'], uuid=identity,
                                   sub_id=alice['sub_id'], enabled=item['enabled'], subscription_owner=alice['email']))
            return result
        grouped = grouped_users()
        module.params['users'] = grouped + [bob]
        assert reconcile()['changed'] and not reconcile()['changed']
        assert len({record['sub_id'] for record in module.params['users'] if record['email'] != bob['email']}) == 4, 'grouped identities need unique backend tokens'
        allowed = {record['uuid'] for record in grouped}
        links = subscription(alice, allowed)
        assert len(links) == 8, 'four outbound identities and two aliases must yield eight profiles'
        assert {(link.username, link.hostname, link.port) for link in links} == {
            (identity, address, 443) for identity in allowed for address in
            [ingress_a['address'], 'public.example.com']}, 'grouped subscription has wrong profile cross product'
        assert len({urllib.parse.unquote(link.fragment) for link in links}) == 8, 'grouped profile labels must be unique'
        assert (alice['uuid'], alice['sub_id']) == original_owner
        assert reconcile()['inbound_ids']['ingress-a'] == grouped_id
        assert client.call('/panel/api/inbounds/get/' + str(grouped_id))['streamSettings']['realitySettings']['privateKey'] == grouped_key
        verify_entries([bob], [ingress_a, dict(ingress_a, address='public.example.com')])
        checks.append('one original subscription exposes eight uniquely labeled profiles for four identities and two aliases')
        # An operator-owned disabled link must survive every managed group edit.
        external_path = '/panel/api/clients/' + urllib.parse.quote(alice['email'], safe='') + '/externalLinks'
        owner_path = '/panel/api/clients/get/' + urllib.parse.quote(alice['email'], safe='')
        operator_link = {'kind': 'link', 'value': 'vless://' + str(uuid.uuid4()) + '@operator.example.com:443?security=tls&type=tcp#operator',
                         'remark': 'vless-mesh-ansible:operator-preserved', 'enable': False,
                         'expiryTime': 4102444800000, 'namePrefix': 'operator-'}
        owner_record = client.call(owner_path)
        client.call(external_path, {'externalLinks': (owner_record.get('externalLinks') or []) + [operator_link]})
        operator_before = [row for row in client.call(owner_path)['externalLinks'] if row.get('remark') == operator_link['remark']]
        assert len(operator_before) == 1
        reconcile()  # Canonicalizes managed-vs-operator ordering once.
        assert not reconcile()['changed']
        assert all(operator_before[0].get(key) == value for key,value in operator_link.items())

        removed = next(record for record in grouped if record['exit'] == 'frankfurt')
        base['additional_exits'].remove('frankfurt')
        module.params['users'] = grouped_users() + [bob]
        assert reconcile()['changed'] and not reconcile()['changed']
        active = {record['uuid'] for record in module.params['users'] if record['email'] != bob['email']}
        assert len(subscription(alice, active)) == 6
        stored = {record['email']:record for record in client.call('/panel/api/clients/list')}
        assert stored[removed['email']]['uuid'] == removed['uuid'] and not stored[removed['email']]['enable']
        base['additional_exits'] = choices[1:]
        module.params['users'] = grouped_users() + [bob]
        assert reconcile()['changed'] and not reconcile()['changed']
        assert len(subscription(alice, allowed)) == 8
        assert (alice['uuid'], alice['sub_id']) == original_owner
        checks.append('removing and readding an outbound choice retains its UUID and the original subscription token')
        base['enabled'] = False
        module.params['users'] = grouped_users() + [bob]
        assert reconcile()['changed'] and not reconcile()['changed']
        disabled_links = subscription(alice, allowed, allow_empty=True)
        # 3x-ui retains its base account's two native share links even when
        # disabled; authentication revocation is the global enable flag.
        assert all(link.username == alice['uuid'] for link in disabled_links), 'disabled child choice still advertised'
        stored = {record['email']:record for record in client.call('/panel/api/clients/list')}
        assert all(not stored[record['email']]['enable'] for record in grouped)
        disabled_rows = [row for row in client.call(owner_path)['externalLinks'] if urllib.parse.urlsplit(row.get('value','')).username in allowed - {alice['uuid']}]
        assert len(disabled_rows) == 6 and all(not row['enable'] for row in disabled_rows)
        assert stored[bob['email']]['enable'], 'disabling a subscription affected an unrelated account'
        base['enabled'] = True
        module.params['users'] = grouped_users() + [bob]
        assert reconcile()['changed'] and not reconcile()['changed']
        assert len(subscription(alice, allowed)) == 8
        operator_after = [row for row in client.call(owner_path)['externalLinks'] if row.get('remark') == operator_link['remark']]
        assert len(operator_after) == 1 and all(operator_after[0].get(key) == value for key,value in operator_link.items())
        checks.append('disabling the base revokes every grouped identity while an unrelated subscription remains active')
        checks.append('native subscription composition preserves unrelated operator external links across choice edits')

        # Imported accounts retain their existing protocol identity and base
        # subscription token. Absolute expiry applies to every routed identity.
        baseline_accounts = account_state()
        imported = user('import@example.test')
        imported.update(exit='out', expiry_time=4102444800000, metadata={
            'comment': 'Original operator note', 'source_email': 'original display name', 'source_uuid': 'legacy-short-id',
            'original_expiry_time': -7776000000, 'created_at': 1700000000000,
            'updated_at': 1700000001000, 'tg_id': '123456789', 'group': '', 'reset': 0,
            'password': 'retained-protocol-password', 'auth': 'retained-auth', 'security': 'auto'})
        imported_child = user('import@example.test--prague')
        imported_child.update(exit='prague', sub_id=imported['sub_id'],
                              subscription_owner=imported['email'], expiry_time=imported['expiry_time'])
        original_import_identity = (imported['uuid'], imported['sub_id'])
        module.params['users'].extend([imported, imported_child])
        assert reconcile()['changed'] and not reconcile()['changed'], 'import rerun changed preserved account data'
        imported_path = '/panel/api/clients/get/' + urllib.parse.quote(imported['email'], safe='')
        imported_record = client.call(imported_path)['client']
        comment = json.loads(imported_record['comment'])
        assert comment['source_comment'] == imported['metadata']['comment']
        for key in ['source_email', 'source_uuid', 'original_expiry_time', 'created_at', 'updated_at']:
            assert comment['source_metadata'][key] == imported['metadata'][key], 'source audit metadata was lost'
        assert panel_module.ownership(imported_record), 'import metadata replaced the ownership marker'
        for source_key, api_key in [('tg_id', 'tgId'), ('password', 'password'), ('auth', 'auth'),
                                    ('security', 'security'), ('group', 'group'), ('reset', 'reset')]:
            expected = int(imported['metadata'][source_key]) if source_key == 'tg_id' else imported['metadata'][source_key]
            assert imported_record[api_key] == expected, 'source field was not preserved: ' + source_key
        imported_rows = {row['email']: row for row in client.call('/panel/api/clients/list')}
        assert all(imported_rows[row['email']]['expiryTime'] == imported['expiry_time'] for row in [imported, imported_child])
        assert (imported_record['uuid'], imported_record['subId']) == original_import_identity
        assert len(subscription(imported, {imported['uuid'], imported_child['uuid']})) == 4
        assert all(account_state()[email] == state for email, state in baseline_accounts.items())
        checks.append('imported identities, source metadata and absolute expiry persist across all exit choices and reruns')

        blank_metadata = user('import-blank-metadata')
        blank_metadata.update(metadata={'comment': '', 'tg_id': 0, 'group': '', 'reset': 0,
                                        'password': '', 'auth': '', 'security': ''})
        module.params['users'].append(blank_metadata)
        assert reconcile()['changed'] and not reconcile()['changed'], 'empty imported metadata was not idempotent'
        blank_record = client.call('/panel/api/clients/get/' + blank_metadata['email'])['client']
        assert all(blank_record[key] == '' for key in ['password', 'auth', 'security', 'group'])
        assert blank_record['tgId'] == 0 and blank_record['reset'] == 0
        assert json.loads(blank_record['comment'])['source_comment'] == ''
        checks.append('empty imported protocol metadata remains empty and idempotent')

        disabled = user('import-disabled')
        disabled.update(enabled=False, expiry_time=-2592000000,
                        metadata={'comment': 'Awaiting first-use support', 'original_expiry_time': -2592000000})
        disabled_child = user('import-disabled--prague')
        disabled_child.update(enabled=False, expiry_time=disabled['expiry_time'], exit='prague',
                              subscription_owner=disabled['email'], sub_id=disabled['sub_id'])
        module.params['users'].extend([disabled, disabled_child])
        assert reconcile()['changed'] and not reconcile()['changed']
        stored = {row['email']: row for row in client.call('/panel/api/clients/list')}
        assert all(not stored[row['email']]['enable'] and stored[row['email']]['expiryTime'] == -2592000000
                   for row in [disabled, disabled_child]), 'disabled first-use policy was activated or erased'
        disabled['enabled'] = disabled_child['enabled'] = True
        try:
            panel_module.validate(module.params)
        except panel_module.PanelError:
            pass
        else:
            raise AssertionError('unsupported active first-use policy passed validation')
        disabled['enabled'] = disabled_child['enabled'] = False
        assert not reconcile()['changed']
        checks.append('disabled first-use policies remain disabled and retain their original duration; activation is rejected')

        try:
            client.call('/panel/api/clients/add', {'client': {
                'email': 'invalid space', 'id': str(uuid.uuid4()), 'subId': secrets.token_urlsafe(24),
                'enable': False}, 'inboundIds': [grouped_id]})
        except panel_module.PanelError:
            pass
        else:
            raise AssertionError('pinned panel unexpectedly accepted a whitespace email')
        assert not any(row['email'] == 'invalid space' for row in client.call('/panel/api/clients/list'))
        checks.append('pinned panel accepts preserved email addresses and rejects whitespace labels before adoption')

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
        import traceback
        location = traceback.extract_tb(error.__traceback__)[-1]
        print('FAIL isolated REALITY panel integration at ' + Path(location.filename).name + ':' + str(location.lineno) + ': ' + (str(error) or type(error).__name__), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
