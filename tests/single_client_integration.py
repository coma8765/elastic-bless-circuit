#!/usr/bin/env python3
"""Exercise single-client migration and UI management on a disposable 3x-ui.

Use the repository's Ansible Python environment. By default the fixture uses
local Podman and localhost/vless-control:single. For an isolated Docker fixture on
another machine, pass --engine docker --ssh user@host (passwordless sudo is
required). Only this test's private database is mounted. Published ports and
any SSH forwards listen on loopback. No VPN traffic is sent by this test.
"""
import argparse
import base64
import contextlib
import copy
import json
import secrets
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from reality_panel import Module, endpoint, panel_module, wait


EXITS = {'out': 'Kyrgyzstan', 'out-prague': 'Czechia',
         'out-frankfurt': 'Germany', 'out-singapore': 'Singapore'}
SELECTORS = {name: 0x4001 + index for index, name in enumerate(EXITS)}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class FixtureEngine:
    """Run the container on the chosen engine; always access its API via loopback."""

    def __init__(self, args):
        self.engine = args.engine
        self.target = args.ssh
        self.ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=12', '-p', str(args.ssh_port)]
        if args.identity_file:
            self.ssh += ['-o', 'IdentitiesOnly=yes', '-i', args.identity_file]

    def run(self, *args, check=True):
        cmd = [self.engine, *args]
        if self.target:
            cmd = [*self.ssh, self.target, shlex.join(['sudo', '-n', *cmd])]
        try:
            result = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
        except (subprocess.TimeoutExpired, OSError):
            raise RuntimeError('Fixture engine failed to finish ' + args[0]) from None
        if check and result.returncode:
            # The setting command and responses can include generated test credentials.
            raise RuntimeError('Fixture engine failed during ' + args[0])
        return result

    @contextlib.contextmanager
    def loopback_ports(self, name):
        remote = []
        for port in (2053, 2096):
            mapping = self.run('port', name, str(port) + '/tcp').stdout.strip()
            address, value = mapping.rsplit(':', 1)
            require(address == '127.0.0.1', 'Test port was not published on IPv4 loopback')
            remote.append(int(value))
        if not self.target:
            yield remote
            return
        with contextlib.ExitStack() as stack:
            sockets = [stack.enter_context(socket.socket()) for _ in remote]
            for sock in sockets:
                sock.bind(('127.0.0.1', 0))
            local = [sock.getsockname()[1] for sock in sockets]
        forward = [*self.ssh, '-N', '-o', 'ExitOnForwardFailure=yes']
        for here, there in zip(local, remote):
            forward += ['-L', f'127.0.0.1:{here}:127.0.0.1:{there}']
        process = subprocess.Popen([*forward, self.target], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        try:
            yield local
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@contextlib.contextmanager
def disposable_panel(args):
    runtime = FixtureEngine(args)
    name = 'vless-single-client-test-' + uuid.uuid4().hex[:14]
    volume = name + '-db'
    password = secrets.token_urlsafe(32)
    marker = 'io.vless.test=' + name
    options = ['--label', marker, '--memory', '256m', '--memory-swap', '256m',
               '--pids-limit', '128', '--no-healthcheck', '-v', volume + ':/etc/x-ui']
    # Refuse to run or clean anything with a preexisting name.
    require(runtime.run('volume', 'inspect', volume, check=False).returncode != 0
            and runtime.run('container', 'inspect', name, check=False).returncode != 0,
            'Fixture name collision')
    runtime.run('volume', 'create', '--label', marker, volume)
    container_id = None
    try:
        runtime.run('run', '--rm', '--network', 'none', *options, '--entrypoint', '/app/x-ui',
                    args.image, 'setting', '-username', 'fixture-admin', '-password', password,
                    '-port', '2053', '-webBasePath', '/')
        container_id = runtime.run('run', '-d', '--name', name, *options,
                                   '-p', '127.0.0.1::2053/tcp', '-p', '127.0.0.1::2096/tcp',
                                   '--entrypoint', '/usr/bin/tini', args.image, '--', '/app/x-ui').stdout.strip()
        with runtime.loopback_ports(name) as (api_port, sub_port):
            url = f'http://127.0.0.1:{api_port}'
            try:
                api = wait(lambda: panel_module.Panel(url, 'fixture-admin', password))
            except RuntimeError:
                raise RuntimeError('Isolated 3x-ui admin login did not become ready') from None
            require(api.call('/panel/api/clients/list') == [] and api.call('/panel/api/inbounds/list') == [],
                    'Expected a fresh test database')
            yield api, url, sub_port, password
    finally:
        if not container_id:
            # A timed-out detached run may still have created its container.
            lookup = runtime.run('container', 'inspect', '--format', '{{.Id}}', name, check=False)
            if lookup.returncode == 0:
                container_id = lookup.stdout.strip()
        if container_id:
            owned = runtime.run('inspect', '--format', '{{.Id}} {{index .Config.Labels "io.vless.test"}}',
                                container_id).stdout.strip()
            require(owned == f'{container_id} {name}', 'Fixture container ownership changed')
            runtime.run('rm', '-f', container_id)
        owner = runtime.run('volume', 'inspect', '--format', '{{index .Labels "io.vless.test"}}',
                            volume).stdout.strip()
        require(owner == name, 'Fixture volume ownership changed')
        runtime.run('volume', 'rm', volume)


def subscription(sub_port, token, *, expect_missing=False):
    url = f'http://127.0.0.1:{sub_port}/sub/' + urllib.parse.quote(token, safe='')
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            raw = response.read(65537)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return []
        raise RuntimeError('Unexpected subscription HTTP status ' + str(error.code)) from None
    require(not expect_missing, 'Inactive subscription should return HTTP 404')
    require(len(raw) <= 65536, 'Oversize test subscription')
    if not raw.strip():
        return []
    if not raw.startswith(b'vless://'):
        raw = base64.b64decode(b''.join(raw.split()), validate=True)
    return [urllib.parse.urlsplit(line) for line in raw.decode().strip().splitlines()]


def check_profiles(sub_port, token, identifier, endpoints):
    expected = {}
    for ep in endpoints:
        choices = [(EXITS[name], SELECTORS[name]) for name in ep.get('subscription_exits') or EXITS]
        if ep.get('auto_selector') is not None:
            choices.append(('Auto', ep['auto_selector']))
        for label, selector in choices:
            parts = identifier.split('-')
            parts[2] = format(selector, '04x')
            expected[(ep['address'], '-'.join(parts))] = (ep, ep['display_country'] + ' -> ' + label)
    links = subscription(sub_port, token)
    require(len(links) == len(expected), 'Incorrect number of native subscription profiles')
    for link in links:
        key = (link.hostname, link.username)
        if link.scheme != 'vless' or key not in expected:
            groups = (link.username or '').split('-')
            base = identifier.split('-')
            same_base = len(groups) == 5 and groups[:2] + groups[3:] == base[:2] + base[3:]
            selector = groups[2] if len(groups) == 5 else '<invalid>'
            raise AssertionError(f'Unexpected route at {link.hostname}; selector={selector}, '
                                 f'matches non-selector UUID groups={same_base}, '
                                 f'label={urllib.parse.unquote(link.fragment)}')
        ep, label = expected.pop(key)
        q = urllib.parse.parse_qs(link.query, keep_blank_values=True)
        require(link.port == ep['port'] and urllib.parse.unquote(link.fragment) == label,
                'Incorrect country pair or public port')
        incorrect = [k for k, v in {
            'security': 'reality', 'flow': 'xtls-rprx-vision',
            'sni': ep['reality_server_name'], 'pbk': ep['reality_public_key'],
            'sid': ep['reality_short_id'], 'fp': ep['reality_fingerprint'],
        }.items() if q.get(k) != [v]]
        require(not incorrect, f'Incorrect REALITY/Vision fields for {label}: {incorrect}')


def exercise(api, url, sub_port, password):
    ends = [endpoint('in'), endpoint('in-prague')]
    ends[0].update(display_country='Russia')
    ends[1].update(display_country='Czechia', subscription_exits=['out-prague'])
    owner, token, base_uuid = 'alice', secrets.token_urlsafe(24), str(uuid.uuid4())
    rows = [dict(email=owner if name == 'out' else owner + '--' + name,
                 uuid=base_uuid if name == 'out' else str(uuid.uuid4()),
                 subscription_owner=owner, sub_id=token, exit=name, exit_display_country=country,
                 enabled=True) for name, country in EXITS.items()]
    params = dict(url=url, username='fixture-admin', password=password, users=rows,
                  ingress_endpoints=ends, directory_port=14443, subscription_port=2096)

    def reconcile(**options):
        module = Module(copy.deepcopy(dict(params, **options)))
        return panel_module.reconcile(module, api, panel_module.validate(module.params))

    def clients():
        return {r['email']: r for r in api.call('/panel/api/clients/list')}

    def update(email, **values):
        original = clients()[email]
        payload = panel_module.client_payload(original)
        payload.update(values)
        api.call('/panel/api/clients/update/' + urllib.parse.quote(email, safe=''), payload)

    def membership(email, action, inbound):
        api.call('/panel/api/clients/' + urllib.parse.quote(email, safe='') + '/' + action,
                 {'inboundIds': [inbound]})

    before = reconcile()
    directory_ids = before['inbound_ids']
    require(set(clients()) == {r['email'] for r in rows}, 'Legacy fixture requires four panel rows')

    observed = set()

    def legacy_subscription_ready():
        try:
            links = subscription(sub_port, token)
        except RuntimeError as error:
            observed.add(str(error))
            return None
        observed.add(str(len(links)) + ' profiles')
        return links if len(links) == 5 else None

    # The real settings reload can briefly answer 404 on a fresh volume.
    try:
        wait(legacy_subscription_ready, seconds=20)
    except RuntimeError:
        raise RuntimeError(f'Legacy subscription failed to publish five profiles; observed {sorted(observed)}') from None
    original_db_id = clients()[owner]['id']
    single = dict(client_mode='single', route_selectors=SELECTORS, exit_countries=EXITS)
    migrate = dict(single, migrate_single_clients=True)
    child = rows[1]['email']
    comment = clients()[child]['comment']
    update(child, comment='unrelated operator')
    refused = False
    try:
        reconcile(**migrate)
    except panel_module.PanelError:
        refused = True
    require(refused and set(clients()) == {r['email'] for r in rows},
            'Migration must refuse unowned child deletion and preserve existing clients')
    update(child, comment=comment)
    migrated = reconcile(**migrate)
    records = clients()
    require(migrated['inbound_ids'] == directory_ids and set(records) == {owner},
            'Migration must keep both directories and exactly one native client')
    require((records[owner]['id'], records[owner]['uuid'], records[owner]['subId']) ==
            (original_db_id, base_uuid, token), 'Migration changed the base identity or subscription token')
    require(set(records[owner]['inboundIds']) == set(directory_ids.values()),
            'Owner was not attached to both managed inbounds')
    check_profiles(sub_port, token, base_uuid, ends)
    require(not reconcile(**single)['changed'], 'Single-client directory rerun changed steady state')
    print('PASS one migrated client owns both inbounds and all four exit choices')

    ends[0]['auto_selector'] = 16420
    reconcile(**single, defer_new_auto=True)
    check_profiles(sub_port, token, base_uuid, [dict(ends[0], auto_selector=None), ends[1]])
    reconcile(**single)
    check_profiles(sub_port, token, base_uuid, ends)
    require(not reconcile(**single, defer_new_auto=True)['changed'], 'A staged rerun removed a published Auto')
    print('PASS original subscription gains Auto only on its opted-in ingress after publication')

    inbound = directory_ids['in-prague']
    membership(owner, 'detach', inbound)
    reconcile(**single)
    require(set(clients()[owner]['inboundIds']) == {directory_ids['in']},
            'Reconcile restored a membership removed through the UI')
    check_profiles(sub_port, token, base_uuid, ends[:1])
    membership(owner, 'attach', inbound)
    check_profiles(sub_port, token, base_uuid, ends)

    newcomer = 'operator-added@example.com'
    newcomer_id, newcomer_token = str(uuid.uuid4()), secrets.token_urlsafe(24)
    api.call('/panel/api/clients/add', {'client': {
        'email': newcomer, 'id': newcomer_id, 'subId': newcomer_token,
        'flow': 'xtls-rprx-vision', 'enable': True}, 'inboundIds': list(directory_ids.values())})
    check_profiles(sub_port, newcomer_token, newcomer_id, ends)
    update(newcomer, comment='created in the panel')
    reconcile(**single)
    require(clients()[newcomer]['comment'] == 'created in the panel', 'UI metadata edit was lost')
    print('PASS UI-created account publishes native links and UI membership edits survive reconcile')

    membership(owner, 'detach', inbound)
    frankfurt = endpoint('in-frankfurt')
    frankfurt.update(display_country='Germany', subscription_exits=['out-frankfurt'])
    ends.append(frankfurt)
    expanded = reconcile(**single)['inbound_ids']
    require(set(expanded) == {'in', 'in-prague', 'in-frankfurt'} and
            set(clients()[newcomer]['inboundIds']) == set(expanded.values()),
            'New ingress was not attached to the account with all existing inbounds')
    require(set(clients()[owner]['inboundIds']) == {directory_ids['in']},
            'New ingress broadened a restricted account')
    require(not reconcile(**single)['changed'], 'Rerun changed membership after adding a new ingress')
    check_profiles(sub_port, newcomer_token, newcomer_id, ends)
    check_profiles(sub_port, token, base_uuid, ends[:1])
    membership(owner, 'attach', inbound)
    membership(owner, 'attach', expanded['in-frankfurt'])
    check_profiles(sub_port, token, base_uuid, ends)
    print('PASS new ingress extends full membership and keeps restricted membership intact')

    update(owner, enable=False)
    reconcile(**single)
    require(not clients()[owner]['enable'], 'Reconcile re-enabled the disabled owner')
    subscription(sub_port, token, expect_missing=True)
    update(owner, enable=True, expiryTime=int(time.time() * 1000) - 60_000)
    reconcile(**single)
    require(0 < clients()[owner]['expiryTime'] < int(time.time() * 1000),
            'Reconcile reset the absolute expiry')
    subscription(sub_port, token, expect_missing=True)
    check_profiles(sub_port, newcomer_token, newcomer_id, ends)
    update(owner, expiryTime=0, enable=True)
    check_profiles(sub_port, token, base_uuid, ends)
    for inbound_id in expanded.values():
        membership(owner, 'detach', inbound_id)
    reconcile(**single)
    require(not clients()[owner].get('inboundIds'), 'Reconcile restored all-detached memberships')
    subscription(sub_port, token, expect_missing=True)
    membership(owner, 'attach', expanded['in'])
    check_profiles(sub_port, token, base_uuid, ends[:1])
    membership(owner, 'detach', expanded['in'])
    api.call('/panel/api/clients/bulkAttach', {'emails': [owner], 'inboundIds': list(expanded.values())})
    check_profiles(sub_port, token, base_uuid, ends)
    api.call('/panel/api/clients/del/' + owner, {})
    reconcile(**single)
    require(set(clients()) == {newcomer}, 'Reconcile recreated a deleted inventory owner')
    subscription(sub_port, token, expect_missing=True)
    check_profiles(sub_port, newcomer_token, newcomer_id, ends)
    print('PASS disable, expiry, last detach and deletion each return HTTP 404; reactivation restores access')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=['docker', 'podman'], default='podman')
    parser.add_argument('--image', default='localhost/vless-control:single')
    parser.add_argument('--ssh', help='Run a disposable fixture on this SSH host with sudo -n')
    parser.add_argument('--ssh-port', type=int, default=22)
    parser.add_argument('--identity-file')
    args = parser.parse_args()
    with disposable_panel(args) as fixture:
        exercise(*fixture)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('FAIL single-client integration: ' + str(error), file=sys.stderr)
        sys.exit(1)
