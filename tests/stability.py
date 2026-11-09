#!/usr/bin/env python3
"""Live cache security checks for the existing Podman stand.

Do not run concurrently with stand.py test or tls.py. This test temporarily
stops the panel and changes only the lab ingress's private user cache. It
restores the original cache and starts the panel in a finally block, then
checks that both legitimate routes recover. Cached credentials are never
printed or passed through a shell.
"""
import copy
import json
from pathlib import Path
import tempfile
import time

import stand


CACHE = 'vless-in:/var/lib/node/users.json'


def put_cache(path, value):
    # File-based transfer avoids putting secret JSON into argv or shell text.
    stand.write(path, value)
    stand.pod('cp', path, CACHE)


def restart_ready():
    stand.pod('restart', 'vless-in')
    stand.wait(lambda: stand.ready('vless-in'))


def assert_denied(index):
    assert stand.pod('inspect', 'vless-client', '--format', '{{.State.Running}}') == 'true'
    try:
        stand.fetch(index)
    except RuntimeError:
        return
    raise AssertionError('client ' + str(index) + ' retained access after cache authorization expired')


def assert_cold_unready(seconds=5):
    # A cold ingress with no valid authoritative users must not expose readiness.
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        assert stand.pod('inspect', 'vless-in', '--format', '{{.State.Running}}') == 'true'
        assert not stand.ready('vless-in'), 'cold ingress became ready without valid user data'
        time.sleep(0.5)
    for index in [0, 1]:
        assert_denied(index)


def verify_routes():
    for index, label in enumerate(['a', 'b']):
        assert stand.wait(lambda: stand.fetch(index)) == stand.ip('vless-out-' + label)


def run():
    stand.STATE.mkdir(exist_ok=True)
    verify_routes()
    checks = []
    failure = None
    restore_errors = []
    with tempfile.TemporaryDirectory(prefix='cache-security-', dir=stand.STATE) as directory:
        original_path = Path(directory) / 'original-users.json'
        changed_path = Path(directory) / 'candidate-users.json'
        original = None
        try:
            # Wait for a durable authenticated snapshot before taking its backup.
            stand.wait(lambda: stand.pod('exec', 'vless-in', 'test', '-f',
                                        '/var/lib/node/users.json', check=False) == ''
                       and stand.pod('exec', 'vless-in', 'stat', '-c', '%s',
                                     '/var/lib/node/users.json', check=False))
            stand.pod('stop', 'vless-control')
            stand.pod('cp', CACHE, original_path)
            original_path.chmod(0o600)
            original = original_path.read_text()
            cached = json.loads(original)
            assert isinstance(cached['users'], list) and cached['users'], 'user cache is empty'

            # A fresh snapshot can still contain a user whose absolute expiry
            # has passed. That user alone must disappear during a panel outage.
            expiring = copy.deepcopy(cached)
            expiring['saved'] = int(time.time())
            matched = False
            for user in expiring['users']:
                if user['email'] == 'alice-a':
                    user['expiryTime'] = int(time.time() * 1000) - 1000
                    matched = True
                elif user['email'] == 'alice-b':
                    user['expiryTime'] = 0
            assert matched, 'lab alice-a identity not found in cached snapshot'
            put_cache(changed_path, expiring)
            restart_ready()
            assert_denied(0)
            assert stand.wait(lambda: stand.fetch(1)) == stand.ip('vless-out-b')
            checks.append('absolute user expiry is enforced locally during a panel outage')

            # Even otherwise-valid users must be removed past the stale ceiling.
            stale = copy.deepcopy(cached)
            stale['saved'] = 1
            put_cache(changed_path, stale)
            restart_ready()
            for index in [0, 1]:
                assert_denied(index)
            checks.append('stale cached user snapshot removes both authorizations')

            # A corrupt snapshot on a cold start cannot inherit authorizations
            # from the prior process or claim readiness.
            put_cache(changed_path, '{invalid-json')
            stand.pod('restart', 'vless-in')
            assert_cold_unready()
            checks.append('corrupt cache on a cold start remains unready and fails closed')

            # The same contract applies when no persisted snapshot exists.
            stand.pod('exec', 'vless-in', 'rm', '-f', '/var/lib/node/users.json')
            stand.pod('restart', 'vless-in')
            assert_cold_unready()
            checks.append('missing cache on a cold start remains unready and fails closed')
        except BaseException as error:
            failure = error
        finally:
            if original is not None:
                try:
                    put_cache(changed_path, original)
                except BaseException as error:
                    restore_errors.append('restore original user cache: ' + str(error))
            for name, restore in [
                ('start control', lambda: stand.pod('start', 'vless-control', check=False)),
                ('control authentication', lambda: stand.wait(stand.panel_session)),
                ('restart ingress', restart_ready),
                ('verify legitimate routes', verify_routes),
            ]:
                try:
                    restore()
                except BaseException as error:
                    restore_errors.append(name + ': ' + str(error))
    if restore_errors:
        raise RuntimeError('cache test restoration failed: ' + '; '.join(restore_errors)) from failure
    if failure is not None:
        raise failure
    checks.append('panel restoration recovers both valid client routes')
    for check in checks:
        print('PASS ' + check, flush=True)
    stand.write(stand.STATE / 'stability-test-results.json', {
        'passed': checks,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})


if __name__ == '__main__':
    run()
