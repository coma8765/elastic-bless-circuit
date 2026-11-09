#!/usr/bin/env python3
"""Optional TLS integration check against an already-running local stand.

Temporarily updates the lab ingress, directory inbound and test client, then
restores them even when a check fails. Do not run concurrently with stand tests.
The generated lab certificate is verified by an explicit SHA-256 leaf pin.
"""
import base64
import copy
import hashlib
import json
import socket
import ssl
import subprocess
import time
import urllib.request

import stand


def recreate_client():
    stand.pod('rm', '-f', 'vless-client', check=False)
    stand.start(
        'vless-client', 'localhost/vless-node:dev',
        args=['xray', 'run', '-config', '/client.json'],
        mounts=[(stand.STATE / 'client.json', '/client.json:ro')],
        options=['-p', '127.0.0.1:11080:1080', '-p', '127.0.0.1:11081:1081'])


def tls_probe():
    # This checks the actual public port negotiates TLS before proxy requests.
    context = ssl.create_default_context(cafile=str(stand.STATE / 'secrets/tls-test-cert.pem'))
    with socket.create_connection(('127.0.0.1', 14443), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname='vless-lab.test') as secure:
            return secure.version()


def stream_object(value):
    return json.loads(value) if isinstance(value, str) else copy.deepcopy(value)


def run():
    in_path = stand.STATE / 'in.yaml'
    client_path = stand.STATE / 'client.json'
    original_in = in_path.read_text()
    original_client = client_path.read_text()
    config = json.loads(original_in)
    client = json.loads(original_client)
    inbound_id = config['panel']['inbound_id']
    api = stand.wait(stand.panel_session)
    original_inbound = api('/panel/api/inbounds/get/' + str(inbound_id))
    changed_inbound = copy.deepcopy(original_inbound)
    secret_dir = stand.STATE / 'secrets'
    cert = secret_dir / 'tls-test-cert.pem'
    key = secret_dir / 'tls-test-key.pem'
    subprocess.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1',
         '-nodes', '-subj', '/CN=vless-lab.test', '-addext','subjectAltName=DNS:vless-lab.test','-addext','basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    cert.chmod(0o600)
    key.chmod(0o600)
    certificate = {'certificateFile': '/run/secrets/tls-test-cert.pem',
                   'keyFile': '/run/secrets/tls-test-key.pem'}
    stream = {'network': 'tcp', 'security': 'tls',
              'tlsSettings': {'certificates': [certificate]}}
    config['listener']['stream'] = stream
    directory_stream = stream_object(original_inbound['streamSettings'])
    external = directory_stream.get('externalProxy', [])
    for proxy in external:
        proxy['forceTls'] = 'same'
    directory_stream.update(copy.deepcopy(stream))
    directory_stream['externalProxy'] = external
    changed_inbound['streamSettings'] = directory_stream
    for outbound in client['outbounds']:
        if outbound['protocol'] == 'vless':
            outbound['streamSettings'] = {
                'network': 'tcp', 'security': 'tls',
                'tlsSettings': {'serverName': 'vless-lab.test', 'pinnedPeerCertSha256': fingerprint}}
    checks = []
    failure = None
    restore_errors = []
    try:
        api('/panel/api/inbounds/update/' + str(inbound_id), changed_inbound)
        stand.write(in_path, config)
        stand.write(client_path, client)
        stand.pod('restart', 'vless-in')
        stand.wait(lambda: stand.ready('vless-in'))
        recreate_client()
        negotiated = stand.wait(tls_probe)
        assert negotiated in ('TLSv1.2', 'TLSv1.3'), negotiated
        checks.append('public VLESS port negotiates ' + negotiated)
        for index, label in enumerate(['a', 'b']):
            assert stand.wait(lambda: stand.fetch(index)) == stand.ip('vless-out-' + label)
        checks.append('both client UUIDs route through their assigned exits over public TLS')
        assert 'Example Domain' in stand.fetch(0, 'https://example.com')
        checks.append('internet HTTPS succeeds through TLS ingress and mesh transit')
        raw = urllib.request.urlopen(
            'http://127.0.0.1:12096/sub/lab-alice-a', timeout=10).read()
        links = raw.decode() if raw.startswith(b'vless://') else base64.b64decode(raw).decode()
        assert 'security=tls' in links, 'subscription did not advertise TLS'
        checks.append('3x-ui subscription advertises public TLS ingress')
    except BaseException as error:
        failure = error
    finally:
        # Keep every restore attempt independent so a panel outage cannot stop
        # local client/ingress restoration, or vice versa.
        for name, restore in [
            ('panel inbound', lambda: stand.wait(stand.panel_session)(
                '/panel/api/inbounds/update/' + str(inbound_id), original_inbound)),
            ('ingress YAML', lambda: stand.write(in_path, original_in)),
            ('client JSON', lambda: stand.write(client_path, original_client)),
            ('ingress restart', lambda: stand.pod('restart', 'vless-in')),
            ('client recreation', recreate_client),
        ]:
            try:
                restore()
            except BaseException as error:
                restore_errors.append(name + ': ' + str(error))
    if restore_errors:
        raise RuntimeError('TLS test restoration failed: ' + '; '.join(restore_errors)) from failure
    if failure is not None:
        raise failure
    for index, label in enumerate(['a', 'b']):
        assert stand.wait(lambda: stand.fetch(index)) == stand.ip('vless-out-' + label)
    checks.append('original lab configuration restored and both routes verified')
    for check in checks:
        print('PASS ' + check, flush=True)
    stand.write(stand.STATE / 'tls-test-results.json', {
        'passed': checks,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})


if __name__ == '__main__':
    run()
