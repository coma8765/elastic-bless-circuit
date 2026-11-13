#!/usr/bin/env python3
"""Exercise the generated ingress, geographic gateway and exits in one offline Podman namespace.

Build the node image, cache docker.io/library/python:3.13-slim, then run
python3 tests/geoip_gateway.py --image localhost/vless-node:dev. The two images
must use compatible Debian/Python runtimes. Only the disposable container needs
NET_ADMIN to assign synthetic destination IPs to its own loopback interface.
"""
import argparse
import contextlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid


# These IPs exist only on the fixture's loopback. Its synthetic country file
# maps the first to DE, the second to FR and leaves the third unmatched.
DE, FR, UNKNOWN = '11.0.0.10', '12.0.0.10', '13.0.0.10'
COUNTRY_HOST = 'destination.gateway.test'
AUTO, MANUAL = 0x4fa0, 0x4fb0
PROBE_PORT, HTTP_PORT = 14443, 18080
# An overlapping name intentionally catches Xray balancer prefix-selector leaks.
EXITS = {'west': '127.0.0.2', 'east': '127.0.0.3', 'west-extra': '127.0.0.4'}


def country_data():
    """Encode GeoIPList -> GeoIP -> CIDR with /32 entries; proto fields are all <128 bytes."""
    def field(number, value):
        return bytes((number << 3 | 2, len(value))) + value

    def entry(code, ip):
        cidr = field(1, ipaddress.ip_address(ip).packed) + bytes((2 << 3, 32))
        return field(1, field(1, code.encode()) + field(2, cidr))

    return entry('DE', DE) + entry('FR', FR)


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: {(result.stderr or result.stdout)[-1500:]}')
    return result


def secret(path):
    path.write_text(str(uuid.uuid4()))
    return str(path)


def render(folder, name, config, users=()):
    policy = folder / (name + '.yaml')
    policy.write_text(json.dumps(config))
    snapshot = folder / (name + '.users.json')
    snapshot.write_text(json.dumps(list(users)))
    result = command('node-agent', 'render', str(policy), str(snapshot))
    return json.loads(result.stdout)


class Xray:
    def __init__(self, folder, name, config):
        self.name = name
        self.path = folder / (name + '.json')
        self.path.write_text(json.dumps(config))
        self.port = config['inbounds'][0]['port']
        self.process = None
        self.log = folder / (name + '.log')
        command('xray', 'run', '-test', '-config', str(self.path))

    def start(self):
        with self.log.open('a') as log:
            self.process = subprocess.Popen(['xray', 'run', '-config', str(self.path)],
                                            stdout=log, stderr=subprocess.STDOUT)
        until = time.monotonic() + 5
        while time.monotonic() < until and self.process.poll() is None:
            with socket.socket() as sock:
                if sock.connect_ex(('127.0.0.1', self.port)) == 0:
                    return
            time.sleep(0.05)
        raise RuntimeError(f'{self.name} did not start: {self.log.read_text()[-1500:]}')

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)


def run_fixture(folder, stack):
    env_assets = Path(os.environ['XRAY_LOCATION_ASSET'])
    # Check the pinned release before replacing it with deterministic on-wire fixtures.
    country_check = folder / 'country-check.json'
    country_check.write_text(json.dumps({
        'outbounds': [{'tag': 'block', 'protocol': 'blackhole'}],
        'routing': {'rules': [{'ip': ['ext:country-geoip.dat:' + code for code in ('de', 'us', 'cz', 'sg')],
                               'outboundTag': 'block'}]},
    }))
    command('xray', 'run', '-test', '-config', str(country_check))
    print('PASS packaged country data includes DE, US, CZ and SG', flush=True)
    for asset in env_assets.glob('*.dat'):
        if asset.name != 'country-geoip.dat':
            (folder / asset.name).symlink_to(asset)
    (folder / 'country-geoip.dat').write_bytes(country_data())
    os.environ['XRAY_LOCATION_ASSET'] = str(folder)
    for ip in (DE, FR, UNKNOWN):
        command('ip', 'addr', 'add', ip + '/32', 'dev', 'lo')

    ca, key = folder / 'fixture.crt', folder / 'fixture.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=GeoIP gateway test', '-addext', 'subjectAltName=IP:' + DE,
            '-keyout', str(key), '-out', str(ca))
    os.environ['SSL_CERT_FILE'] = str(ca)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ca, key)
    delays = {'west': 0.38, 'east': 0.13, 'west-extra': 0.002}
    observed = {name: 0 for name in EXITS}
    received = []
    names = {ip: name for name, ip in EXITS.items()}

    class Witness(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            source = self.client_address[0]
            name = names.get(source, 'unexpected:' + source)
            if self.server.server_port == PROBE_PORT and self.path == '/health':
                if name not in delays:
                    self.send_error(403)
                    return
                time.sleep(delays[name])
                self.send_response(204)
                self.end_headers()
                observed[name] += 1
                return
            received.append((self.path, name))
            body = name.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    for port in (HTTP_PORT, PROBE_PORT):
        service = http.server.ThreadingHTTPServer(('0.0.0.0', port), Witness)
        if port == PROBE_PORT:
            service.socket = tls.wrap_socket(service.socket, server_side=True)
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        stack.callback(service.server_close)
        stack.callback(service.shutdown)

    def launch(name, config):
        node = Xray(folder, name, config)
        stack.callback(node.stop)
        node.start()
        return node

    exit_nodes, peers = {}, []
    for index, (name, src) in enumerate(EXITS.items()):
        port = 22000 + index
        credential = secret(folder / (name + '.uuid'))
        peers.append(dict(name=name, address='127.0.0.1', port=port, uuid_file=credential))
        export = render(folder, name, dict(role='out', allow_insecure_lab=True,
            listener=dict(address='127.0.0.1', port=port),
            allow_private_destinations=True, transit_uuid_file=credential))
        # Simulate separate public egress addresses; the application witness records
        # the actual TCP peer for both Observatory and SOCKS test requests.
        export['outbounds'][0]['sendThrough'] = src
        exit_nodes[name] = launch(name, export)

    gateway_port = 22010
    caller_keys = {name: secret(folder / (name + '.uuid')) for name in ('all', 'limited')}
    access = {'all': list(EXITS), 'limited': ['west', 'west-extra']}
    gateway = render(folder, 'gateway', dict(role='gateway', allow_insecure_lab=True,
        listener=dict(address='127.0.0.1', port=gateway_port), exits=peers,
        gateway=dict(countries={'DE': ['west', 'east'], 'FR': ['west-extra']},
                     probe_url=f'https://{DE}:{PROBE_PORT}/health', probe_interval_seconds=1,
                     ingresses=[dict(name=name, uuid_file=key, exits=access[name])
                                for name, key in caller_keys.items()])))
    # Only ingress knows this answer. The gateway must receive the resolved IP.
    launch('gateway', gateway)

    client = dict(inbounds=[], outbounds=[], routing=dict(rules=[]))
    socks_ports = {}
    owner = str(uuid.uuid4())
    for index, (name, key_path) in enumerate(caller_keys.items()):
        port = 22020 + index
        ingress = render(folder, name, dict(role='in', allow_insecure_lab=True,
            listener=dict(address='127.0.0.1', port=port), exits=peers,
            single_client=dict(selectors={exit_name: MANUAL + i for i, exit_name in enumerate(access[name])}),
            auto_gateway=dict(selector=AUTO, address='127.0.0.1', port=gateway_port, uuid_file=key_path)),
            [{'id': owner, 'email': 'fixture-owner'}])
        ingress.setdefault('dns', {}).setdefault('hosts', {})[COUNTRY_HOST] = DE
        launch(name, ingress)

        for choice in ('auto', 'manual'):
            mode = name + '-' + choice
            selector = AUTO if choice == 'auto' else MANUAL
            identifier = owner[:14] + format(selector, '04x') + owner[18:]
            socks_port = 23000 + len(socks_ports)
            socks_ports[mode] = socks_port
            client['inbounds'].append(dict(tag=mode, listen='127.0.0.1', port=socks_port, protocol='socks'))
            client['outbounds'].append(dict(tag=mode, protocol='vless', settings=dict(vnext=[
                dict(address='127.0.0.1', port=port, users=[dict(id=identifier, encryption='none')])])))
            client['routing']['rules'].append(dict(type='field', inboundTag=[mode], outboundTag=mode))
    launch('client', client)

    def wait_for(check, explanation, timeout=22):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if check():
                return
            time.sleep(0.25)
        raise AssertionError(explanation + '; probe counts ' + str(observed))

    def request(mode, destination, path):
        response = subprocess.run(['curl', '--noproxy', '', '--http1.1', '-fsS', '--max-time', '2',
                                   '--socks5-hostname', f'127.0.0.1:{socks_ports[mode]}',
                                   f'http://{destination}:{HTTP_PORT}/{path}'],
                                  capture_output=True, text=True, timeout=4)
        return response.stdout if response.returncode == 0 else None

    def expect(mode, host, name, *, poll=False):
        path = uuid.uuid4().hex
        if poll:
            wait_for(lambda: request(mode, host, path) == name, f'{mode} to {host}: expected {name}')
        else:
            actual = request(mode, host, path)
            assert actual == name, f'{mode} to {host}: expected {name}, received {actual}'
        assert ('/' + path, name) in received

    def denied(mode, host):
        path = uuid.uuid4().hex
        for _ in range(3):
            assert request(mode, host, path) is None, f'{mode} unexpectedly reached {host}'
        assert not any(p == '/' + path for p, _ in received), 'blocked request reached the application'

    wait_for(lambda: all(n >= 2 for n in observed.values()), 'no HTTPS observation for each exit')
    expect('all-auto', DE, 'east', poll=True)
    expect('all-auto', COUNTRY_HOST, 'east')
    expect('all-auto', FR, 'west-extra')
    expect('limited-auto', DE, 'west')
    expect('limited-auto', FR, 'west-extra')
    expect('all-manual', FR, 'west')
    denied('all-auto', UNKNOWN)
    denied('all-auto', '127.0.0.1')
    print('PASS destination IP/domain, per-ingress exit permissions, fixed selector and default denial', flush=True)

    # Both eligible exits remain healthy. Inverting only HTTPS latency must flip
    # the measured winner; arbitrary availability-based selection cannot pass.
    delays.update(west=0.035, east=0.30)
    expect('all-auto', DE, 'west', poll=True)
    expect('all-auto', FR, 'west-extra')
    print('PASS leastPing switches between two healthy exits after reversing probe latency', flush=True)
    exit_nodes['west'].stop()
    expect('all-auto', DE, 'east', poll=True)
    denied('limited-auto', DE)
    exit_nodes['east'].stop()
    denied('all-auto', DE)
    # Allow the outstanding outage probes to complete, then repeat the denial.
    # This covers the all-unhealthy fallback after Observatory converges as well
    # as the transient interval when it can still choose a disconnected exit.
    checks_before = observed['west-extra']
    wait_for(lambda: observed['west-extra'] >= checks_before + 2, 'healthy exit probes stopped')
    denied('all-auto', DE)
    expect('all-auto', FR, 'west-extra')
    print('PASS preferred-exit failure, eligible fallback and all-down blocking with excluded exit alive', flush=True)
    exit_nodes['west'].start()
    expect('all-auto', DE, 'west', poll=True)
    expect('limited-auto', DE, 'west')
    print('PASS recovered exit resumes traffic', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default=os.getenv('NODE_IMAGE', 'localhost/vless-node:dev'))
    parser.add_argument('--python-image', default='docker.io/library/python:3.13-slim')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        with tempfile.TemporaryDirectory() as work, contextlib.ExitStack() as stack:
            run_fixture(Path(work), stack)
        return
    name = 'ebc-geoip-' + uuid.uuid4().hex[:16]
    cmd = ['podman', 'run', '--rm', '-i', '--name', name, '--label', 'io.vless.geoip-test=' + name,
           '--network', 'none', '--pull', 'never',
           '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
           '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '160', '--no-healthcheck',
           '--mount', f'type=image,source={args.python_image},destination=/fixture',
           '-e', 'PYTHONHOME=/fixture/usr/local', '-e', 'LD_LIBRARY_PATH=/fixture/usr/local/lib',
           '-e', 'GOMAXPROCS=1', '--entrypoint', '/fixture/usr/local/bin/python3.13',
           args.image, '-B', '-', '--inside']
    try:
        subprocess.run(cmd, input=Path(__file__).read_bytes(), check=True, timeout=180)
    finally:
        # On timeout, remove only the fixture that owns the unique run label.
        info = subprocess.run(['podman', 'inspect', '--format', '{{index .Config.Labels "io.vless.geoip-test"}}',
                               name], capture_output=True, text=True)
        if info.returncode == 0 and info.stdout.strip() == name:
            subprocess.run(['podman', 'rm', '--force', '--ignore', name], check=True, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
