#!/usr/bin/env python3
"""Exercise compiled exit DNS caching and private-address denial without Internet.

Requires cached node and official Python images; never pulls images. Both test
containers share an isolated network=none namespace, publish no host ports and
are removed in finally. NET_ADMIN is limited to that namespace to assign the
synthetic public DNS/server address. All identities and services are disposable.
"""
import json
import os
import subprocess
import sys
import time
import uuid

ENGINE = os.environ.get('CONTAINER_ENGINE', 'podman')
IMAGE = os.environ.get('NODE_IMAGE', 'localhost/vless-node:dev')
CANARY_IMAGE = os.environ.get('CANARY_IMAGE', 'docker.io/library/python:3.13-slim')
if ENGINE not in ('podman', 'docker'):
    raise RuntimeError('CONTAINER_ENGINE must be podman or docker')

SERVER = r'''
import http.server,json,os,socket,struct,threading,time
state={'http_hits':0,'dns_queries':{}};lock=threading.Lock()
def save():
 with open('/tmp/stats.tmp','w') as f:json.dump(state,f)
 os.replace('/tmp/stats.tmp','/tmp/stats.json')
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  with lock:state['http_hits']+=1;save()
  self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length','17');self.end_headers();self.wfile.write(b'reachable-canary\n')
 def log_message(self,*args):pass
httpd=http.server.ThreadingHTTPServer(('0.0.0.0',18080),Handler)
threading.Thread(target=httpd.serve_forever,daemon=True).start()
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('1.1.1.1',53))
with lock:save()
open('/tmp/ready','w').close()
while True:
 packet,peer=sock.recvfrom(4096)
 if len(packet)<12:continue
 pos=12;labels=[]
 try:
  while packet[pos]:
   size=packet[pos];labels.append(packet[pos+1:pos+1+size].decode('ascii'));pos+=size+1
  pos+=1;qtype,qclass=struct.unpack('!HH',packet[pos:pos+4]);end=pos+4
 except Exception:continue
 name='.'.join(labels)
 with lock:
  state['dns_queries'][name]=state['dns_queries'].get(name,0)+1;save()
 addresses={'public.canary.test':['1.1.1.1'],'private.canary.test':['127.0.0.1'],
            'mixed.canary.test':['1.1.1.1','127.0.0.1'],
            'mixed-reverse.canary.test':['127.0.0.1','1.1.1.1']}.get(name,[])
 if qtype!=1 or qclass!=1:addresses=[]
 answer=b''.join(b'\xc0\x0c'+struct.pack('!HHIH',1,1,2,4)+socket.inet_aton(address) for address in addresses)
 header=packet[:2]+struct.pack('!HHHHH',0x8180,1,len(addresses),0,0)
 sock.sendto(header+packet[12:end]+answer,peer)
'''


def run():
    marker = uuid.uuid4().hex
    canary = 'vless-dns-canary-' + marker[:12]
    node = 'vless-dns-node-' + marker[:12]
    started = []
    checks = []

    def cli(args, data=None, required=True, timeout=30):
        result = subprocess.run([ENGINE, *args], input=data, text=True,
                                capture_output=True, timeout=timeout)
        if required and result.returncode:
            raise RuntimeError('isolated fixture command failed: ' + args[0])
        return result

    def write(container, path, content):
        cli(['exec', '-i', container, 'sh', '-c', 'umask 077; cat > ' + path], content)

    def inspect(container):
        return json.loads(cli(['inspect', container]).stdout)[0]

    def stats():
        return json.loads(cli(['exec', canary, 'cat', '/tmp/stats.json']).stdout)

    def curl(url, port=None, expected=True):
        command = ['exec', node, 'curl', '--http1.1', '--noproxy', '', '-fsS',
                   '--connect-timeout', '2', '--max-time', '3']
        if port is not None:
            command += ['--socks5-hostname', '127.0.0.1:' + str(port)]
        result = cli(command + [url], required=False, timeout=10)
        if expected:
            assert result.returncode == 0 and result.stdout == 'reachable-canary\n', 'known reachable canary failed'
        else:
            assert result.returncode != 0, 'a prohibited request reached the canary'
        return result

    try:
        cli(['image', 'inspect', IMAGE])
        cli(['image', 'inspect', CANARY_IMAGE])
        cli(['run', '-d', '--rm', '--pull=never', '--name', canary,
             '--label', 'io.vless.dns-canary=' + marker,
             '--network', 'none', '--read-only', '--cap-drop', 'ALL',
             '--cap-add', 'NET_BIND_SERVICE',
             '--security-opt', 'no-new-privileges', '--pids-limit', '32', '--memory', '64m',
             '--tmpfs', '/tmp:rw,noexec,nosuid,size=4m', '--entrypoint', 'sleep', CANARY_IMAGE, '300'])
        started.append(canary)
        cli(['run', '-d', '--rm', '--pull=never', '--no-healthcheck', '--name', node,
             '--label', 'io.vless.dns-canary=' + marker,
             '--network', 'container:' + canary, '--read-only', '--cap-drop', 'ALL',
             '--cap-add', 'NET_ADMIN', '--security-opt', 'no-new-privileges',
             '--pids-limit', '64', '--memory', '192m',
             '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m',
             '--tmpfs', '/var/lib/tailscale:rw,noexec,nosuid,size=1m',
             '--tmpfs', '/var/lib/node:rw,noexec,nosuid,size=1m',
             '--entrypoint', 'sleep', IMAGE, '300'])
        started.append(node)
        for container in started:
            info = inspect(container)
            assert not info['HostConfig'].get('PortBindings')
            assert info['HostConfig']['ReadonlyRootfs']
            assert all(mount['Type'] == 'tmpfs' for mount in info.get('Mounts', []))
        assert inspect(canary)['HostConfig']['NetworkMode'] == 'none'
        assert inspect(node)['HostConfig']['NetworkMode'].startswith('container:')
        cli(['exec', node, 'ip', 'addr', 'add', '1.1.1.1/32', 'dev', 'lo'])
        write(canary, '/tmp/server.py', SERVER)
        cli(['exec', '-d', canary, 'sh', '-c', 'python3 -B /tmp/server.py > /tmp/server.log 2>&1'])
        for attempt in range(30):
            if cli(['exec', canary, 'test', '-f', '/tmp/ready'], required=False).returncode == 0:
                break
            time.sleep(.1)
        else:
            detail = cli(['exec', canary, 'cat', '/tmp/server.log'], required=False).stdout
            raise RuntimeError('local canary did not start: ' + detail[-800:])
        curl('http://127.0.0.1:18080/probe')
        checks.append('private HTTP canary is reachable inside the isolated namespace')

        identifier = str(uuid.uuid4())
        write(node, '/tmp/transit-uuid', identifier)
        config = {'role': 'out', 'allow_insecure_lab': True,
                  'listener': {'address': '127.0.0.1', 'port': 18443},
                  'transit_uuid_file': '/tmp/transit-uuid', 'dns': {'servers': ['1.1.1.1']}}
        write(node, '/tmp/node.yaml', json.dumps(config))
        rendered = cli(['exec', node, 'node-agent', 'render', '/tmp/node.yaml']).stdout
        compiled = json.loads(rendered)
        assert compiled['dns']['disableCache'] is False
        assert compiled['routing']['rules'] == [{'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'block'}]
        write(node, '/tmp/server.json', rendered)
        cli(['exec', node, 'xray', 'run', '-test', '-c', '/tmp/server.json'])
        cli(['exec', '-d', node, 'xray', 'run', '-c', '/tmp/server.json'])
        client = {'log': {'loglevel': 'warning'}, 'dns': {'hosts': {'transit.canary.invalid': '127.0.0.1'}},
                  'inbounds': [], 'outbounds': [{'tag': 'block', 'protocol': 'blackhole'}], 'routing': {'rules': []}}
        for port, credential in [(11080, identifier), (11081, str(uuid.uuid4()))]:
            tag = 'route-' + str(port)
            client['inbounds'].append({'tag': tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                                       'settings': {'auth': 'noauth', 'udp': False}})
            client['outbounds'].append({'tag': tag, 'protocol': 'vless', 'settings': {'vnext': [
                {'address': 'transit.canary.invalid', 'port': 18443,
                 'users': [{'id': credential, 'encryption': 'none'}]}]},
                'streamSettings': {'network': 'tcp', 'security': 'none', 'sockopt': {'domainStrategy': 'UseIPv4'}}})
            client['routing']['rules'].append({'type': 'field', 'inboundTag': [tag], 'outboundTag': tag})
        write(node, '/tmp/client.json', json.dumps(client))
        cli(['exec', node, 'xray', 'run', '-test', '-c', '/tmp/client.json'])
        cli(['exec', '-d', node, 'xray', 'run', '-c', '/tmp/client.json'])
        time.sleep(.3)
        curl('http://1.1.1.1:18080/probe', 11080)
        checks.append('correct transit UUID reaches the synthetic public canary')

        curl('http://public.canary.test:18080/probe', 11080)
        first_queries = stats()['dns_queries'].get('public.canary.test', 0)
        curl('http://public.canary.test:18080/probe', 11080)
        assert first_queries > 0 and stats()['dns_queries']['public.canary.test'] == first_queries, 'fresh connections bypassed the DNS cache'
        time.sleep(2.4)
        curl('http://public.canary.test:18080/probe', 11080)
        assert stats()['dns_queries']['public.canary.test'] > first_queries, 'expired DNS cache was not refreshed'
        checks.append('fresh connections reuse cached DNS and refresh after the fixture TTL expires')

        for hostname in ['private.canary.test', 'mixed.canary.test', 'mixed-reverse.canary.test', '127.0.0.1']:
            before_hits = stats()['http_hits']
            curl('http://' + hostname + ':18080/probe', 11080, expected=False)
            after = stats()
            assert after['http_hits'] == before_hits, 'private canary received application bytes'
            if hostname != '127.0.0.1':
                assert after['dns_queries'].get(hostname, 0) > 0, 'private-address test did not exercise DNS'
        checks.append('private literals and private-only or mixed DNS answers send no bytes to the reachable canary')
        before_hits = stats()['http_hits']
        curl('http://1.1.1.1:18080/probe', 11081, expected=False)
        assert stats()['http_hits'] == before_hits, 'unknown transit UUID reached the public canary'
        curl('http://1.1.1.1:18080/probe', 11080)
        checks.append('unknown transit UUID is rejected while the authorized control still works')
        for check in checks:
            print('PASS ' + check, flush=True)
        return checks
    finally:
        cleanup_errors = []
        for container in reversed(started):
            try:
                result = cli(['inspect', container], required=False)
                if result.returncode:  # The bounded --rm fixture may have expired.
                    continue
                actual = json.loads(result.stdout)[0]
                assert actual['Config']['Labels'].get('io.vless.dns-canary') == marker
                cli(['rm', '-f', '-v', container])
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        remaining = cli(['ps', '-a', '--filter', 'label=io.vless.dns-canary=' + marker,
                         '--format', '{{.Names}}']).stdout.strip()
        assert not remaining and not cleanup_errors, 'isolated canary cleanup failed'
        print('PASS removed both isolated canary containers and their temporary state', flush=True)


if __name__ == '__main__':
    try:
        run()
    except Exception as error:
        print('FAIL isolated exit DNS canary: ' + (str(error) or type(error).__name__), file=sys.stderr)
        sys.exit(1)
