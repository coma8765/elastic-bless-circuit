#!/usr/bin/env python3
"""Real Podman/Headscale/3x-ui integration stand; no mocks. Run from any directory."""
import argparse
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local'
NAMES = ['vless-client', 'vless-in', 'vless-out-a', 'vless-out-b', 'vless-target', 'vless-control', 'vless-headscale']

def pod(*args, check=True):
    p = subprocess.run(['podman', *map(str, args)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError('podman '+str(args[0])+': '+p.stderr[-3000:])
    return p.stdout.strip()

def wait(fn, seconds=90):
    end = time.monotonic()+seconds
    last = None
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except Exception as e:
            last = e
        time.sleep(1)
    raise RuntimeError('condition timed out: '+str(last))

def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) if not isinstance(data, str) else data)
    path.chmod(0o600)

def start(name, image, args=(), mounts=(), options=()):
    cmd = ['run', '-d', '--name', name, '--network', 'vless-lab', '--restart=unless-stopped']
    for src, dst in mounts:
        cmd += ['-v', str(src)+':'+dst]
    if args and args[0]=='xray': cmd += ['--no-healthcheck']
    if image in ['localhost/vless-node:dev','localhost/vless-control:dev'] and not args:
        cmd += ['-e','SSL_CERT_FILE=/run/secrets/headscale-ca.pem']
    cmd += list(options)+[image]+list(args)
    pod(*cmd)

def panel_session():
    s=json.loads((STATE/'stand.json').read_text())
    op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    token=json.load(op.open('http://127.0.0.1:12053/csrf-token',timeout=10))['obj']
    def api(path, data=None):
        payload = json.dumps(data).encode() if data is not None else None
        req=urllib.request.Request('http://127.0.0.1:12053'+path, data=payload,
                                   headers={'Content-Type':'application/json','X-CSRF-Token':token})
        j=json.load(op.open(req,timeout=10))
        if not j.get('success'): raise RuntimeError(str(j))
        return j.get('obj')
    api('/login', {'username':'lab-admin','password':s['password']})
    return api

def ip(name):
    return pod('inspect',name,'--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

def ready(name):
    return pod('exec',name,'test','-f','/run/node/ready',check=False)=='' and 'ready' in pod('exec',name,'cat','/run/node/ready',check=False)

def up():
    STATE.mkdir(exist_ok=True)
    # Refuse to overwrite a running stand or its private credentials.
    running=json.loads(pod('ps','-a','--format','json'))
    if any(c.get('Names',[None])[0] in NAMES for c in running):
        raise RuntimeError('stand already exists; use test, or down before up')
    pod('network','create','vless-lab',check=False)
    (STATE/'headscale').mkdir(exist_ok=True)
    (STATE/'headscale/config.yaml').write_text((ROOT/'tests/headscale.yaml').read_text())
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-days','7','-nodes','-subj','/CN=vless-headscale','-addext','subjectAltName=DNS:vless-headscale','-keyout',str(STATE/'headscale/key.pem'),'-out',str(STATE/'headscale/cert.pem')],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    write(STATE/'secrets/headscale-ca.pem',(STATE/'headscale/cert.pem').read_text())
    (STATE/'headscale/key.pem').chmod(0o600)
    start('vless-headscale','localhost/vless-headscale:dev',mounts=[(STATE/'headscale','/etc/headscale:ro'),('vless-headscale-state','/var/lib/headscale')])
    wait(lambda: pod('exec','vless-headscale','headscale','users','create','lab',check=False) or pod('exec','vless-headscale','headscale','users','list','-o','json'))
    users=json.loads(pod('exec','vless-headscale','headscale','users','list','-o','json'))
    uid=next(u['id'] for u in users if u['name']=='lab')
    auth=json.loads(pod('exec','vless-headscale','headscale','preauthkeys','create','--user',uid,'--reusable','--expiration','24h','-o','json'))['key']
    write(STATE/'secrets/mesh-key',auth)
    password=secrets.token_urlsafe(24)
    write(STATE/'secrets/panel-user','lab-admin')
    write(STATE/'secrets/panel-password',password)
    s={'password':password,'users':[str(uuid.uuid4()),str(uuid.uuid4())]}
    write(STATE/'stand.json',s)
    write(STATE/'control.yaml',{'allow_insecure_lab':True,'mesh':{'enabled':True,'server':'https://vless-headscale','hostname':'control','auth_key_file':'/run/secrets/mesh-key'},'panel_settings':{'username_file':'/run/secrets/panel-user','password_file':'/run/secrets/panel-password','port':2053,'base_path':'/'}})
    start('vless-control','localhost/vless-control:dev',mounts=[('vless-control-db','/etc/x-ui'),('vless-control-state','/var/lib/tailscale'),(STATE/'control.yaml','/etc/node/config.yaml:ro'),(STATE/'secrets','/run/secrets:ro')],options=['--cap-add=NET_ADMIN','--device=/dev/net/tun','--security-opt=label=disable','-p','127.0.0.1:12053:2053','-p','127.0.0.1:12096:2096'])
    api=wait(lambda: panel_session())
    stream={'network':'tcp','security':'none','externalProxy':[{'dest':'127.0.0.1','port':14443,'forceTls':'none','remark':'local-ingress'}]}
    inbound=api('/panel/api/inbounds/add',{'enable':True,'remark':'distributed-ingress','listen':'127.0.0.1','port':14443,'protocol':'vless','settings':{'clients':[],'decryption':'none'},'streamSettings':stream,'sniffing':{'enabled':False}})
    iid=inbound['id']
    settings=api('/panel/api/setting/all',{})
    settings.update({'subEnable':True,'subPort':2096,'subPath':'/sub/','subListen':'0.0.0.0'})
    api('/panel/api/setting/update',settings)
    api('/panel/api/setting/restartPanel',{})
    api=wait(lambda: panel_session())
    for i,label in enumerate(['alice-a','alice-b']):
        api('/panel/api/clients/add',{'client':{'email':label,'id':s['users'][i],'enable':True,'subId':'lab-'+label},'inboundIds':[iid]})
    for label in ['a','b']:
        write(STATE/f'secrets/transit-{label}',str(uuid.uuid4()))
        c={'role':'out','allow_insecure_lab':True,'allow_private_destinations':True,'mesh':{'enabled':True,'server':'https://vless-headscale','hostname':'out-'+label,'auth_key_file':'/run/secrets/mesh-key'},'listener':{'address':'mesh','port':8443},'transit_uuid_file':'/run/secrets/transit-'+label}
        write(STATE/f'out-{label}.yaml',c)
        start('vless-out-'+label,'localhost/vless-node:dev',mounts=[(STATE/f'out-{label}.yaml','/etc/node/config.yaml:ro'),(STATE/'secrets','/run/secrets:ro'),('vless-out-'+label+'-state','/var/lib/tailscale')],options=['--cap-add=NET_ADMIN','--device=/dev/net/tun','--security-opt=label=disable'])
        wait(lambda: ready('vless-out-'+label))
    exits=[{'name':'out-'+l,'address':pod('exec','vless-out-'+l,'tailscale','ip','-4'),'port':8443,'uuid_file':'/run/secrets/transit-'+l} for l in ['a','b']]
    c={'role':'in','allow_insecure_lab':True,'sync_seconds':2,'mesh':{'enabled':True,'server':'https://vless-headscale','hostname':'in','auth_key_file':'/run/secrets/mesh-key'},'listener':{'address':'0.0.0.0','port':14443},'panel':{'url':'http://vless-control:2053','allow_http':True,'username_file':'/run/secrets/panel-user','password_file':'/run/secrets/panel-password','inbound_id':iid},'routes':{'alice-a':'out-a','alice-b':'out-b'},'exits':exits}
    write(STATE/'in.yaml',c)
    start('vless-in','localhost/vless-node:dev',mounts=[(STATE/'in.yaml','/etc/node/config.yaml:ro'),(STATE/'secrets','/run/secrets:ro'),('vless-in-state','/var/lib/tailscale'),('vless-in-cache','/var/lib/node')],options=['--cap-add=NET_ADMIN','--device=/dev/net/tun','--security-opt=label=disable','-p','127.0.0.1:14443:14443'])
    wait(lambda: ready('vless-in'))
    start('vless-target','docker.io/library/python:3.13-slim',args=['python','/server.py'],mounts=[(ROOT/'tests/http_server.py','/server.py:ro')])
    client={'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[],'routing':{'rules':[]}}
    for i in range(3):
        client['inbounds'].append({'tag':str(i),'listen':'0.0.0.0','port':1080+i,'protocol':'socks','settings':{'auth':'noauth','udp':True}})
        client['outbounds'].append({'tag':str(i),'protocol':'vless','settings':{'vnext':[{'address':'vless-in','port':14443,'users':[{'id':s['users'][i] if i<2 else str(uuid.uuid4()),'encryption':'none'}]}]}})
        client['routing']['rules'].append({'type':'field','inboundTag':[str(i)],'outboundTag':str(i)})
    write(STATE/'client.json',client)
    start('vless-client','localhost/vless-node:dev',args=['xray','run','-config','/client.json'],mounts=[(STATE/'client.json','/client.json:ro')],options=['-p','127.0.0.1:11080:1080','-p','127.0.0.1:11081:1081'])
    print('Stand running. Panel: http://127.0.0.1:12053; credentials: .local/stand.json',flush=True)

def fetch(i, url='http://vless-target:8080'):
    return pod('exec','vless-client','curl','-fsS','--max-time','8','--socks5-hostname','127.0.0.1:'+str(1080+i),url)

def test():
    checks=[]
    for i,l in enumerate(['a','b']):
        assert wait(lambda: fetch(i))==ip('vless-out-'+l), 'wrong exit'
        checks.append('UUID '+l+' routed through matching mesh exit')
    try: fetch(2)
    except RuntimeError: checks.append('unknown UUID rejected')
    else: raise AssertionError('unknown UUID accepted')
    for l in ['a','b']:
        peer=pod('exec','vless-out-'+l,'tailscale','ip','-4')
        result=pod('exec','vless-in','tailscale','ping','--c','5','--until-direct=true',peer)
        assert 'via ' in result and 'DERP(' not in result.splitlines()[-1],result
    checks.append('both mesh peers reached by direct P2P')
    for label in ['a', 'b']:
        node = 'vless-out-' + label
        mesh_ip = pod('exec', node, 'tailscale', 'ip', '-4')
        listeners = pod('exec', node, 'ss', '-lntH')
        vless = [line for line in listeners.splitlines() if ':8443' in line]
        assert len(vless) == 1 and mesh_ip + ':8443' in vless[0], listeners
    checks.append('exit VLESS listeners bind only to their mesh addresses')
    assert fetch(0,'https://example.com').find('Example Domain')>=0
    checks.append('internet HTTPS through two VLESS hops')
    # A failed selected exit must not fall back to direct internet or another exit.
    pod('stop', 'vless-out-a')
    try:
        try:
            fetch(0)
        except RuntimeError:
            pass
        else:
            raise AssertionError('unavailable selected exit did not fail closed')
        assert fetch(1) == ip('vless-out-b')
        checks.append('selected exit outage fails closed while the other route stays available')
    finally:
        pod('start', 'vless-out-a')
    wait(lambda: ready('vless-out-a'))
    assert wait(lambda: fetch(0)) == ip('vless-out-a')
    pod('stop','vless-control')
    try:
        time.sleep(4)
        assert fetch(0)==ip('vless-out-a')
        checks.append('control outage preserves existing forwarding')
        pod('restart','vless-in')
        wait(lambda: ready('vless-in'))
        assert wait(lambda: fetch(0))==ip('vless-out-a')
        checks.append('ingress restart recovers cached users during control outage')
    finally: pod('start','vless-control')
    api=wait(lambda: panel_session())
    # Disable a client using the actual panel API; restored after the assertion.
    record=api('/panel/api/clients/get/alice-a')['client']
    client={k:record[k] for k in ['email','flow','enable','subId','totalGB','expiryTime','limitIp','limitHwid']}
    client['id']=record['uuid']
    client['enable']=False
    api('/panel/api/clients/update/alice-a',client)
    try:
        wait(lambda: all(u.get('email')!='alice-a' for u in json.loads(pod('exec','vless-in','cat','/run/node/config.json'))['inbounds'][0]['settings']['clients']),seconds=45)
        try: fetch(0)
        except RuntimeError: checks.append('panel revocation propagated')
        else: raise AssertionError('revoked client accepted')
        assert fetch(1)==ip('vless-out-b')
    finally:
        client['enable']=True
        api('/panel/api/clients/update/alice-a',client)
    wait(lambda: fetch(0))
    identities=json.loads((STATE/'stand.json').read_text())['users']
    for i,label in enumerate(['alice-a','alice-b']):
        def subscription():
            raw=urllib.request.urlopen('http://127.0.0.1:12096/sub/lab-'+label,timeout=10).read()
            return raw.decode() if raw.startswith(b'vless://') else base64.b64decode(raw).decode()
        links=wait(subscription)
        assert identities[i] in links and '127.0.0.1:14443' in links, links
    checks.append('3x-ui subscriptions contain public ingress and matching UUIDs')
    pod('restart','vless-out-a')
    wait(lambda: ready('vless-out-a'))
    assert wait(lambda: fetch(0))==ip('vless-out-a')
    checks.append('exit restart preserves mesh identity and forwarding')
    for check in checks: print('PASS '+check,flush=True)
    write(STATE/'test-results.json',{'passed':checks,'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())})

def down():
    for n in NAMES: pod('rm','-f',n,check=False)
    for v in ['vless-headscale-state','vless-control-db','vless-control-state','vless-in-cache','vless-in-state','vless-out-a-state','vless-out-b-state']:
        pod('volume','rm',v,check=False)
    pod('network','rm','vless-lab',check=False)
    print('Stand removed; local configuration retained in .local/')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=['up','test','down'])
    args=parser.parse_args()
    globals()[args.command]()
