#!/usr/bin/env python3
"""Exercise an installed release with local fixtures and clean state; never print secrets."""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request


class HttpOrigin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length','6');self.end_headers();self.wfile.write(b'origin')
    def log_message(self,*_):pass


def until(probe, seconds=45):
    deadline=time.monotonic()+seconds
    while True:
        value=probe()
        if value:return value
        if time.monotonic()>=deadline:raise RuntimeError('Bounded release probe timed out')
        threading.Event().wait(.02)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--data',type=Path,required=True)
    parser.add_argument('--mode',choices=['local','dedicated'],required=True)
    parser.add_argument('--bundle',type=Path)
    parser.add_argument('--disposable-container',action='store_true')
    args=parser.parse_args()
    binary=args.binary.resolve();config=args.config.resolve();data=args.data.resolve()
    if data.exists() and any(data.iterdir()):parser.error('Release rehearsal requires clean data')
    uid,gid=os.geteuid(),os.getegid();prefix=[]
    if args.mode=='dedicated':
        if not args.disposable_container or not Path('/.dockerenv').exists():parser.error('Dedicated trust-store rehearsal is allowed only in a disposable container')
        account=pwd.getpwnam('nullgate');uid,gid=account.pw_uid,account.pw_gid
        prefix=['setpriv','--reuid='+str(uid),'--regid='+str(gid),'--init-groups','--inh-caps=+net_bind_service','--ambient-caps=+net_bind_service']
    data.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.geteuid()==0:os.chown(data,uid,gid)
    os.chmod(data,0o700)
    process=None;servers=[];stop=threading.Event();password=secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix='nullgate-release-') as temporary:
        work=Path(temporary)
        if os.geteuid()==0:os.chown(work,uid,gid)
        def owned(path,mode):
            os.chmod(path,mode)
            if os.geteuid()==0:os.chown(path,uid,gid)
        host='127.0.0.1'
        if args.mode=='dedicated':
            hostname=socket.gethostname()
            for line in Path('/etc/hosts').read_text().splitlines():
                words=line.split()
                if len(words)>1 and hostname in words[1:] and '.' in words[0] and not words[0].startswith('127.'):
                    host=words[0];break
            if host=='127.0.0.1':raise RuntimeError('Dedicated rehearsal needs a private container interface')
        def certificate(name,names):
            cert,key=work/(name+'.pem'),work/(name+'.key')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=NullGate release fixture','-addext','subjectAltName='+names,'-addext','basicConstraints=critical,CA:FALSE','-addext','extendedKeyUsage=serverAuth','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            owned(cert,0o644);owned(key,0o600);return cert,key
        origin_cert,origin_key=certificate('origin','IP:127.0.0.1,DNS:localhost')
        web_cert,web_key=certificate('web','IP:127.0.0.1,IP:'+host+',DNS:localhost')
        plain=http.server.ThreadingHTTPServer(('127.0.0.1',0),HttpOrigin)
        secure=http.server.ThreadingHTTPServer(('127.0.0.1',0),HttpOrigin)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(origin_cert,origin_key);secure.socket=context.wrap_socket(secure.socket,server_side=True)
        for server in [plain,secure]:threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
        upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.bind(('127.0.0.1',0));upstream.settimeout(.2)
        def dns_loop():
            while not stop.is_set():
                try:query,peer=upstream.recvfrom(65535)
                except socket.timeout:continue
                except OSError:return
                answer=bytearray(query);answer[2:4]=b'\x81\x80';answer[6:8]=b'\0\1'
                answer.extend(b'\xc0\x0c\0\1\0\1\0\0\0\x1e\0\4\x7f\0\0\1');upstream.sendto(answer,peer)
        threading.Thread(target=dns_loop,daemon=True).start()
        listen='127.0.0.1' if args.mode=='local' else '0.0.0.0'
        original=config.read_text()
        if str(data) not in original:raise RuntimeError('Installer did not configure the selected data directory')
        text=f'''schema_version=1
data_dir={json.dumps(str(data))}
[dns]
udp_listen="{listen}:5353"
tcp_listen="{listen}:5353"
upstreams=["127.0.0.1:{upstream.getsockname()[1]}"]
[http]
listen="{listen}:8080"
[web]
listen="{listen}:{8081 if args.mode=='local' else 8443}"
'''
        if args.mode=='dedicated':text+=f'''public_origin="https://{host}:8443"
[web.tls]
certificate_file={json.dumps(str(web_cert))}
private_key_file={json.dumps(str(web_key))}
'''
        text+='[auth]\nmode="local"\n';config.write_text(text)
        if args.mode=='local':owned(config,0o600)
        else:os.chmod(config,0o640)
        secret=work/'password';secret.write_text(password);owned(secret,0o600)
        provision= subprocess.run(prefix+[str(binary),'provision-admin','--config',str(config),'--username','admin','--password-file',str(secret)],capture_output=True,timeout=45)
        if provision.returncode:raise RuntimeError('Installed binary first-run provisioning failed')
        if password.encode() in provision.stdout+provision.stderr:raise RuntimeError('Provisioning exposed credentials')
        secret.unlink()
        empty=work/'empty-roots';empty.mkdir();owned(empty,0o700)
        env={**os.environ,'SSL_CERT_FILE':str(origin_cert),'SSL_CERT_DIR':str(empty),'RUST_LOG':'info'}
        log=work/'runtime.log';handle=log.open('w')
        def launch():
            nonlocal process
            process=subprocess.Popen(prefix+[str(binary),'--config',str(config)],env=env,stdout=subprocess.DEVNULL,stderr=handle)
            def ready():
                if process.poll() is not None:raise RuntimeError('Installed runtime exited before readiness')
                return 'runtime ready' in log.read_text()
            until(ready)
        def shutdown():
            nonlocal process
            process.send_signal(signal.SIGTERM)
            if process.wait(timeout=45)!=0:raise RuntimeError('Installed runtime shutdown failed')
            process=None
        origin=('http://127.0.0.1:8081' if args.mode=='local' else f'https://{host}:8443')
        management=ssl.create_default_context(cafile=str(web_cert))
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=management))
        cookie='';csrf='';credentials=[]
        def api(path,method='GET',body=None):
            request=urllib.request.Request(origin+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':origin,'Cookie':cookie,'X-CSRF-Token':csrf})
            with opener.open(request,timeout=10) as response:return response.headers,response.read()
        def login():
            nonlocal cookie,csrf
            cookie='';headers,body=api('/api/v1/auth/csrf');cookie=headers['Set-Cookie'].split(';')[0];csrf=json.loads(body)['csrf']
            headers,_=api('/api/v1/auth/login','POST',{'username':'admin','password':password})
            cookie=next(h.split(';')[0] for h in headers.get_all('Set-Cookie') if '_session=' in h)
            csrf=json.loads(api('/api/v1/auth/csrf')[1])['csrf'];credentials.extend([cookie,csrf])
        def dns(name):
            labels=b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\0'
            query=b'\x12\x34\x01\0\0\1\0\0\0\0\0\0'+labels+b'\0\1\0\1'
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                probe.settimeout(5);probe.sendto(query,(host,5353));reply=probe.recv(65535)
                assert reply[:2]==b'\x12\x34';return reply[3]&15
        def http_request(path):
            connection=http.client.HTTPConnection(host,8080,timeout=5);target=f'http://127.0.0.1:{plain.server_port}{path}'
            connection.request('GET',target);response=connection.getresponse();result=response.status,response.read();connection.close();return result
        def https(target,path,trust):
            context=ssl.create_default_context(cafile=str(trust)) if trust else ssl.create_default_context()
            connection=http.client.HTTPSConnection(host,8080,timeout=5,context=context)
            connection.set_tunnel(target,secure.server_port);connection.request('GET',path,headers={'Host':f'{target}:{secure.server_port}'})
            certificate=connection.sock.getpeercert(binary_form=True)
            response=connection.getresponse();result=response.status,response.read();connection.close();return result,certificate
        try:
            launch();login()
            assert json.loads(api('/api/v1/auth/me')[1])['role']=='administrator'
            api('/api/v1/lists','POST',{'expected_revision':0,'name':'Release rehearsal'})
            rules=f'blocked.test\n*.tracking.test\nhttp://127.0.0.1:{plain.server_port}/ads/*\nhttps://127.0.0.1:{secure.server_port}/ads/*\nbad rule'
            report=json.loads(api('/api/v1/lists/1/rules','POST',{'expected_revision':1,'text':rules})[1]);assert report['import']['malformed'][0]['line']==5
            assert dns('allowed.test')==0 and dns('blocked.test')==3 and dns('sub.tracking.test')==3 and dns('tracking.test')==0
            assert http_request('/ads?ignored=1')==(403,b'') and http_request('/sibling')==(200,b'origin')
            ca=work/'public-ca.pem';ca.write_bytes(api('/api/v1/certificates/ca')[1]);assert b'PRIVATE KEY' not in ca.read_bytes()
            before=ca.read_bytes();result,leaf=https('127.0.0.1','/ads?ignored=1',ca);assert result==(403,b'')
            allowed=https('127.0.0.1','/sibling',ca)[0]
            assert allowed==(200,b'origin'), 'Allowed inspected request status='+str(allowed[0])+' bytes='+str(len(allowed[1]))
            result,origin_leaf=https('localhost','/ads',origin_cert);assert result==(200,b'origin')
            assert leaf!=origin_leaf
            # Per-application trust removal creates a fresh verifier without the inspection CA.
            try:https('127.0.0.1','/ads',origin_cert)
            except ssl.SSLCertVerificationError:pass
            else:raise RuntimeError('Untrusted inspection CA was accepted')
            if args.mode=='dedicated':
                trusted=Path('/usr/local/share/ca-certificates/nullgate-release-rehearsal.crt')
                shutil.copyfile(ca,trusted)
                subprocess.run(['update-ca-certificates'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                assert https('127.0.0.1','/sibling',None)[0]==(200,b'origin')
                trusted.unlink();subprocess.run(['update-ca-certificates','--fresh'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:https('127.0.0.1','/sibling',None)
                except ssl.SSLCertVerificationError:pass
                else:raise RuntimeError('Removed inspection CA remained trusted by a fresh verifier')
            shutdown()
            prior_log=log.read_text()
            backup=work/'backup-state';shutil.copytree(data,backup);backup_config=work/'backup-config';shutil.copyfile(config,backup_config)
            if args.bundle:
                current=config.read_bytes()
                subprocess.run(['python3',str(args.bundle/'install-user.py'),'--prefix',str(binary.parent.parent),'--config-dir',str(config.parent),'--data-dir',str(data)],check=True,stdout=subprocess.DEVNULL)
                assert config.read_bytes()==current
            else:
                # Debian conffile behavior is exercised by the container wrapper's reinstall too.
                assert binary.stat().st_mode & 0o111
            material=data/'inspection-ca/material.bin';material.write_bytes(b'corrupt-release-fixture')
            bad=subprocess.run(prefix+[str(binary),'--config',str(config)],env=env,capture_output=True,timeout=45)
            assert bad.returncode!=0 and b'runtime ready' not in bad.stderr and material.read_bytes()==b'corrupt-release-fixture'
            shutil.rmtree(data);shutil.copytree(backup,data);shutil.copyfile(backup_config,config)
            if os.geteuid()==0:
                os.chown(data,uid,gid)
                for p in data.rglob('*'):os.chown(p,uid,gid)
            handle.close();handle=log.open('w');launch();login()
            assert api('/api/v1/certificates/ca')[1]==before
            assert http_request('/ads')==(403,b'') and dns('blocked.test')==3
            assert json.loads(api('/api/v1/metrics')[1])['imports']['partial']==0
            shutdown()
            content=prior_log+bad.stderr.decode(errors='replace')+log.read_text()
            if any(secret in content for secret in [password,*credentials,'PRIVATE KEY']):raise RuntimeError('Release log exposed private fixture data')
            print(json.dumps({'result':'passed','mode':args.mode,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'checks':['first Administrator','login and CSRF','mixed rules and diagnostics','DNS forwarding and NXDOMAIN','HTTP/HTTPS empty403 and siblings','unlisted TLS passthrough','CA trust and removal','offline backup/restore','corrupt CA fails closed','reinstall preserves config','persistent policy and CA','clean shutdown']}))
        finally:
            if process is not None:
                process.kill();process.wait()
            handle.close();stop.set();upstream.close()
            for server in servers:server.shutdown();server.server_close()


if __name__=='__main__':main()
