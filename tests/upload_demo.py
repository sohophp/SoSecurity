#!/usr/bin/env python3
"""Private upload playground acceptance, isolated by default or against the explicitly selected entry."""
import argparse, http.client, http.cookiejar, json, os, socket, struct, subprocess, tempfile, time, urllib.error, urllib.parse, urllib.request, zlib
from pathlib import Path
parser=argparse.ArgumentParser(); parser.add_argument('runtime', nargs='?', default='php'); parser.add_argument('--url'); args=parser.parse_args()
root=Path(__file__).resolve().parent.parent
checks=0
def check(expected, actual):
    global checks
    checks+=1; assert expected==actual,(expected,actual)
def client(): return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def png():
    def chunk(kind,data): return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',2,2,8,2,0,0,0))+chunk(b'IDAT',zlib.compress((b'\x00'+b'\xff\x00\x00'*2)*2))+chunk(b'IEND',b'')
def acceptance(base, storage=None):
    browser=client(); controls=None
    def call(action=None, content=None, visitor=None, csrf=None):
        nonlocal controls
        headers={'Accept':'application/json'}; data=None
        if action is not None:
            fields={'action':action,'_csrf':controls if csrf is None else csrf}
            if content is None: data=urllib.parse.urlencode(fields).encode()
            else:
                boundary='sosecurity-demo-boundary'
                data=b''.join((f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n').encode() for k,v in fields.items())
                data+=(f'--{boundary}\r\nContent-Disposition: form-data; name="upload"; filename="test.png"\r\nContent-Type: application/x-php\r\n\r\n').encode()+content+(f'\r\n--{boundary}--\r\n').encode()
                headers['Content-Type']='multipart/form-data; boundary='+boundary
        request=urllib.request.Request(base+'?module=upload',data=data,headers=headers)
        try: response=(visitor or browser).open(request,timeout=8)
        except urllib.error.HTTPError as error: response=error
        with response:
            body=json.load(response)
            if visitor is None and body.get('controls_token'): controls=body['controls_token']
            return response.status,body
    check(200,call()[0]); check(403,call('normal_sample',csrf='forged')[0]); call('clear')
    status,body=call('upload',png()); check(200,status); check('image/png',body['result']['saved']['mime'])
    check(False,body['result']['saved']['scanner_passed']); check(1,len(body['state']['files'])); check(False,'path' in body['result']['saved'])
    original=body['result']['saved']['filename']; stranger=client(); status,stranger_body=call(visitor=stranger)
    check([],stranger_body['state']['files']); check(403,call('clear',visitor=stranger,csrf=controls)[0])
    for action,reason in [('fake_sample','upload.mime'),('size_sample','upload.too_large'),('path_sample','upload.filename'),('budget_sample','upload.image_budget'),('scanner_reject','upload.scan_rejected')]:
        status,body=call(action); check(422,status); check(reason,body['result']['reason'])
    for action,reason in [('scanner_fail','upload.scan_failed'),('store_fail','upload.directory')]:
        status,body=call(action); check(503,status); check(reason,body['result']['reason'])
    check([original],[entry['filename'] for entry in call()[1]['state']['files']])
    call('normal_sample'); call('normal_sample'); check(422,call('normal_sample')[0]); check(3,len(call()[1]['state']['files']))
    call('clear'); check([],call()[1]['state']['files'])
    check(422,call('upload',b'x'*1048577)[0])
    if storage is not None:
        status,body=call('normal_sample'); name=body['result']['saved']['filename']; path=storage/'uploads'/name
        check(0o600,path.stat().st_mode & 0o777); os.utime(path,(time.time()-601,time.time()-601))
        check(200,call('normal_sample')[0]); check(False,path.exists()); check(1,len(call()[1]['state']['files'])); call('clear')
    if args.url:
        endpoint=urllib.parse.urlsplit(base)
        for headers,expected in [({'Content-Length':'2097153','Content-Type':'multipart/form-data; boundary=probe'},413),({'Transfer-Encoding':'chunked'},411),({},411)]:
            connection=(http.client.HTTPSConnection if endpoint.scheme=='https' else http.client.HTTPConnection)(endpoint.hostname,endpoint.port,timeout=5)
            try:
                connection.putrequest('POST',endpoint.path+'?module=upload')
                for key,value in headers.items(): connection.putheader(key,value)
                connection.endheaders(); response=connection.getresponse(); check(expected,response.status); response.read()
            finally: connection.close()
    print(f'PASS upload playground: {checks} assertions; native multipart, CSRF, fault refusal, private quota and visitor isolation')
if args.url: acceptance(args.url.rstrip('/')+'/')
else:
    with tempfile.TemporaryDirectory(prefix='sosecurity-upload-demo-') as directory:
        storage=Path(directory,'storage'); storage.mkdir(mode=0o700); sessions=Path(directory,'sessions'); sessions.mkdir(mode=0o700)
        with socket.socket() as probe: probe.bind(('127.0.0.1',0)); port=probe.getsockname()[1]
        env=os.environ.copy(); env['SOSECURITY_DEMO_STORAGE']=str(storage)
        with open(Path(directory,'server.log'),'w+') as log:
            server=subprocess.Popen([args.runtime,'-d','display_errors=0','-d','upload_max_filesize=1M','-d','post_max_size=2M','-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'demo/public')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None: raise RuntimeError('Upload demo server exited')
                    try: urllib.request.urlopen(f'http://127.0.0.1:{port}/',timeout=.2).close(); break
                    except OSError: time.sleep(.05)
                else: raise RuntimeError('Upload demo startup failed')
                acceptance(f'http://127.0.0.1:{port}/',storage)
            finally:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait()
