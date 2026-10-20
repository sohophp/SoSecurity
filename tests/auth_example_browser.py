#!/usr/bin/env python3
"""Optional real-browser acceptance of the distributed native authentication example."""
import base64,json,os,socket,subprocess,sys,tempfile,time
from pathlib import Path
runtime=sys.argv[1] if len(sys.argv)>1 else 'php';root=Path(__file__).resolve().parent.parent
example_root=Path(sys.argv[2]).resolve() if len(sys.argv)>2 else root/'examples'
if not (example_root/'authentication.php').is_file(): raise RuntimeError('Explicit native authentication example required')
with tempfile.TemporaryDirectory(prefix='sosecurity-native-auth-browser-') as directory:
    work=Path(directory);storage=work/'state';storage.mkdir(mode=0o700);sessions=work/'sessions';sessions.mkdir(mode=0o700)
    def hashed(value): return subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',value],text=True)
    config=work/'account.json';config.write_text(json.dumps({'username':'demo','subject':'demo-account','hash':hashed('Correct-test-password'),'version':'1','mfa_required':True}));config.chmod(0o600)
    key=base64.b64encode(os.urandom(32)).decode();result=subprocess.run([runtime,str(root/'tests/auth-setup.php')],input=json.dumps({'directory':str(storage),'key':key}),text=True,capture_output=True,check=True)
    if result.stderr: raise RuntimeError('Factor setup failed: '+result.stderr)
    fixture=work/'fixture.json';fixture.write_text(result.stdout);fixture.chmod(0o600)
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_AUTH_EXAMPLE_')};env.update(SOSECURITY_AUTH_EXAMPLE_CONFIG=str(config),SOSECURITY_AUTH_EXAMPLE_STORAGE=str(storage),SOSECURITY_AUTH_EXAMPLE_DUMMY_HASH=hashed('Dummy-test-password'),SOSECURITY_AUTH_EXAMPLE_HTTPS='0',SOSECURITY_AUTH_EXAMPLE_KEY=key,SOSECURITY_AUTH_EXAMPLE_REMEMBER_KEY=base64.b64encode(os.urandom(32)).decode())
    with open(work/'server.log','w+') as log:
        server=subprocess.Popen([runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(example_root)],env=env,stdout=log,stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:log.seek(0);raise RuntimeError(log.read())
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('Native authentication example startup timed out')
            subprocess.run(['node',str(root/'tests/auth-example-browser.cjs'),f'http://127.0.0.1:{port}/authentication.php',str(fixture)],env=env,check=True)
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait()
