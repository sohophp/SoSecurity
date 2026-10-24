#!/usr/bin/env python3
"""Only an owned, no-TCP Redis instance; no external delivery or host credentials."""
import os, subprocess, sys, tempfile, time
from pathlib import Path
root=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='sosecurity-keytime-') as directory:
    path=Path(directory);socket=path/'redis.sock';(path/'api-key-time-owner').write_text('owned key time tests\n')
    env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_TEST_')};env['SOSECURITY_TEST_REDIS_SOCKET']=str(socket)
    with (path/'redis.log').open('w') as log:
        server=subprocess.Popen(['redis-server','--port','0','--unixsocket',str(socket),'--unixsocketperm','700','--dir',directory,'--save','','--appendonly','no'],stdout=log,stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:raise RuntimeError('Owned Redis exited before readiness')
                if socket.exists():
                    probe=subprocess.run(['redis-cli','-s',str(socket),'PING'],capture_output=True,text=True,timeout=2)
                    if probe.returncode==0 and probe.stdout.strip()=='PONG':break
                time.sleep(.02)
            else:raise RuntimeError('Owned Redis readiness timeout')
            for runtime in sys.argv[1:] or ['php']:
                subprocess.run([runtime,str(root/'tests/api-key-time.php'),'redis'],env=env,check=True,timeout=60)
                subprocess.run([runtime,str(root/'tests/api.php')],env=env,check=True,timeout=60)
        finally:
            if server.poll() is None:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
