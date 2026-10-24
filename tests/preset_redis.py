"""Actual preset budgets on an owned Redis process with no TCP listener."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

root=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='sosecurity-preset-redis-') as directory:
    path=Path(directory);socket=path/'redis.sock'
    (path/'preset-test-owner').write_text('owned preset budget test\n')
    env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_TEST_')}
    env['SOSECURITY_TEST_REDIS_SOCKET']=str(socket)
    with (path/'server.log').open('w') as log:
        server=subprocess.Popen(['redis-server','--port','0','--unixsocket',str(socket),'--unixsocketperm','700','--dir',directory,'--save','','--appendonly','no','--daemonize','no'],stdout=log,stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:raise RuntimeError('Owned Redis exited')
                if socket.is_socket():break
                time.sleep(.05)
            else:raise RuntimeError('Owned Redis startup timed out')
            results=[]
            for runtime in sys.argv[1:] or ['php']:
                available=subprocess.run([runtime,'-r','exit(extension_loaded("redis") ? 0 : 1);'],timeout=10)
                if available.returncode:
                    print('NOT RUN actual login preset redis: ext-redis unavailable for '+runtime,flush=True)
                    results.append(2)
                    continue
                result=subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/preset-shared-budget.php'),'redis'],cwd=root,env=env,timeout=30)
                results.append(result.returncode)
            if any(results):raise RuntimeError('Preset backend failed: '+str(results))
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
