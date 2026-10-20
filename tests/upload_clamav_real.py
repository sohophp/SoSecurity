#!/usr/bin/env python3
"""Run an owned no-TCP clamd with a synthetic signature DB, never a host AV service."""
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

root=Path(__file__).resolve().parent.parent
daemon=shutil.which('clamd')
if not daemon:
    print('NOT RUN real ClamAV: clamd is not installed');sys.exit(1 if os.environ.get('SOSECURITY_REQUIRE_CLAMAV')=='1' else 0)
runtimes=sys.argv[1:] or ['php']
with tempfile.TemporaryDirectory(prefix='sosecurity-clamav-real-') as directory:
    work=Path(directory);(work/'database').mkdir(mode=0o700);path=str(work/'scan.sock')
    marker=b'SoSecurity antivirus acceptance marker.\n'
    (work/'database/local.hdb').write_text(hashlib.md5(marker).hexdigest()+':'+str(len(marker))+':SoSecurity.Acceptance.Test\n')
    config=work/'clamd.conf'
    config.write_text('\n'.join(['Foreground yes','LocalSocket '+path,'LocalSocketMode 600','FixStaleSocket no','DatabaseDirectory '+str(work/'database'),'TemporaryDirectory '+str(work),'PidFile '+str(work/'clamd.pid'),'LogFile '+str(work/'clamd.log'),'MaxThreads 1','MaxQueue 4','MaxConnectionQueueLength 4','ReadTimeout 2','CommandReadTimeout 2','SendBufTimeout 200','MaxScanTime 2000','StreamMaxLength 1M','MaxFileSize 256K','MaxScanSize 512K','MaxRecursion 8','MaxFiles 100','AlertExceedsMax yes','AlertEncrypted yes','Bytecode no'])+'\n')
    (work/'observe.php').write_text("<?php register_shutdown_function(static function():void{ $e=error_get_last();if($e!==null&&$e['type']===E_ERROR){fwrite(STDERR,'OWNED_REAL_SCAN_FATAL '.$e['message'].PHP_EOL);} });")
    print('OWNED_CLAMAV '+directory,flush=True)
    with (work/'launch.log').open('w') as log:
        process=subprocess.Popen([daemon,'--foreground','--config-file='+str(config)],stdout=log,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError('Owned clamd exited: '+(work/'launch.log').read_text())
                try:
                    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                        client.settimeout(.2);client.connect(path);client.sendall(b'zPING\0')
                        if client.recv(64)==b'PONG\0':break
                except OSError:pass
                time.sleep(.05)
            else:raise RuntimeError('Owned clamd startup timed out')
            print(subprocess.run([daemon,'--version'],capture_output=True,text=True,check=True).stdout.strip().split('/')[0],flush=True)
            for runtime in runtimes:
                env=os.environ.copy();env['SOSECURITY_TEST_CLAM_SOCKET']=path
                subprocess.run([runtime,'-d','memory_limit=8M','-d','display_errors=stderr','-d','log_errors=0','-d','auto_prepend_file='+str(work/'observe.php'),str(root/'tests/upload-clamav-real.php')],cwd=root,env=env,check=True)
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
print('PASS owned ClamAV process stopped and private test directory removed',flush=True)
