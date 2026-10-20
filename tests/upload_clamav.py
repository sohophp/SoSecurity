#!/usr/bin/env python3
"""Bounded local Unix-socket protocol peers; no remote or system AV service access."""
import hashlib
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

root=Path(__file__).resolve().parent.parent
runtime=sys.argv[1] if len(sys.argv)>1 else 'php'
if not hasattr(socket,'AF_UNIX') or subprocess.run([runtime,'-r','exit(in_array("unix",stream_get_transports(),true)?0:2);'],capture_output=True).returncode:
    print('NOT RUN ClamAV protocol peers: local Unix transport unavailable');sys.exit(1 if os.environ.get('SOSECURITY_REQUIRE_CLAMAV')=='1' else 0)
modes=sys.argv[2:] or ['clean','fragmented','infected','infected-ok','error','truncated','multiple','oversized','wrong-prefix','trailing','limit','heuristic-limit','timeout','hold-open','trickle','write-timeout','replaced','world-socket','symlink','world-directory','regular','save-clean','save-infected','save-error','save-timeout','save-multiple','save-late-error']
subprocess.run([runtime,str(root/'tests/upload-clamav.php'),'configuration'],cwd=root,check=True)
for mode in modes:
    with tempfile.TemporaryDirectory(prefix='sosecurity-clamav-') as directory:
        path=str(Path(directory,'scan.sock')); listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(path);os.chmod(path,0o600);listener.listen(1);listener.settimeout(.2)
        stop=threading.Event();errors=[];received=[];accepted=[]
        def exact(conn,count):
            data=b''
            while len(data)<count:
                part=conn.recv(count-len(data))
                if not part:raise RuntimeError('Truncated client request')
                data+=part
            return data
        def serve():
            try:
                while not stop.is_set():
                    try:conn,_=listener.accept();break
                    except socket.timeout:continue
                else:return
                accepted.append(True)
                with conn:
                    conn.settimeout(5)
                    if mode=='write-timeout':stop.wait(2);return
                    if exact(conn,10)!=b'zINSTREAM\0':raise RuntimeError('Incorrect command framing')
                    digest=hashlib.sha256();total=0
                    while True:
                        count=struct.unpack('!I',exact(conn,4))[0]
                        if count==0:break
                        if count>8192 or total+count>20971520:raise RuntimeError('Unbounded client frame')
                        digest.update(exact(conn,count));total+=count
                    received.append((total,digest.hexdigest()))
                    if mode in ['timeout','save-timeout']:stop.wait(2);return
                    if mode=='replaced':
                        os.rename(path,path+'.old');replacement=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);replacement.bind(path);replacement.close();os.chmod(path,0o600)
                    if mode=='world-socket':os.chmod(path,0o666)
                    replies={'infected':b'stream: Test-Signature FOUND\0','infected-ok':b'stream: Test.OK FOUND\0','save-infected':b'stream: Test-Signature FOUND\0','error':b'stream: error ERROR\0','save-error':b'stream: error ERROR\0','save-multiple':b'stream: OK\0stream: error ERROR\0','truncated':b'stream: OK','multiple':b'stream: OK\0stream: error ERROR\0','oversized':b'x'*4097,'wrong-prefix':b'OK\0','trailing':b'stream: OK\0x','limit':b'INSTREAM size limit exceeded. ERROR\0','heuristic-limit':b'stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0'}
                    reply=replies.get(mode,b'stream: OK\0')
                    if mode=='save-late-error':
                        conn.sendall(b'stream: OK\0');stop.wait(.05);conn.sendall(b'stream: error ERROR\0')
                    elif mode in ['trickle','fragmented']:
                        for byte in reply:
                            conn.sendall(bytes([byte]));stop.wait(.03 if mode=='trickle' else .002)
                    else:conn.sendall(reply)
                    if mode=='hold-open':stop.wait(2)
            except (BrokenPipeError,ConnectionResetError):
                if mode not in ['oversized','trickle','save-late-error']:errors.append('Unexpected peer disconnect')
            except Exception as error:errors.append(str(error))
        selected=path
        if mode=='symlink':selected=str(Path(directory,'alias.sock'));os.symlink(path,selected)
        if mode=='world-directory':os.chmod(directory,0o777)
        if mode=='regular':listener.close();os.unlink(path);Path(path).write_text('not a socket');os.chmod(path,0o600)
        thread=threading.Thread(target=serve,daemon=True) if mode!='regular' else None
        if thread:thread.start()
        env=os.environ.copy();env['SOSECURITY_TEST_CLAM_SOCKET']=selected
        try:
            result=subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/upload-clamav.php'),mode],cwd=root,env=env,capture_output=True,text=True,timeout=15)
        finally:
            stop.set()
            if thread:thread.join(3)
            listener.close();os.chmod(directory,0o700)
        if thread and thread.is_alive():raise RuntimeError('Owned peer did not terminate')
        if result.returncode or errors:raise RuntimeError(mode+' '+result.stdout+result.stderr+' '+str(errors))
        if mode not in ['write-timeout','symlink','world-directory','regular']:
            expected=b'scanner text\n' if mode.startswith('save-') else bytes(range(256))*65+b'zPING\0stream: OK\0'
            if received!=[(len(expected),hashlib.sha256(expected).hexdigest())]:raise RuntimeError('Stream bytes changed '+mode)
        if mode in ['symlink','world-directory','regular'] and accepted:raise RuntimeError('Unsafe endpoint was contacted')
        print(result.stdout,end='',flush=True)
print('PASS owned ClamAV protocol peers on '+runtime,flush=True)
