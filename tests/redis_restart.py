#!/usr/bin/env python3
"""Restore a deliberately stale Redis RDB in an isolated server; never touch host Redis."""
import subprocess
import sys
import tempfile
import time
from pathlib import Path
root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
with tempfile.TemporaryDirectory(prefix='sosecurity-restart-') as directory:
    socket = str(Path(directory, 'redis.sock'))
    state = str(Path(directory, 'state.json'))
    log = open(Path(directory, 'redis.log'), 'w+')
    command = ['redis-server', '--port', '0', '--unixsocket', socket, '--unixsocketperm', '700',
               '--dir', directory, '--save', '', '--appendonly', 'no']
    def cli(*args):
        return subprocess.run(['redis-cli', '-s', socket, *args], capture_output=True, text=True, timeout=3)
    def start():
        process = subprocess.Popen(command, stdout=log, stderr=log)
        for _ in range(100):
            if process.poll() is not None: raise RuntimeError('Isolated Redis exited')
            try:
                if cli('PING').stdout.strip() == 'PONG': return process
            except subprocess.TimeoutExpired: pass
            time.sleep(.02)
        raise RuntimeError('Isolated Redis readiness timeout')
    server = start()
    try:
        subprocess.run([runtime, str(root / 'tests/redis-restart.php'), 'seed', socket, state], check=True)
        assert cli('SAVE').stdout.strip() == 'OK'
        subprocess.run([runtime, str(root / 'tests/redis-restart.php'), 'consume', socket, state], check=True)
        cli('SHUTDOWN', 'NOSAVE'); server.wait(timeout=5)
        server = start()
        subprocess.run([runtime, str(root / 'tests/redis-restart.php'), 'reject', socket, state], check=True)
    finally:
        if server.poll() is None:
            cli('SHUTDOWN', 'NOSAVE'); server.wait(timeout=5)
        log.close()
