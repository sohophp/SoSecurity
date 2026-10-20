#!/usr/bin/env python3
"""Own one no-TCP Redis instance for read-budget and quarantine profiles; no host Redis access."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
mode = sys.argv[2] if len(sys.argv) > 2 else 'budget'
if subprocess.run([runtime, '-r', 'exit(extension_loaded("redis") ? 0 : 1);'], capture_output=True).returncode:
    raise RuntimeError('NOT RUN owned Redis: selected PHP runtime lacks ext-redis')
with tempfile.TemporaryDirectory(prefix='sosecurity-quarantine-redis-') as directory:
    work = Path(directory)
    nonce = os.urandom(16).hex()
    marker = work / 'quarantine-backend-owner'
    marker.write_text(nonce)
    marker.chmod(0o600)
    socket = str(work / 'redis.sock')
    env = dict(os.environ, SOSECURITY_TEST_REDIS_SOCKET=socket, SOSECURITY_TEST_QUARANTINE_OWNER=nonce,
               SOSECURITY_TEST_QUARANTINE_NAMESPACE='quarantine-' + os.urandom(8).hex())
    print('OWNED_REDIS ' + directory, flush=True)
    with (work / 'redis.log').open('w') as log:
        process = subprocess.Popen(['redis-server', '--port', '0', '--unixsocket', socket, '--unixsocketperm', '700', '--dir', directory,
                                    '--save', '', '--appendonly', 'no', '--maxmemory', '64mb', '--maxmemory-policy', 'noeviction'], stdout=log, stderr=subprocess.STDOUT)
        try:
            until = time.monotonic() + 10
            while time.monotonic() < until:
                if process.poll() is not None:
                    raise RuntimeError('Owned Redis exited')
                ready = subprocess.run(['redis-cli', '-s', socket, 'PING'], capture_output=True, text=True)
                if ready.returncode == 0 and ready.stdout.strip() == 'PONG':
                    break
                time.sleep(.02)
            else:
                raise RuntimeError('Owned Redis startup timed out')
            if mode == 'budget':
                arguments = sys.argv[3:] or ['all']
                subprocess.run([runtime, '-d', 'memory_limit=8M', '-d', 'display_errors=stderr', str(ROOT / 'tests/redis-read-budget.php')] + arguments, env=env, cwd=ROOT, check=True)
            elif mode == 'legacy':
                subprocess.run([runtime, str(ROOT / 'tests/redis.php')], env=env, cwd=ROOT, check=True)
            elif mode == 'quarantine':
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(ROOT / 'tests/upload-quarantine.php'), 'redis'], env=env, cwd=ROOT, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(ROOT / 'tests/upload-quarantine-backend-factory.php'), 'redis'], env=env, cwd=ROOT, check=True)
            elif mode == 'quarantine-process':
                subprocess.run([runtime, '-r', "require 'tests/bootstrap.php'; require 'tests/upload-quarantine-backend-support.php'; quarantineBackendStore('redis', null, true);"], env=env, cwd=ROOT, check=True)
                env['SOSECURITY_TEST_QUARANTINE_BACKEND'] = 'redis'
                subprocess.run(['python3', str(ROOT / 'tests/upload_quarantine.py'), runtime], env=env, cwd=ROOT, check=True)
            elif mode == 'quarantine-clam':
                env['SOSECURITY_TEST_QUARANTINE_BACKEND'] = 'redis'
                env['SOSECURITY_REQUIRE_CLAMAV'] = '1'
                subprocess.run(['python3', str(ROOT / 'tests/upload_clamav_real.py'), runtime], env=env, cwd=ROOT, check=True)
            else:
                raise RuntimeError('Select an explicit owned test profile')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
print('PASS owned Redis stopped and private directory removed', flush=True)
