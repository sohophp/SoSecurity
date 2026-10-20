#!/usr/bin/env python3
"""Owned local PHP processes only: generation races, SIGKILL recovery and staging cleanup."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = sys.argv[1] if len(sys.argv) > 1 else 'php'
WORKER = ROOT / 'tests/upload-quarantine-worker.php'


def run(directory, mode, identifier=None, check=True):
    args = [RUNTIME, '-d', 'memory_limit=8M', str(WORKER), str(directory), mode]
    if identifier is not None:
        args.append(identifier)
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=20)
    if not check:
        return result
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return json.loads(result.stdout)


def barrier(directory, child):
    until = time.monotonic() + 10
    while not (directory / 'entered').exists():
        if child.poll() is not None:
            out, err = child.communicate()
            raise RuntimeError(out + err)
        if time.monotonic() >= until:
            raise RuntimeError('Owned process failed to reach test barrier')
        time.sleep(0.005)


def fixture(directory):
    for name in ['ledger', 'spool', 'web']:
        (directory / name).mkdir(mode=0o700)
    (directory / 'source').write_text('scan me\n')


def start(directory, mode, identifier=None):
    args = [RUNTIME, '-d', 'memory_limit=8M', str(WORKER), str(directory), mode]
    if identifier is not None:
        args.append(identifier)
    return subprocess.Popen(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


if os.name != 'posix' or not hasattr(signal, 'SIGKILL'):
    raise RuntimeError('NOT RUN quarantine process checks: POSIX SIGKILL required')

for case in ['admin', 'crash', 'staging']:
    with tempfile.TemporaryDirectory(prefix='sosecurity-quarantine-race-') as name:
        directory = Path(name)
        fixture(directory)
        child = None
        try:
            if case == 'staging':
                child = start(directory, 'staging')
                barrier(directory, child)
                pending = run(directory, 'items')
                assert len(pending) == 1 and pending[0]['state'] == 'staging'
                identifier = pending[0]['id']
                blocked = run(directory, 'remove', identifier, check=False)
                assert blocked.returncode != 0 and 'Quarantine' in blocked.stderr
                assert run(directory, 'items')[0]['state'] == 'staging'
                child.kill()
                child.communicate(timeout=10)
                assert child.returncode == -signal.SIGKILL
                assert run(directory, 'remove', identifier)['removed'] is True
                assert run(directory, 'items') == []
                assert sorted(x.name for x in (directory / 'spool').iterdir()) == ['.quarantine.lock']
                print(f'PASS owned quarantine staging lock, SIGKILL and cleanup: {RUNTIME}', flush=True)
                continue
            identifier = run(directory, 'enqueue')['id']
            child = start(directory, 'scan-wait', identifier)
            barrier(directory, child)
            busy = run(directory, 'scan', identifier)
            assert busy['state'] == 'scanning' and busy['attempts'] == 1
            assert run(directory, 'read', identifier) == {'denied': True}
            if case == 'admin':
                assert run(directory, 'reject', identifier)['state'] == 'rejected'
                (directory / 'release').write_text('release')
                out, err = child.communicate(timeout=10)
                assert child.returncode == 0, out + err
                # Obtain actual bytes before interpreting status: the negative control must prove a release.
                access = run(directory, 'read', identifier)
                if access.get('contents') == 'scan me\n':
                    raise RuntimeError('UNSAFE_QUARANTINE_LATE_CLEAN_RELEASED_ACTUAL_BYTES')
                assert access == {'denied': True}
                assert json.loads(out)['state'] == 'rejected'
                assert run(directory, 'inspect', identifier)['state'] == 'rejected'
                print(f'PASS owned quarantine admin wins over paused clean scanner: {RUNTIME}', flush=True)
            else:
                child.kill()
                child.communicate(timeout=10)
                assert child.returncode == -signal.SIGKILL
                assert run(directory, 'read', identifier) == {'denied': True}
                until = time.monotonic() + 10
                while time.time() <= busy['retry_at']:
                    if time.monotonic() > until:
                        raise RuntimeError('Owned lease wait exceeded bound')
                    time.sleep(0.02)
                ready = run(directory, 'scan', identifier)
                assert ready['state'] == 'available' and ready['attempts'] == 2
                assert run(directory, 'read', identifier) == {'contents': 'scan me\n'}
                print(f'PASS owned quarantine SIGKILL, expired lease and safe retry: {RUNTIME}', flush=True)
            run(directory, 'reject', identifier)
            assert run(directory, 'remove', identifier)['removed'] is True
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
print(f'PASS owned quarantine processes stopped and private fixtures removed: {RUNTIME}')
