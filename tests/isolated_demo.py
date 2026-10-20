"""Isolated local demo server lifecycle for optional HTTP/browser acceptance."""
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request

@contextmanager
def demo_server(runtime):
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix='sosecurity-refinement-demo-') as directory:
        storage = Path(directory, 'storage'); storage.mkdir(mode=0o700)
        sessions = Path(directory, 'sessions'); sessions.mkdir(mode=0o700)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        env = os.environ.copy(); env['SOSECURITY_DEMO_STORAGE'] = str(storage)
        with open(Path(directory, 'server.log'), 'w+') as log:
            server = subprocess.Popen([runtime, '-d', 'session.save_path=' + str(sessions), '-S', f'127.0.0.1:{port}',
                                       '-t', str(root / 'demo/public')], env=env, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:
                        log.seek(0); raise RuntimeError('Demo server exited: ' + log.read())
                    try:
                        urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=.2).close(); break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError('Demo server startup timed out')
                yield f'http://127.0.0.1:{port}/'
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill(); server.wait()
