from pathlib import Path
import json, os, re, selectors, socket, subprocess, sys, tempfile, threading, time

root = Path(__file__).resolve().parents[1]
real = os.environ.get('SOSECURITY_TEST_MYSQL_SOCKET', '')
if not re.fullmatch(r'/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock', real) or not (Path(real).parent/'account-test-owner').is_file() or Path(real).parent.is_symlink():
    raise RuntimeError('Owned MySQL required')
runtime = sys.argv[1] if len(sys.argv)>1 else 'php85'
preload = sys.argv[2:]
if len(preload)>1:
    raise RuntimeError('Use at most one explicit source preload')
rows = []
for mode in ['normal', 'cross', 'expired', 'entry-drop', 'restore-drop']:
    with tempfile.TemporaryDirectory(prefix='sosecurity-wait-proxy-', dir='/tmp') as name:
        work = Path(name); (work/'owned-proxy').write_text('owned'); arm = work/'arm'
        listener = socket.socket(socket.AF_UNIX); listener.bind(str(work/'pdo.sock')); listener.listen(1); listener.settimeout(15)
        stop = threading.Event(); state = {'injected': False, 'error': None, 'settings': []}; peers = []
        def relay():
            try:
                client, _ = listener.accept(); server = socket.socket(socket.AF_UNIX); server.connect(real); peers.extend([client, server])
                for peer in peers: peer.settimeout(5)
                selector = selectors.DefaultSelector(); selector.register(client, selectors.EVENT_READ); selector.register(server, selectors.EVENT_READ); pending = b''
                try:
                    while not stop.is_set():
                        for key, _ in selector.select(.1):
                            data = key.fileobj.recv(65536)
                            if not data: return
                            if key.fileobj is server: client.sendall(data); continue
                            pending += data
                            if len(pending)>65536: raise RuntimeError('Bounded request exceeded')
                            while len(pending)>=4:
                                length = int.from_bytes(pending[:3], 'little')
                                if length>65532: raise RuntimeError('Bounded packet exceeded')
                                if len(pending)<length+4: break
                                packet, pending = pending[:length+4], pending[length+4:]; payload = packet[4:]
                                if arm.is_file() and payload.startswith(b'\x03SET SESSION '): state['settings'].append(payload[1:].decode('ascii'))
                                if not state['injected'] and arm.is_file() and payload.startswith(b'\x03SET SESSION innodb_lock_wait_timeout='):
                                    state['injected'] = True
                                    if mode in ['entry-drop', 'restore-drop']: return
                                    if mode!='normal': time.sleep(1.1)
                                server.sendall(packet)
                finally: selector.close()
            except Exception as error:
                if not stop.is_set(): state['error'] = type(error).__name__
            finally:
                for peer in peers:
                    try: peer.close()
                    except OSError: pass
        thread = threading.Thread(target=relay, daemon=True); thread.start()
        env = dict(os.environ, SOSECURITY_TEST_WAIT_PROXY=str(work/'pdo.sock'), SOSECURITY_TEST_WAIT_ARM=str(arm))
        args = [runtime, '-d', 'memory_limit=8M'] + (['-d', 'auto_prepend_file='+preload[0]] if preload else []) + [str(root/'tests/sql-wait-native-delay.php'), mode]
        try: code = subprocess.run(args, cwd=root, env=env, timeout=30).returncode
        finally:
            stop.set(); listener.close()
            for peer in peers:
                try: peer.shutdown(socket.SHUT_RDWR)
                except OSError: pass
            thread.join(5)
        if thread.is_alive(): raise RuntimeError('Owned relay did not close')
        passed = code==0 and state['injected'] and state['error'] is None
        rows.append(dict(mode=mode, exit=code, injected=state['injected'], relay_error=state['error'], settings=state['settings'], passed=passed))
print(json.dumps(rows))
raise SystemExit(0 if all(row['passed'] for row in rows) else 1)
