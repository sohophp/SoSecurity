#!/usr/bin/env python3
"""Real native PHP multipart uploads on a private loopback test server."""
import json, os, socket, struct, subprocess, sys, tempfile, time, urllib.error, urllib.request, zlib
from pathlib import Path
root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
def png(width=2, height=2):
    def chunk(kind, data): return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B', width, height, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress((b'\x00' + b'\xff\x00\x00' * width) * height)) + chunk(b'IEND', b'')
with tempfile.TemporaryDirectory(prefix='sosecurity-upload-http-') as directory:
    target = Path(directory, 'files'); target.mkdir(mode=0o700)
    source = Path(directory, 'fake'); source.write_bytes(png())
    with socket.socket() as probe: probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
    env = os.environ.copy(); env.update(SOSECURITY_TEST_UPLOAD_DIRECTORY=str(target), SOSECURITY_TEST_UPLOAD_SOURCE=str(source))
    with open(Path(directory, 'server.log'), 'w+') as log:
        server = subprocess.Popen([runtime, '-d', 'display_errors=0', '-d', 'upload_max_filesize=1M', '-d', 'post_max_size=2M', '-S', f'127.0.0.1:{port}', '-t', str(root / 'tests')], env=env, stdout=log, stderr=log)
        url = f'http://127.0.0.1:{port}/http-upload.php'; checks = 0
        def check(expected, actual):
            global checks
            checks += 1; assert expected == actual, (expected, actual)
        def upload(name, contents, content_type='image/png', fault='', maximum=None):
            boundary = 'sosecurity-boundary-42'
            data = b''
            for key, value in [('fault', fault), *([('MAX_FILE_SIZE', str(maximum))] if maximum is not None else [])]:
                data += (f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode()
            data += (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: {content_type}\r\n\r\n').encode() + contents + (f'\r\n--{boundary}--\r\n').encode()
            request = urllib.request.Request(url, data=data, headers={'Content-Type': 'multipart/form-data; boundary=' + boundary})
            try: response = urllib.request.urlopen(request, timeout=8)
            except urllib.error.HTTPError as error: response = error
            with response: return response.status, json.load(response)
        try:
            for _ in range(100):
                if server.poll() is not None: raise RuntimeError('Upload test server exited')
                try:
                    urllib.request.urlopen(url, timeout=.2).close(); break
                except urllib.error.HTTPError: break
                except OSError: time.sleep(.05)
            else: raise RuntimeError('Upload test server startup failed')
            status, result = upload('正常.png', png(), 'application/x-php')
            check(201, status); check('image/png', result['mime']); check(False, result['scanner_passed'])
            saved = target / result['filename']; check(True, saved.is_file()); check(0o600, saved.stat().st_mode & 0o777)
            check(False, str(target) in json.dumps(result)); check(2, result['width'])
            check(422, upload('fake.png', b'<?php echo 1;')[0])
            check('upload.mime', upload('fake.jpg', png())[1]['reason'])
            check('upload.filename', upload('bad.php.png', png())[1]['reason'])
            check('upload.size_mismatch', upload('normal.png', png(), fault='size')[1]['reason'])
            check('upload.not_uploaded', upload('normal.png', png(), fault='fake')[1]['reason'])
            check('upload.too_large', upload('normal.png', b'a' * 1025)[1]['reason'])
            check('upload.too_large', upload('normal.png', png(), maximum=10)[1]['reason'])
            check('upload.empty', upload('normal.png', b'')[1]['reason'])
            status, result = upload('normal.png', png(), fault='scanner'); check(503, status); check('upload.scan_failed', result['reason'])
            check(False, 'DO-NOT-EXPOSE' in json.dumps(result))
            check(1, len(list(target.iterdir())))
            check(413, upload('normal.png', b'a' * 2200000)[0])
            print(f'PASS native multipart uploads: {checks} assertions, real POST provenance, size/type/fault and private storage')
        finally:
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill(); server.wait()
