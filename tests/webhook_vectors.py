#!/usr/bin/env python3
"""Independent raw-frame HMAC/OpenSSL Ed25519 sender -> PHP receiver; all keys are synthetic."""
import base64
import copy
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import random
import subprocess
import sys
from pathlib import Path

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
root = Path(__file__).resolve().parent.parent
randomizer = random.Random(420026)
cases, expected = [], []
sodium = subprocess.call([runtime, '-r', 'exit(extension_loaded("sodium") ? 0 : 1);']) == 0
if not sodium and os.getenv('SOSECURITY_REQUIRE_CRYPTO') == '1':
    raise RuntimeError('Required ext-sodium is missing for webhook vectors')
protocols = ['standard-hmac', 'stripe-v1', 'github-sha256']
if sodium:
    protocols.append('standard-ed25519')
else:
    print('NOT RUN independent webhook Ed25519 profile: ext-sodium required; HMAC profiles continue')
seed = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
public = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')


def add(case, status='allowed', no_lookup=False):
    cases.append(copy.deepcopy(case)); expected.append((status, no_lookup))


# OpenSSL 1.1.1 CLI lacks pkeyutl -rawin, while its one-shot EVP C API supports Ed25519.
lib = None
for library in ([ctypes.util.find_library('crypto'), 'libcrypto.so.3', 'libcrypto.so.1.1', 'libcrypto.dylib'] if sodium else []):
    if not library:
        continue
    try:
        candidate = ctypes.CDLL(library)
    except OSError:
        continue
    if all(hasattr(candidate, name) for name in ['EVP_DigestSign', 'EVP_MD_CTX_new', 'EVP_PKEY_new_raw_private_key']):
        lib = candidate; break
if sodium and lib is None:
    raise RuntimeError('Independent Ed25519 vectors require OpenSSL >=1.1.1 EVP C API')
ptr, size = ctypes.c_void_p, ctypes.c_size_t
private_key = None
if lib is not None:
    lib.OBJ_txt2nid.argtypes = [ctypes.c_char_p]; lib.OBJ_txt2nid.restype = ctypes.c_int
    lib.EVP_PKEY_new_raw_private_key.argtypes = [ctypes.c_int, ptr, ptr, size]; lib.EVP_PKEY_new_raw_private_key.restype = ptr
    lib.EVP_MD_CTX_new.restype = ptr; lib.EVP_MD_CTX_free.argtypes = [ptr]; lib.EVP_PKEY_free.argtypes = [ptr]
    lib.EVP_DigestSignInit.argtypes = [ptr, ptr, ptr, ptr, ptr]; lib.EVP_DigestSignInit.restype = ctypes.c_int
    lib.EVP_DigestSign.argtypes = [ptr, ptr, ptr, ptr, size]; lib.EVP_DigestSign.restype = ctypes.c_int
    private_key = lib.EVP_PKEY_new_raw_private_key(lib.OBJ_txt2nid(b'ED25519'), None, seed, len(seed))
    assert private_key, 'Cannot initialize isolated OpenSSL Ed25519 key'



def ed25519(message):
    context = lib.EVP_MD_CTX_new()
    assert context
    try:
        assert lib.EVP_DigestSignInit(context, None, None, None, private_key) == 1
        output, length = ctypes.create_string_buffer(64), size(64)
        assert lib.EVP_DigestSign(context, output, ctypes.byref(length), message, len(message)) == 1
        assert length.value == 64
        return output.raw
    finally:
        lib.EVP_MD_CTX_free(context)


try:
    for protocol in protocols:
        key = public if protocol == 'standard-ed25519' else b'Independent-test-webhook-secret-32!'
        for body in [b'', b'{}', b'{"value":"\xe5\xb7\xa5\xe5\x85\xb7/\xf0\x9f\x98\x80"}\n', b'\0\xff\r\n', randomizer.randbytes(256), randomizer.randbytes(65536)]:
            for offset in [-301, -300, 0, 30, 31]:
                timestamp = 100000 + offset
                if protocol.startswith('standard-'):
                    message = b'msg_python.' + str(timestamp).encode() + b'.' + body
                    if protocol == 'standard-ed25519':
                        signature = ed25519(message)
                    else:
                        signature = hmac.new(key, message, hashlib.sha256).digest()
                    headers = {'webhook-id': 'msg_python', 'webhook-timestamp': str(timestamp),
                               'webhook-signature': ('v1a,' if protocol == 'standard-ed25519' else 'v1,') + base64.b64encode(signature).decode()}
                elif protocol == 'stripe-v1':
                    headers = {'stripe-signature': f't={timestamp},v1=' + hmac.new(key, str(timestamp).encode() + b'.' + body, hashlib.sha256).hexdigest()}
                else:
                    headers = {'x-hub-signature-256': 'sha256=' + hmac.new(key, body, hashlib.sha256).hexdigest(),
                               'x-github-delivery': 'untrusted-id', 'x-github-event': 'untrusted-type'}
                case = dict(protocol=protocol, options={'allow_untimed': True} if protocol == 'github-sha256' else {},
                            now=100000, key=base64.b64encode(key).decode(), body=base64.b64encode(body).decode(),
                            headers=headers, method='POST', url='https://hooks.example/events')
                valid = protocol == 'github-sha256' or -300 <= offset <= 30
                add(case, 'allowed' if valid else 'denied', not valid)
                altered = copy.deepcopy(case); altered['body'] = base64.b64encode(body + b' ').decode(); add(altered, 'denied', not valid)
                altered = copy.deepcopy(case); altered['method'] = 'GET'; add(altered, 'denied', True)
                altered = copy.deepcopy(case); altered['url'] += '?alias=1'; add(altered, 'denied', True)
                if not valid:
                    continue
                if protocol == 'github-sha256':
                    altered = copy.deepcopy(case); altered['headers']['x-github-delivery'] = 'changed-id'; altered['headers']['x-github-event'] = 'changed-type'; add(altered)
                elif protocol.startswith('standard-'):
                    altered = copy.deepcopy(case); altered['headers']['webhook-id'] = 'another_message'; add(altered, 'denied')
                    for value in ['0100000', '-1', '1e5', '9223372036854775808']:
                        altered = copy.deepcopy(case); altered['headers']['webhook-timestamp'] = value; add(altered, 'denied', True)
                    altered = copy.deepcopy(case); altered['headers']['webhook-signature'] += '='; add(altered, 'denied', True)
                    altered = copy.deepcopy(case); altered['headers']['webhook-signature'] = 'v2,ignored ' + altered['headers']['webhook-signature']; add(altered)
                else:
                    altered = copy.deepcopy(case); altered['headers']['stripe-signature'] += f',t={timestamp}'; add(altered, 'denied', True)
                    altered = copy.deepcopy(case); altered['headers']['stripe-signature'] = f't={timestamp},v0=ignored'; add(altered, 'denied', True)
                    altered = copy.deepcopy(case); altered['headers']['stripe-signature'] += ',v0=ignored'; add(altered)
                altered = copy.deepcopy(case); altered['options']['maximum_body'] = max(0, len(body) - 1)
                add(altered, 'denied' if body else 'allowed', bool(body))

finally:
    if lib is not None and private_key:
        lib.EVP_PKEY_free(private_key)

actual = json.loads(subprocess.check_output([runtime, str(root / 'tests/webhook-vectors.php')], input=json.dumps(cases).encode(), timeout=60))
assert len(actual) == len(expected)
for index, (case, got, (status, no_lookup)) in enumerate(zip(cases, actual, expected)):
    assert got['result'] == status, (index, case['protocol'], status, got)
    if no_lookup:
        assert got['calls'] == 0, (index, 'unexpected key-provider access')
    if status == 'allowed':
        assert got['digest'] == hashlib.sha256(base64.b64decode(case['body'])).hexdigest(), index
        standard = case['protocol'].startswith('standard-')
        assert got['id'] == ('msg_python' if standard else None), index
        assert (got['timestamp'] is None) == (case['protocol'] == 'github-sha256'), index
print(f'PASS independent webhook vectors: {len(cases)} Python raw-frame requests on {runtime}; HMAC'+(' and OpenSSL Ed25519' if sodium else '')+', '
      'binary/Unicode/64KiB bodies, signed freshness boundaries, aliases, key-work refusal and GitHub unsigned metadata; synthetic keys only')
