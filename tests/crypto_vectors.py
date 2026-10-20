#!/usr/bin/env python3
"""Independent envelope framing/interoperability using the native libsodium C API."""
import base64
import ctypes
import ctypes.util
import json
import os
import subprocess
import sys
from pathlib import Path

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
root = Path(__file__).resolve().parent.parent
if subprocess.call([runtime, '-r', 'exit(extension_loaded("sodium") ? 0 : 1);']) != 0:
    if os.getenv('SOSECURITY_REQUIRE_CRYPTO') == '1':
        raise RuntimeError('Required ext-sodium is missing')
    print('NOT RUN independent crypto envelopes: ext-sodium required')
    sys.exit()
library = ctypes.util.find_library('sodium')
if not library:
    raise RuntimeError('Native libsodium is required for independent crypto envelope verification')
lib = ctypes.CDLL(library)
lib.sodium_init.restype = ctypes.c_int
assert lib.sodium_init() >= 0
ull = ctypes.c_ulonglong
ptr = ctypes.c_void_p
lib.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [ptr, ptr, ptr, ull, ptr, ull, ptr, ptr, ptr]
lib.crypto_aead_xchacha20poly1305_ietf_encrypt.restype = ctypes.c_int
lib.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = [ptr, ptr, ptr, ptr, ull, ptr, ull, ptr, ptr]
lib.crypto_aead_xchacha20poly1305_ietf_decrypt.restype = ctypes.c_int
key = bytes(range(32))
checks = 0

def check(expected, actual):
    global checks
    checks += 1
    assert expected == actual, (expected, actual)

def php(data):
    result = subprocess.run([runtime, str(root / 'tests/crypto-vectors.php')], input=json.dumps(data),
                            text=True, capture_output=True, check=True)
    check('', result.stderr)
    return json.loads(result.stdout)

def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

for binding in ['tenant:account', '用户/租户']:
    encoded_binding = binding.encode()
    aad = b'SoSecurity.AEAD.1.6:vector14:vector-purpose' + str(len(encoded_binding)).encode() + b':' + encoded_binding
    for plain in [b'', b'Independent framing test', bytes(range(256))]:
        nonce = bytes(range(24))
        buffer = ctypes.create_string_buffer(len(plain) + 16)
        length = ull()
        check(0, lib.crypto_aead_xchacha20poly1305_ietf_encrypt(buffer, ctypes.byref(length), plain, len(plain), aad, len(aad), None, nonce, key))
        envelope = 'sosc1.vector.' + b64(nonce + buffer.raw[:length.value])
        check(base64.b64encode(plain).decode(), php({'mode': 'decrypt', 'envelope': envelope, 'binding': binding})['plain'])
        check(False, php({'mode': 'decrypt', 'envelope': envelope, 'binding': binding + '-other'})['valid'])
        result = php({'mode': 'encrypt', 'plain': base64.b64encode(plain).decode(), 'binding': binding})
        raw = base64.urlsafe_b64decode(result['envelope'].split('.')[2] + '===')
        buffer = ctypes.create_string_buffer(max(1, len(plain)))
        length = ull()
        check(0, lib.crypto_aead_xchacha20poly1305_ietf_decrypt(buffer, ctypes.byref(length), None, raw[24:], len(raw) - 24, aad, len(aad), raw[:24], key))
        check(plain, buffer.raw[:length.value])
print(f'PASS independent crypto envelopes: {checks} assertions; native C/PHP encryption, decryption, binary data and Unicode bindings')
