#!/usr/bin/env python3
"""Independent ac1 model: PHP JSON encoding, canonical envelope, claims and HMAC; test-only secrets."""
import base64
import copy
import hashlib
import hmac
import json
import random
import subprocess
import sys
from pathlib import Path

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
root = Path(__file__).resolve().parent.parent
randomizer = random.Random(413601)


def php_json(value):
    # PHP's default json_encode escapes Unicode, slashes and U+2028/U+2029, without spaces.
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).replace('/', '\\/').encode('ascii')


def digest(value):
    return hashlib.sha256(php_json(value)).hexdigest()


def bridge(cases):
    return json.loads(subprocess.check_output([runtime, str(root / 'tests/credential-vectors.php')],
                                             input=json.dumps(cases).encode(), timeout=60))


def signature(parts, scope='tenant', site='credential-test', domain='api-credential-v1'):
    message = [domain, site, scope, parts[1], parts[2], parts[3], parts[4],
               int(parts[5]), int(parts[6]), int(parts[7]), parts[8], parts[9]]
    return base64.urlsafe_b64encode(hmac.new(b'k' * 32, php_json(message), hashlib.sha256).digest()).decode().rstrip('=')


def claims(state, identifier, record):
    return digest(['api-credential-claims-v1', 'credential-test', 'tenant', 'alice',
                   digest(['api-credential-root-v1', 'credential-test', 'tenant', 'alice']),
                   state['epoch'], identifier, record['generation'], record['created'], record['issued'],
                   record['expires'], record['name'], record['scopes'], record['identity'], record['key_id'],
                   record['policy'], record['creator'], record['issuer']])


specifications = [{'operation': 'issue', 'name': name, 'scopes': scopes, 'ttl': ttl}
                  for name in ['tool', '工具/部署😀', '工具 <script> & "quote"', 'é:e\u0301']
                  for scopes in [['documents:read'], ['documents:write', 'documents:read']]
                  for ttl in [1, 86400, 31536000]]
issued = bridge(specifications)
account_fingerprint = digest(['tenant', 'alice', '1', True, ['editor'], False])
identity_fingerprint = hashlib.sha256((account_fingerprint + ':none').encode()).hexdigest()
owner_reference = digest(['api-credential-root-v1', 'credential-test', 'tenant', 'alice'])
assertions = 0
for specification, output in zip(specifications, issued):
    token, state = output['token'], output['state']
    parts = token.split('.')
    identifier = parts[4]
    record = state['entries'][identifier]
    assert len(parts) == 11 and parts[0] == 'ac1' and len(token) <= 512
    assert parts[2] == owner_reference and record['identity'] == identity_fingerprint
    assert state['policy'] == record['policy'] == digest(dict(sorted(output['policy'].items())))
    assert record['creator'] == record['issuer'] == owner_reference
    assert record['name'] == specification['name'] and record['scopes'] == sorted(specification['scopes'])
    assert record['created'] == record['issued'] == 100000 and record['expires'] == 100000 + specification['ttl']
    assert record['claims'] == parts[8] == claims(state, identifier, record)
    assert record['digest'] == hashlib.sha256(token.encode()).hexdigest()
    assert hmac.compare_digest(parts[10], signature(parts))
    assertions += 9

# Manufacture valid credentials entirely in Python; PHP receives only trusted synthetic server state + request.
vectors, expected = [], []


def add(token, state, result, no_lookup=False, scope='tenant', required='documents:read'):
    vectors.append({'operation': 'verify', 'token': token, 'state': state, 'scope': scope, 'required': required})
    expected.append((result, no_lookup))


for generation in [1, 2, 19, 9223372036854775807]:
    for name in ['python', 'Python/工具😀']:
        output = copy.deepcopy(issued[0])
        state = output['state']
        identifier = randomizer.randbytes(16).hex()
        original_record = next(iter(state['entries'].values()))
        state['epoch'] = randomizer.randbytes(16).hex()
        record = dict(original_record, name=name, generation=generation, expires=100600)
        state['entries'] = {identifier: record}
        record['claims'] = claims(state, identifier, record)
        parts = ['ac1', 'old', owner_reference, state['epoch'], identifier, str(generation),
                 '100000', '100600', record['claims'], randomizer.randbytes(32).hex(), '']
        parts[10] = signature(parts)
        token = '.'.join(parts)
        record['digest'] = hashlib.sha256(token.encode()).hexdigest()
        add(token, state, 'allowed')
        add(token, None, 'denied')  # Authentic MAC cannot recreate missing state.
        add(token, state, 'denied', True, scope='another-tenant')
        add(token, state, 'denied', required='documents:write')
        # Authentic signature with a different protocol/site/tenant must fail before state lookup.
        for context in [{'site': 'another-site'}, {'scope': 'another-tenant'}, {'domain': 'api-credential-v2'}]:
            altered = parts.copy(); altered[10] = signature(altered, **context)
            add('.'.join(altered), state, 'denied', True)
        # Canonical decimals and base64url are part of the envelope, even with a genuine MAC.
        for field, values in {5: ['0', '01', '-1', '9223372036854775808', '9999999999999999999'],
                              6: ['0100000', '-1', '9223372036854775807'],
                              7: ['0100600', '100000', '31636001', '9223372036854775808']}.items():
            for value in values:
                altered = parts.copy(); altered[field] = value; altered[10] = signature(altered)
                add('.'.join(altered), state, 'denied', True)
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        last = alphabet.index(parts[10][-1])
        for low_bits in [1, 2, 3]:
            altered = parts.copy(); altered[10] = parts[10][:-1] + alphabet[(last & ~3) | low_bits]
            add('.'.join(altered), state, 'denied', True)
        for suffix in ['=', '\n', '\r\n', '.extra', ',another']:
            add(token + suffix, state, 'denied', True)
        # Well-typed storage tampering cannot elevate the signed credential, including policy/provenance.
        for field, value in [('name', 'changed'), ('scopes', ['documents:write']), ('expires', 100601),
                             ('creator', 'a' * 64), ('issuer', 'b' * 64), ('policy', 'c' * 64)]:
            tampered = copy.deepcopy(state)
            tampered['entries'][identifier][field] = value
            add(token, tampered, 'corrupt')
            if field != 'policy':
                tampered = copy.deepcopy(tampered)
                tampered['entries'][identifier]['claims'] = claims(tampered, identifier, tampered['entries'][identifier])
                add(token, tampered, 'denied')
        altered = parts.copy(); altered[9] = ('0' if parts[9][0] != '0' else '1') + parts[9][1:]
        altered[10] = signature(altered)
        add('.'.join(altered), state, 'denied')  # Even a genuine new MAC cannot match the old token digest.

actual = bridge(vectors)
assert len(actual) == len(expected)
for index, (got, (result, no_lookup)) in enumerate(zip(actual, expected)):
    assert got['result'] == result, (index, result, got)
    if no_lookup:
        assert got['calls'] == 0, (index, 'unexpected ledger access')
    assertions += 1 + int(no_lookup)
print(f'PASS independent API credential vectors: {len(issued)} PHP issues, {len(vectors)} Python requests, '
      f'{assertions} checks on {runtime}; Unicode claims, provenance/policy, HMAC, canonical numbers/base64, '
      'missing state and storage tampering; synthetic keys/accounts only')
