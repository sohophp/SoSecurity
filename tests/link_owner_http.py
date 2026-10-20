#!/usr/bin/env python3
"""Reciprocal real-account checks: a share credential grants reads, never another owner's management authority."""
import sys
import link_http as native
runtime=sys.argv[1] if len(sys.argv)>1 else 'php'
if native.subprocess.call([runtime,'-r','exit(extension_loaded("pdo_sqlite")?0:1);'])!=0:
    print('NOT RUN signed-link owner HTTP: optional PDO SQLite required')
    raise SystemExit(1 if native.os.getenv('SOSECURITY_REQUIRE_RESET')=='1' else 0)
with native.fixture(runtime) as f:
    alice=native.Visitor(f['url']);alice.call();native.check(200,alice.login()[0]);url,reference=alice.issue()
    bob=native.Visitor(f['url']);bob.call();native.check(200,bob.call('login',{'username':'other','password':'Other-link-test-password'})[0])
    for action,fields in [('revoke',{'document_id':'a','link_id':reference}),('revoke_all',{'document_id':'a'}),('list',{'document_id':'a'}),('issue',{'document_id':'a','delivery':'read'})]:
        native.check(403,bob.call(action,fields)[0])
    # A deliberately shared bearer URL still authorizes reading, even while the reader is signed in as Bob.
    native.check(200,bob.call(url=url)[0]);other,other_reference=bob.issue('once','b')
    native.check(403,alice.call('revoke',{'document_id':'b','link_id':other_reference})[0]);native.check(200,alice.call(url=other)[0]);native.check(403,alice.call(url=other)[0])
    native.check(True,alice.call('revoke',{'document_id':'a','link_id':reference})[1]['revoked']);native.check(403,bob.call(url=url)[0])
print(f'PASS reciprocal signed-link owner HTTP: {native.checks} assertions on {runtime}; real login, known-ID denial, cross-owner issue/list/revoke/revoke-all refusal and deliberate bearer read separation')
