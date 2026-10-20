#!/usr/bin/env python3
"""Process genuine Ed25519 receipts in a second runtime without sodium or publisher keys."""
import json
import subprocess
import sys
from webhook_http import fixture,deliver,root,check
from webhook_processing_http import worker

producer=sys.argv[1]
consumer=sys.argv[2]
assert subprocess.check_output([consumer,'-r','echo extension_loaded("sodium")?"yes":"no";'],text=True)=='no'
with fixture(producer,processing=True) as f:
    inputs={'database':str(f['database']),'seals':str(f['seal_file']),'url':f['url']}
    received=subprocess.run([producer,str(root/'tests/webhook-processing-history.php'),'receive'],input=json.dumps(inputs),capture_output=True,text=True,check=True,timeout=10)
    check('',received.stderr);inputs['receipt']=json.loads(received.stdout)['receipt_id']
    f['provider_file'].unlink()
    processed=subprocess.run([consumer,str(root/'tests/webhook-processing-history.php'),'process'],input=json.dumps(inputs),capture_output=True,text=True,check=True,timeout=10)
    check('',processed.stderr);check(False,json.loads(processed.stdout)['sodium']);check(3,json.loads(processed.stdout)['assertions'])
    check(1,f['db'].execute('SELECT event_count FROM webhook_example_projection').fetchone()[0]);check(1,f['db'].execute('SELECT COUNT(*) FROM webhook_example_effects').fetchone()[0])
    f['save_provider']();check(200,deliver(f,identifier='cli-without-sodium')[0]);f['provider_file'].unlink()
    check(1,worker(consumer,f)['succeeded']);check(2,f['db'].execute('SELECT event_count FROM webhook_example_projection').fetchone()[0])
print('PASS genuine Ed25519 historical receipt: accepted with sodium, processed once without sodium or publisher keys after signature window; real private SQLite business transaction')
print('PASS native CLI processing without sodium: actual Standard HMAC receipt, no publisher/MFA/password services, exactly one additional stable business effect')
