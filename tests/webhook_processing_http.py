#!/usr/bin/env python3
"""Actual TLS reception, independent CLI SQL work, strong operator retry and stable business idempotency."""
import argparse
import json
import os
import subprocess
import time
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from webhook_http import fixture, deliver, payload, Visitor, otp, check, root, SCOPE, ACCOUNT, PASSWORD
import webhook_http


def worker(runtime, fixture_data, *arguments, success=True, environment=None, handler_failure=False):
    env=dict(fixture_data['env'] if environment is None else environment)
    # Historical work needs neither publisher signing keys nor the operator's MFA secrets or password source.
    for name in ['SOSECURITY_WEBHOOK_EXAMPLE_PROVIDER_KEYS','SOSECURITY_WEBHOOK_EXAMPLE_MFA_KEYS','SOSECURITY_WEBHOOK_EXAMPLE_DUMMY_HASH','SOSECURITY_TEST_WEBHOOK_INGRESS']:
        env.pop(name,None)
    result=subprocess.run([runtime,str(root/'examples/webhook-worker.php'),'--once',*arguments],env=env,capture_output=True,text=True,timeout=20)
    if handler_failure or success:
        check(2 if handler_failure else 0,result.returncode);check('',result.stderr);data=json.loads(result.stdout)
        check(['claimed','complete','failed','next_cursor','succeeded'],sorted(data));check(1 if handler_failure else 0,data['failed'])
        return data
    check(1,result.returncode);check('',result.stdout);check('webhook_worker.unavailable\n',result.stderr)


def prepare_dead(runtime,f,receipt):
    result=subprocess.run([runtime,str(root/'tests/webhook-processing-setup.php')],input=json.dumps({'database':str(f['database']),'seals':str(f['seal_file']),'url':f['url'],'receipt':receipt}),capture_output=True,text=True,check=True,timeout=15)
    check('',result.stderr);check('dead',json.loads(result.stdout)['status'])


def run(runtime, tls=True, browser=False):
    with fixture(runtime,tls=tls,processing=True) as f:
        db=f['db']
        count=lambda:db.execute('SELECT COALESCE(SUM(event_count),0) FROM webhook_example_projection').fetchone()[0]
        status,data,_=deliver(f,identifier='work-1');check(200,status);receipt=data['receipt_id']
        check(0,count());check(0,db.execute('SELECT COUNT(*) FROM sosecurity_webhook_processing').fetchone()[0])
        result=worker(runtime,f);check(1,result['claimed']);check(1,result['succeeded']);check(True,result['complete']);check(1,count())
        check('succeeded',db.execute('SELECT status FROM sosecurity_webhook_processing WHERE receipt_id=?',(receipt,)).fetchone()[0])
        check(1,db.execute('SELECT COUNT(*) FROM webhook_example_effects').fetchone()[0]);check([],list(f['sessions'].iterdir()))
        check(0,worker(runtime,f)['claimed']);check(1,count())
        check(True,deliver(f,identifier='work-1')[1]['duplicate']);check(0,worker(runtime,f)['claimed']);check(1,count())

        # Remove only this fixture's security history; its independent business ledger still prevents a second effect.
        db.execute('DELETE FROM sosecurity_webhook_processing');db.execute('DELETE FROM sosecurity_webhook_inbox');db.commit()
        check(False,deliver(f,identifier='work-1')[1]['duplicate']);check(1,worker(runtime,f)['succeeded']);check(1,count())

        # Operator recovery starts with a genuine public-API terminal failure, never a forged SQL status.
        status,data,_=deliver(f,identifier='retry-1');check(200,status);dead=data['receipt_id']
        prepare_dead(runtime,f,dead);check(0,worker(runtime,f)['claimed']);check(1,count())
        anonymous=Visitor(f['url'],f['ca']);check(200,anonymous.call()[0]);check(403,anonymous.call('retry',{'receipt_id':dead})[0])
        admin=Visitor(f['url'],f['ca']);check(200,admin.call()[0]);check('mfa_required',admin.login()[1]['stage'])
        check(403,admin.call('retry',{'receipt_id':dead})[0])
        status,data,_=admin.call();flow=data['flow_id'];status,data,_=admin.call('second_factor',{'flow_id':flow,'code':otp(f['factor']['uri'])});check(200,status);check('authenticated',data['stage'])
        rows={row['receipt_id']:row for row in data['receipts']};check('dead',rows[dead]['processing']['status'])
        raw=json.dumps(data)
        for secret in ['DOCUMENT-PRIVATE','body_digest','claim_digest','worker_digest','seal_key','payload']:
            check(False,secret in raw)
        snapshot=db.execute('SELECT * FROM sosecurity_webhook_processing ORDER BY receipt_id').fetchall()
        check(403,admin.call('retry',{'receipt_id':dead},csrf='wrong')[0]);check(snapshot,db.execute('SELECT * FROM sosecurity_webhook_processing ORDER BY receipt_id').fetchall());check(1,count())
        check(400,admin.call('retry',{'receipt_id':dead,'attempt':0})[0]);check(400,admin.call('retry',{'receipt_id':'../bad'})[0])
        check(409,admin.call('retry',{'receipt_id':'a'*32})[0]);check(409,admin.call('retry',{'receipt_id':receipt})[0]);check(1,count())
        status,data,_=admin.call('retry',{'receipt_id':dead});check(200,status);check(True,data['retry_scheduled']);check(1,count())
        check(1,worker(runtime,f)['succeeded']);check(2,count());check(409,admin.call('retry',{'receipt_id':dead})[0])
        check(1,db.execute('SELECT manual_retries FROM sosecurity_webhook_processing WHERE receipt_id=?',(dead,)).fetchone()[0])

        # Current enabled state is rechecked after durable receipt acceptance and before any business work.
        status,data,_=deliver(f,identifier='disabled-later');check(200,status);blocked=data['receipt_id']
        db.execute('UPDATE webhook_documents SET enabled=0 WHERE tenant=? AND account=? AND id=?',(SCOPE,ACCOUNT,'a'));db.commit()
        worker(runtime,f,success=False);check(2,count());check(0,db.execute('SELECT COUNT(*) FROM sosecurity_webhook_processing WHERE receipt_id=?',(blocked,)).fetchone()[0])
        db.execute('UPDATE webhook_documents SET enabled=1 WHERE tenant=? AND account=? AND id=?',(SCOPE,ACCOUNT,'a'));db.commit()
        check(1,worker(runtime,f)['succeeded']);check(3,count())

        # Losing the publisher verification file does not prevent independently sealed historical work.
        status,data,_=deliver(f,identifier='withdrawn-key');check(200,status)
        f['provider_file'].unlink();check(1,worker(runtime,f)['succeeded']);check(4,count());f['save_provider']()

        # Revoking current operator roles invalidates metadata reads and management authority.
        db.execute('UPDATE webhook_accounts SET roles=? WHERE tenant=? AND subject=?',('["reader"]',SCOPE,'admin'));db.commit()
        status,data,_=admin.call();check(True,status in (200,403));check(False,'receipts' in data);check(403,admin.call('retry',{'receipt_id':dead})[0]);check(4,count())

        # Wrong worker configuration and absent schema fail without installing or resetting anything.
        for variable,value in [('SOSECURITY_WEBHOOK_EXAMPLE_WORKER','untrusted label'),('SOSECURITY_WEBHOOK_EXAMPLE_PROCESSING','0'),('SOSECURITY_WEBHOOK_EXAMPLE_DOCUMENT_ROOT',str(f['work']))]:
            worker(runtime,f,success=False,environment=dict(f['env'],**{variable:value}));check(4,count())
        db.execute('DROP TABLE sosecurity_webhook_processing');db.commit();worker(runtime,f,success=False)
        check(0,db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='sosecurity_webhook_processing'").fetchone()[0]);check(4,count())

    # A bounded page requires continuation, including empty pages containing only completed records.
    with fixture(runtime,tls=tls,processing=True) as f:
        for number in range(21):check(200,deliver(f,identifier='page-'+str(number))[0])
        first=worker(runtime,f);check(20,first['succeeded']);check(False,first['complete']);check(32,len(first['next_cursor']))
        second=worker(runtime,f,'--after='+first['next_cursor']);check(1,second['succeeded']);check(True,second['complete'])
        first=worker(runtime,f);check(0,first['claimed']);check(False,first['complete'])
        second=worker(runtime,f,'--after='+first['next_cursor']);check(0,second['claimed']);check(True,second['complete'])
        check(21,f['db'].execute('SELECT SUM(event_count) FROM webhook_example_projection').fetchone()[0])
        worker_url=f['url'].replace('/webhooks.php','/webhook-worker.php')
        client=urllib.request.build_opener(*([urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(f['ca'])))] if f['ca'] else []))
        try:response=client.open(worker_url,timeout=10)
        except urllib.error.HTTPError as error:response=error
        with response:check(404,response.status);check(b'',response.read())
        check(21,f['db'].execute('SELECT SUM(event_count) FROM webhook_example_projection').fetchone()[0])

    # Conflicting content after security-history loss cannot be silently treated as a previously applied event.
    with fixture(runtime,tls=tls,processing=True) as f:
        check(200,deliver(f,identifier='stable-conflict')[0]);check(1,worker(runtime,f)['succeeded']);db=f['db']
        before=db.execute('SELECT * FROM webhook_example_effects').fetchall();projection=db.execute('SELECT * FROM webhook_example_projection').fetchall()
        db.execute('DELETE FROM sosecurity_webhook_processing');db.execute('DELETE FROM sosecurity_webhook_inbox')
        db.execute('INSERT INTO webhook_documents VALUES(?,?,?,?,?,?)',(SCOPE,ACCOUNT,'b','1',1,'PRIVATE-B'));db.commit()
        changed=json.loads(payload('stable-conflict'));changed['resource']='b'
        check(200,deliver(f,identifier='stable-conflict',body=json.dumps(changed,separators=(',',':')).encode())[0]);worker(runtime,f,handler_failure=True)
        check(before,db.execute('SELECT * FROM webhook_example_effects').fetchall());check(projection,db.execute('SELECT * FROM webhook_example_projection').fetchall())
        check(('retry','example.business_failed'),db.execute('SELECT status,error_code FROM sosecurity_webhook_processing').fetchone())

    # A known handler rollback schedules bounded automatic retry without duplicating its partially inserted business ledger.
    with fixture(runtime,tls=tls,processing=True) as f:
        db=f['db'];db.execute('INSERT INTO webhook_example_projection VALUES(?,?,?,?,?,?)',(SCOPE,ACCOUNT,'a','1',1000000000,'x'*64));db.commit()
        check(200,deliver(f,identifier='retry-handler')[0]);check(1,worker(runtime,f,handler_failure=True)['failed'])
        check(0,db.execute('SELECT COUNT(*) FROM webhook_example_effects').fetchone()[0]);check('retry',db.execute('SELECT status FROM sosecurity_webhook_processing').fetchone()[0])
        db.execute('UPDATE webhook_example_projection SET event_count=999999999');db.commit();time.sleep(1.05)
        check(1,worker(runtime,f)['succeeded']);check(1,db.execute('SELECT COUNT(*) FROM webhook_example_effects').fetchone()[0]);check(1000000000,db.execute('SELECT event_count FROM webhook_example_projection').fetchone()[0])

    if browser:
        with fixture(runtime,tls=True,processing=True) as f:
            check(200,deliver(f,identifier='<script>alert(1)</script>')[0]);status,data,_=deliver(f,identifier='browser-dead');check(200,status);prepare_dead(runtime,f,data['receipt_id'])
            env=dict(f['env'],SOSECURITY_TEST_WEBHOOK_PASSWORD=PASSWORD,SOSECURITY_TEST_WEBHOOK_OTP_URI=f['factor']['uri'])
            env['SOSECURITY_TEST_WEBHOOK_SCREENSHOT']='/tmp/sosecurity-r43-processing-'+subprocess.check_output([runtime,'-r','echo PHP_MAJOR_VERSION.PHP_MINOR_VERSION;'],text=True)+'-mobile.png'
            subprocess.run(['node',str(root/'tests/webhook-processing-browser.cjs'),f['url']],env=env,check=True,timeout=60)
            check(2,worker(runtime,f)['succeeded']);check(2,f['db'].execute('SELECT SUM(event_count) FROM webhook_example_projection').fetchone()[0])

    # Inclusion does not run main, initialize a session, read configuration or print output.
    probe='$_SERVER["SCRIPT_FILENAME"]="/different-entry.php"; ob_start(); require $argv[1]; $out=ob_get_clean(); echo json_encode([$out,session_status(),headers_sent()]);'
    result=subprocess.run([runtime,'-r',probe,str(root/'examples/webhook-worker.php')],capture_output=True,text=True,check=True,timeout=5)
    check('',result.stderr);check(['',1,False],json.loads(result.stdout))
    print(f'PASS webhook processing native {"TLS" if tls else "HTTP"}/CLI: {webhook_http.checks} assertions on '+subprocess.check_output([runtime,'-r','echo PHP_VERSION;'],text=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('runtime');parser.add_argument('--http',action='store_true');parser.add_argument('--browser',action='store_true');args=parser.parse_args();run(args.runtime,not args.http,args.browser)
