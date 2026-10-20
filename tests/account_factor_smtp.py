#!/usr/bin/env python3
"""Real local TLS SMTP acceptance for one owned FactorNotices event and SQLite database."""
from account_smtp_server import *

with tempfile.TemporaryDirectory(prefix='sosecurity-factor-smtp-') as private:
    directory=Path(private);os.chmod(directory,0o700)
    key=directory/'key.pem';cert=directory/'ca.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=smtp.example.test','-addext','subjectAltName=DNS:smtp.example.test','-days','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
    os.chmod(key,0o600)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(cert),str(key))
    for name,extra in [('accepted',{}),('revoked-before',{'revoke':'before'}),('revoked-after',{'revoke':'after'}),('accepted-reply-lost',{'drop_after_data':True,'accept_then_drop':True})]:
        settings={'mode':'tls','coordination':str(directory/'coord.json'),**extra};relay=Relay(context,settings,directory)
        config=directory/'config.json';config.write_text(json.dumps({**settings,'port':relay.port,'ca':str(cert)}));os.chmod(config,0o600)
        result=subprocess.run([runtime,'-d','memory_limit=8M',str(stage/'tests/account-factor/smtp-notices.php'),str(config)],capture_output=True,text=True,timeout=30)
        if result.returncode:
            relay.socket.close();raise RuntimeError(name+': '+result.stdout+result.stderr)
        relay.close();actual=json.loads(result.stdout)
        if name=='accepted':assert relay.accepted and actual['result']=={'state':'submitted','code':'smtp.accepted'} and actual['queue_state']=='sent' and actual['next']['state']=='idle',actual
        if name=='revoked-before':assert not relay.body and actual['account_status']=='disabled' and actual['result']['state']=='rejected' and actual['queue_state']=='dead',actual
        if name=='revoked-after':assert relay.accepted and actual['account_status']=='disabled' and actual['error']=='account.delivery_unknown' and actual['queue_state']=='leased' and actual['next']['state']=='discarded',actual
        if name=='accepted-reply-lost':assert relay.accepted and actual['result']['state']=='unknown' and actual['queue_state']=='dead' and actual['next']['state']=='idle',actual
        if relay.body:
            mail=email.message_from_bytes(relay.body,policy=email.policy.default)
            assert mail['To']=='owned@example.test' and actual['notice_type']=='factor_management_started',actual
            assert b'token=' not in mail.get_payload(decode=True),actual
        print('PASS owned factor SQLite + real local TLS SMTP '+name,flush=True)
    print('PASS factor notice SMTP pipeline: 4 cases, owned temporary SQLite and loopback TLS only',flush=True)
