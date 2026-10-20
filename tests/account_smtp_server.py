import sqlite3,base64,concurrent.futures,email,email.policy,hashlib,json,os,socket,ssl,subprocess,sys,tempfile,threading,time
from pathlib import Path
stage=Path(__file__).resolve().parent.parent
runtime=sys.argv[1]
output=Path(sys.argv[2]) if len(sys.argv)>2 else Path(tempfile.mkdtemp(prefix='sosecurity-mail-results-'));output.mkdir(parents=True,exist_ok=True)
class Relay:
 def __init__(self,context,settings,directory):
  self.context=context;self.s=settings;self.commands=[];self.body=b'';self.accepted=False;self.error=None;self.authenticated=False
  self.socket=socket.socket(socket.AF_UNIX if settings['mode']=='unix' else socket.AF_INET,socket.SOCK_STREAM)
  if settings['mode']=='unix':self.path=str(directory/'relay.sock');self.socket.bind(self.path);self.port=25
  else:self.socket.bind(('127.0.0.1',0));self.port=self.socket.getsockname()[1];self.path=None
  self.socket.listen(1);self.socket.settimeout(10);self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
 def read(self,connection):
  data=b''
  while not data.endswith(b'\r\n'):
   part=connection.recv(1)
   if not part:return data
   data+=part
   if len(data)>65536:raise RuntimeError('Owned client exceeded test line bound')
  return data
 def revoke(self):
  path=self.s.get('coordination')
  if not path:return
  details=json.loads(Path(path).read_text());database=Path(details['database']);assert str(database).startswith('/tmp/sosecurity-test-') and database.parent.stat().st_mode&0o077==0
  with sqlite3.connect(str(database),timeout=1) as db:db.execute("UPDATE account_example SET status='disabled',credential_version='owned-revocation'")
 def run(self):
  connection=None
  try:
   connection,_=self.socket.accept();connection.settimeout(5);tls=self.s['mode']=='tls'
   if self.s.get('tls_delay'):time.sleep(self.s['tls_delay'])
   if tls:connection=self.context.wrap_socket(connection,server_side=True)
   if self.s.get('greeting_delay'):time.sleep(self.s['greeting_delay'])
   connection.sendall(b'220 owned local relay\r\n')
   while True:
    line=self.read(connection)
    if not line:return
    verb=line.split(b' ',1)[0].strip().upper();self.commands.append((verb.decode('ascii','replace')+' [redacted]') if verb==b'AUTH' else line.decode('utf8','replace').strip())
    if verb==b'EHLO':
     if self.s.get('revoke')=='before':self.revoke()
     if self.s.get('ehlo_raw'):connection.sendall(self.s['ehlo_raw'].encode());continue
     if self.s.get('large_header'):connection.sendall(b'250-'+b'X'*16777216+b'\r\n250 OK\r\n');continue
     if self.s.get('oversize'):connection.sendall(b'250-'+b'X'*600+b'\r\n250 OK\r\n');continue
     lines=[b'250-owned local relay',b'250-SIZE 16384']
     if self.s['mode']=='starttls' and not tls and not self.s.get('no_starttls'):lines.append(b'250-STARTTLS')
     if self.s.get('smtp_utf8') and not (tls and self.s.get('strip_utf8_after_tls')):lines.append(b'250-SMTPUTF8')
     lines.append(b'250 AUTH PLAIN');connection.sendall(b'\r\n'.join(lines)+b'\r\n')
    elif verb==b'STARTTLS':
     connection.sendall(b'220 begin TLS\r\n');connection=self.context.wrap_socket(connection,server_side=True);connection.settimeout(5);tls=True
    elif verb==b'AUTH':
     if not tls:raise RuntimeError('Credentials were disclosed without TLS')
     parts=line.strip().split(b' ')
     if len(parts)<3:
      connection.sendall(b'334 \r\n');encoded=self.read(connection).strip();self.commands.append('AUTH DATA [redacted]')
     else:encoded=parts[2]
     fields=base64.b64decode(encoded).split(b'\x00');self.authenticated=len(fields)==3 and fields[0] in [b'',b'owned-user'] and fields[1:]==[b'owned-user',b'owned-password'];connection.sendall(b'235 authenticated\r\n' if self.authenticated and not self.s.get('auth_refuse') else b'535 rejected\r\n')
    elif verb==b'MAIL':connection.sendall(b'250 sender accepted\r\n')
    elif verb==b'RCPT':connection.sendall(b'550 recipient rejected\r\n' if self.s.get('recipient_refused') else b'250 recipient accepted\r\n')
    elif verb==b'DATA':
     connection.sendall(b'354 send content\r\n');parts=[]
     while True:
      part=self.read(connection)
      if not part:return
      if part==b'.\r\n':break
      parts.append(part[1:] if part.startswith(b'..') else part)
     self.body=b''.join(parts)
     if self.s.get('revoke')=='after':self.revoke()
     if self.s.get('drop_after_data'):
      self.accepted=self.s.get('accept_then_drop',False);return
     if self.s.get('delay_after_data'):time.sleep(self.s['delay_after_data'])
     code=self.s.get('final',250)
     if code==250:self.accepted=True
     if self.s.get('large_final'):connection.sendall(b'250 '+b'X'*16777216+b'\r\n');return
     connection.sendall(str(code).encode()+(b'\r\n' if self.s.get('bare_final') else b' owned final response\r\n'))
    elif verb==b'QUIT':connection.sendall(b'221 bye\r\n');return
    else:connection.sendall(b'500 unsupported\r\n')
  except (ConnectionError,ssl.SSLError,socket.timeout,OSError) as exc:self.error=type(exc).__name__
  finally:
   if connection is not None:connection.close()
   self.socket.close()
 def close(self):
  self.thread.join(timeout=7)
  if self.thread.is_alive():self.socket.close();raise RuntimeError('Owned SMTP server did not finish')
  if self.path and Path(self.path).exists():Path(self.path).unlink()
