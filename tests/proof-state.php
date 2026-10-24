<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account as A;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Captcha\Captcha;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
$mysql=($argv[1]??'')==='mysql';$mode=$argv[2]??'normal';$directory=privateDirectory();$created=false;$pdo=null;
try{
 foreach(['files','scratch','witness','other'] as $part){mkdir($directory.'/'.$part,0700);}
 if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required.');}}
 $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/state.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
 if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
 $pdo->exec('CREATE TABLE proof_owned_permissions(id INTEGER NOT NULL PRIMARY KEY, enabled INTEGER NOT NULL)'.($mysql?' ENGINE=InnoDB':''));$created=true;$pdo->exec('INSERT INTO proof_owned_permissions VALUES(1,1)');
 $clock=new TestClock();$store=new SoSecurity\Storage\FileStore($directory.'/files','proof-state:tokens',$clock);$old=new CsrfTokens($store,30,4,$clock);
 $sql=new A\SqlStateSnapshot($pdo,'proof-owned-permissions',['proof_owned_permissions'=>['columns'=>['id'=>'int','enabled'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>1]],30000);
 $files=new A\FileStateSnapshot($pdo,'proof-owned-files',$directory.'/files',$directory.'/scratch',2,30000);$source=new A\CompositeStateSnapshot($pdo,['permissions'=>$sql,'files'=>$files],30000);
 $keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('w',32)]);$witness=new A\LocalStateWitness($pdo,$directory.'/witness','proof-state','tenant',str_repeat('e',64),$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);$witness->initialize($source->digest());$boundary=new A\StateBoundary($witness,static function():bool{return true;});
 $calls=0;$guardMode='allow';$late=0;$expireAt=0;$nested=null;
 $guard=static function(string &$action,string &$authorityScope,string &$scope,string &$binding)use($pdo,$clock,&$calls,&$guardMode,&$late,&$expireAt,&$nested){
  ++$calls;if($expireAt!==0&&$calls===$expireAt){$clock->time+=7200;}if($nested!==null){$fn=$nested;$nested=null;$fn();}
  if($guardMode==='error'){throw new RuntimeException('SYNTHETIC-PRIVATE-REQUEST');}if($guardMode==='boolean'){return true;}if($guardMode==='deny'||($late!==0&&$calls===$late)){return null;}
  $allowed=$authorityScope==='tenant'&&$scope==='form'&&in_array($binding,['browser','browser2','browser3'],true)&&(int)$pdo->query('SELECT enabled FROM proof_owned_permissions WHERE id=1')->fetchColumn()===1;
  $action='mutated';$authorityScope='mutated';$scope='mutated';$binding='mutated';return $allowed?'actual-browser':null;
 };
 $inspect=static function()use($witness):array{return $witness->inspect(static function():bool{return true;});};$initial=$inspect();
 $state=new A\StateProofConnection($boundary,$witness,$source,$files,'files',$store,'proof-state','tenant',str_repeat('e',64),$clock,$guard);
 $sdk=SoSecurity\Security::fromArray(['site'=>'proof-state'],[],$clock);$csrf=$sdk->csrf($state);$captcha=$sdk->captcha($state);
 Check::same(0,$calls);Check::same($initial,$inspect());
 if($mode==='deadline'){
  $GLOBALS['proof_deadline_fault']=true;
  try{Check::throws(StorageException::class,static function()use($csrf){$csrf->issue('form','browser');});}finally{$GLOBALS['proof_deadline_fault']=false;}
  Check::same($initial,$inspect());$token=$csrf->issue('form','browser');Check::same(true,$csrf->verify('form','browser',$token,true));
  echo 'PASS native proof deadline construction: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
 }
 Check::throws(ConfigurationException::class,static function()use($state){SoSecurity\Security::fromArray(['site'=>'wrong'],[],new TestClock())->csrf($state);});
 Check::throws(ConfigurationException::class,static function()use($store,$state){new CsrfTokens($store,30,4,new TestClock(),$state);});
 Check::throws(ConfigurationException::class,static function()use($csrf){$csrf->issue('password-reset','browser');});
 foreach([$old,new CsrfTokens(new SoSecurity\Storage\FileStore($directory.'/files','foreign',$clock),30,4,$clock)] as $raw){
  try{$raw->issue('form','browser');throw new LogicException('Raw proof bypass');}catch(StorageException $error){Check::same('account.state_required',$error->reason());}
 }
 Check::same(false,$csrf->verify('form','browser',str_repeat('a',64),true));Check::same($initial,$inspect());
 $guardMode='deny';Check::throws(SecurityException::class,static function()use($csrf){$csrf->issue('form','browser');});Check::same(false,$captcha->verify('form','browser',str_repeat('a',32),'1'));Check::same($initial,$inspect());
 foreach(['error','boolean'] as $guardMode){try{$csrf->issue('form','browser');throw new LogicException('Bad guard accepted');}catch(SoSecurity\Exception\DependencyException $error){Check::same('proof.authority_unavailable',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'SYNTHETIC')!==false);}Check::same($initial,$inspect());}$guardMode='allow';
 $nested=static function()use($csrf){Check::throws(ConfigurationException::class,static function()use($csrf){$csrf->issue('form','browser');});};
 $token=$csrf->issue('form','browser');$record=$inspect();Check::same('proof.csrf.issue',$record['intent']['action']);Check::same('authorized',$record['intent']['kind']);Check::same(false,strpos(json_encode($record),$token)!==false);Check::same(false,strpos(json_encode($record),'actual-browser')!==false);
 Check::same(true,$csrf->verify('form','browser',$token));Check::same($record,$inspect());
 Check::same(false,$csrf->verify('form','other',$token,true));Check::same($record,$inspect());
 if($mode==='race'){
  if($mysql){throw new RuntimeException('Use the separately declared SQLite worker test');}
  file_put_contents($directory.'/proof-worker-owner','owned proof workers');$jobs=[];$wins=0;
  try{
   for($i=0;$i<4;++$i){$process=proc_open('exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/proof-state-worker.php'),[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot start proof worker');}$jobs[]=[$process,$pipes];$input=json_encode(['directory'=>$directory,'token'=>$token]);if(fwrite($pipes[0],$input)!==strlen($input)){throw new RuntimeException('Worker input incomplete');}fclose($pipes[0]);}
   foreach($jobs as &$job){list($process,$pipes)=$job;$output=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($process);$job=null;Check::same(0,$code);Check::same('',$error);Check::same(true,in_array($output,['0','1'],true));$wins+=(int)$output;}unset($job);
   Check::same(1,$wins);Check::same('current',$inspect()['status']);Check::same($source->digest(),$inspect()['digest']);
   echo 'PASS native proof process consumption: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
  }finally{foreach($jobs as $job){if($job===null){continue;}list($process,$pipes)=$job;foreach($pipes as $pipe){if(is_resource($pipe)){fclose($pipe);}}if(is_resource($process)){proc_terminate($process);proc_close($process);}}}
 }
 if(in_array($mode,['expiry-admission','expiry-late'],true)){
  $calls=0;$expireAt=$mode==='expiry-admission'?2:4;
  if($mode==='expiry-admission'){Check::same(false,$csrf->verify('form','browser',$token,true));Check::same($record,$inspect());}
  else{try{$csrf->verify('form','browser',$token,true);throw new LogicException('Late expiry accepted');}catch(SecurityException $error){Check::same('account.completion_unknown',$error->reason());}Check::same('pending',$inspect()['status']);}
  echo 'PASS native proofs '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
 }
 if($mode==='late'){$calls=0;$late=4;try{$csrf->verify('form','browser',$token,true);throw new LogicException('Post-consumption loss accepted');}catch(SecurityException $error){Check::same('account.completion_unknown',$error->reason());}Check::same('pending',$inspect()['status']);echo 'PASS native proofs late: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;}
 $path=$directory.'/files/'.$store->snapshotFile(SoSecurity\Support\Guard::key('csrf','form','browser'));$backup=file_get_contents($path);
 Check::same(true,$csrf->verify('form','browser',$token,true));Check::same('proof.csrf.verify',$inspect()['intent']['action']);$record=$inspect();Check::same(false,$csrf->verify('form','browser',$token,true));Check::same($record,$inspect());
 if($mode==='restore'){file_put_contents($path,$backup);chmod($path,0600);$before=$calls;try{$csrf->verify('form','browser',$token,true);throw new LogicException('Old consumed proof revived');}catch(StorageException $error){Check::same('account.witness_stale',$error->reason());}Check::same($before,$calls);echo 'PASS native proofs restore: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;}
 $challenge=$captcha->arithmetic('form','browser');preg_match('/^(\d+) \+ (\d+)/',$challenge->prompt,$parts);$answer=(string)($parts[1]+$parts[2]);
 Check::same(false,$captcha->verify('form','browser',$challenge->id,'wrong'));Check::same('proof.captcha.verify',$inspect()['intent']['action']);
 Check::same(true,$captcha->verify('form','browser',$challenge->id,$answer));$record=$inspect();Check::same(false,$captcha->verify('form','browser',$challenge->id,$answer));Check::same($record,$inspect());
 $challenge=$captcha->arithmetic('form','browser');preg_match('/^(\d+) \+ (\d+)/',$challenge->prompt,$parts);$answer=(string)($parts[1]+$parts[2]);
 for($i=0;$i<3;++$i){Check::same(false,$captcha->verify('form','browser',$challenge->id,'wrong'));}Check::same(false,$captcha->verify('form','browser',$challenge->id,$answer));
 $token=$csrf->issue('form','browser');$challenge=$captcha->arithmetic('form','browser');
 $record=$inspect();Check::throws(SecurityException::class,static function()use($state,$store,$clock){(new CsrfTokens($store,30,4,$clock,$state))->issue('form','other');});Check::same($record,$inspect());
 try{$csrf->issue('form','browser2');throw new LogicException('Physical capacity exceeded');}catch(SecurityException $error){Check::same('proof.capacity',$error->reason());}Check::same($record,$inspect());
 $boundary->run('owned.permission.disable',static function()use($pdo){$pdo->exec('UPDATE proof_owned_permissions SET enabled=0 WHERE id=1');});$record=$inspect();Check::same(false,$csrf->verify('form','browser',$token,true));Check::same($record,$inspect());
 $boundary->run('owned.permission.enable',static function()use($pdo){$pdo->exec('UPDATE proof_owned_permissions SET enabled=1 WHERE id=1');});
 $csrf->revoke('form','browser');Check::same('proof.csrf.revoke',$inspect()['intent']['action']);$captcha->revoke('form','browser');Check::same('proof.captcha.revoke',$inspect()['intent']['action']);Check::same([] ,glob($directory.'/files/*.json'));
 $short=new CsrfTokens($store,1,4,$clock,$state);$token=$short->issue('form','browser');$clock->time+=1;$record=$inspect();Check::same(false,$short->verify('form','browser',$token,true));Check::same($record,$inspect());$short->revoke('form','browser');
 Check::same('current',$inspect()['status']);Check::same($source->digest(),$inspect()['digest']);
 echo 'PASS native proofs: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;
}finally{if($mysql&&$created){$pdo->exec('DROP TABLE proof_owned_permissions');}foreach(['files','scratch','witness','other'] as $part){cleanDirectory($directory.'/'.$part);}cleanDirectory($directory);}
