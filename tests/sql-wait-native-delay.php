<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;
$real=getenv('SOSECURITY_TEST_MYSQL_SOCKET');$proxy=getenv('SOSECURITY_TEST_WAIT_PROXY');$arm=getenv('SOSECURITY_TEST_WAIT_ARM');$mode=$argv[1]??'';
if(!is_string($real)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$real)||!is_file(dirname($real).'/account-test-owner')||is_link(dirname($real))||!is_string($proxy)||!preg_match('~\A/tmp/sosecurity-wait-proxy-[A-Za-z0-9_-]+/pdo\.sock\z~D',$proxy)||is_link(dirname($proxy))||!is_file(dirname($proxy).'/owned-proxy')||$arm!==dirname($proxy).'/arm'||!in_array($mode,['normal','cross','expired','entry-drop','restore-drop'],true)){throw new RuntimeException('Owned native wait transport required');}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$admin=new PDO('mysql:unix_socket='.$real.';dbname=sosecurity_test','sosecurity_test','integration-only',$options);$pdo=null;$created=false;$inner=null;$outer=null;$body=0;$seen=null;$after=null;$returned=false;$written=false;$parentReturned=false;
$read=static function(PDO $p):array{$q=$p->query('SELECT @@SESSION.innodb_lock_wait_timeout,@@SESSION.lock_wait_timeout');try{return array_map('intval',$q->fetch(PDO::FETCH_NUM));}finally{$q->closeCursor();}};
try{
 $admin->exec('CREATE TABLE sosecurity_wait_delay(id INTEGER NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created=true;$pdo=new PDO('mysql:unix_socket='.$proxy.';dbname=sosecurity_test','sosecurity_test','integration-only',$options);$pdo->exec('SET SESSION innodb_lock_wait_timeout=19,lock_wait_timeout=23');$owner=new SqlTransaction($pdo,new SystemClock(),10000);$child=new SqlTransaction($pdo,new SystemClock(),$mode==='expired'?1000:3000);Check::same(true,$child->canBatchLedgerReads());
 try{$owner->run(static function()use($owner,$child,$pdo,$mode,$arm,$read,&$body,&$seen,&$after,&$returned,&$written,&$inner):void{
  if($mode!=='restore-drop'){file_put_contents($arm,'armed');}
  try{$child->readIn($owner,static function()use($pdo,$mode,$arm,$read,&$body,&$seen):void{++$body;$seen=$read($pdo);if($mode==='restore-drop'){file_put_contents($arm,'armed');}});$returned=true;}catch(Throwable $e){$inner=$e;}
  if(!in_array($mode,['entry-drop','restore-drop'],true)){$after=$read($pdo);}
  $owner->query('INSERT INTO sosecurity_wait_delay VALUES(1)')->closeCursor();$written=true;
 });$parentReturned=true;}catch(Throwable $e){$outer=$e;}
 $drop=in_array($mode,['entry-drop','restore-drop'],true);$visible=(int)$admin->query('SELECT COUNT(*) FROM sosecurity_wait_delay')->fetchColumn();$reason=$inner instanceof SoSecurity\Exception\SecurityException||$inner instanceof SoSecurity\Exception\ConfigurationException?$inner->reason():null;echo 'OBSERVATION native wait transport '.json_encode(['mode'=>$mode,'body'=>$body,'seen'=>$seen,'after'=>$after,'returned'=>$returned,'written'=>$written,'parent_returned'=>$parentReturned,'visible'=>$visible,'reason'=>$reason,'php'=>PHP_VERSION]).PHP_EOL;
 Check::same(in_array($mode,['normal','cross'],true),$returned);Check::same(in_array($mode,['normal','cross','restore-drop'],true)?1:0,$body);Check::same(!$drop,$written);Check::same(!$drop,$parentReturned);Check::same($drop?0:1,$visible);Check::same($drop?'sql.cleanup':($mode==='expired'?'sql.timeout':null),$reason);if($mode==='cross'){Check::same([3,2],$seen);}if($mode==='normal'){Check::same([3,3],$seen);}if(!$drop){Check::same([10,10],$after);Check::same([19,23],$read($pdo));}else{foreach([$owner,$child] as $failed){Check::throws(SoSecurity\Storage\StorageException::class,static function()use($failed):void{$failed->run(static function():void{});});}}echo 'PASS native wait transport '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}finally{$pdo=null;if($created){$admin->exec('DROP TABLE sosecurity_wait_delay');}}
