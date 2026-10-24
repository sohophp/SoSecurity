<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
$mysql=($argv[1]??'')==='mysql';
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required.');}}
foreach(['request','association','key'] as $authority){foreach(['final-read','commit','cleanup'] as $phase){
 inboxCase($mysql,static function(InboxEnvironment $e)use($authority,$phase):void{
  $allowed=true;$triggered=false;$revoke=static function()use($e,$authority,&$allowed,&$triggered):void{$triggered=true;if($authority==='request'){$allowed=false;}elseif($authority==='association'){$e->association=false;}else{$e->keyOnline=false;}};
  $verifier=new SoSecurity\Webhook\Verifier($e->endpoint,static function()use($e){return $e->keyOnline?$e->keys:null;},static function()use(&$allowed):bool{return $allowed;},$e->clock);$e->inbox=$e->service(null,$verifier);
  if($phase==='final-read'){$e->pdo->afterStatement=static function(string $sql)use($revoke):void{if(strpos($sql,'SELECT 1 FROM ')===0&&strpos($sql,'payload=:payload')!==false){$revoke();}};}
  elseif($phase==='commit'){$e->pdo->afterCommit=$revoke;}
  else{$committed=false;$e->pdo->afterCommit=static function()use(&$committed):void{$committed=true;};$e->pdo->afterExec=static function(string $sql)use(&$committed,$revoke):void{if($committed&&(strpos($sql,'PRAGMA busy_timeout=')===0||strpos($sql,'SET SESSION innodb_lock_wait_timeout=')===0)){$revoke();}};}
  try{$e->receive();throw new LogicException('Withdrawn completion authority accepted: '.$authority.'/'.$phase);}catch(SoSecurity\Exception\SecurityException $error){Check::same(true,in_array($error->reason(),['webhook.denied','webhook.completion_denied'],true));}
  Check::same(true,$triggered);Check::same($phase==='final-read'?0:1,$e->count());Check::same(false,$e->pdo->inTransaction());
 });
}}
echo 'PASS Webhook completion authority: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;
