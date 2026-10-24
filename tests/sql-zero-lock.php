<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
foreach(['run','enlist','context-own','context-host','readIn'] as $mode){
 $pdo=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$pdo->exec('PRAGMA busy_timeout=0');$unit=new SqlTransaction($pdo,new TestClock(),1000);$value=null;$host=in_array($mode,['enlist','context-host'],true);
 $read=static function()use($pdo):int{$q=$pdo->query('PRAGMA busy_timeout');$v=(int)$q->fetchColumn();$q->closeCursor();return $v;};
 try{
  if($host){$pdo->beginTransaction();}
  if($mode==='readIn'){$owner=new SqlTransaction($pdo,new TestClock(),1000);$value=$owner->run(static function()use($pdo,$unit,$owner,$read):int{$pdo->exec('PRAGMA busy_timeout=0');return $unit->readIn($owner,$read);});}
  else{$method=strpos($mode,'context-')===0?'inContext':$mode;$value=$unit->$method($read);}
  $restored=$read();if($host){Check::same(true,$pdo->inTransaction());$pdo->rollBack();}
  echo 'OBSERVATION zero lock '.json_encode(['mode'=>$mode,'inside'=>$value,'restored'=>$restored]).PHP_EOL;Check::same(0,$value);Check::same(0,$restored);echo 'PASS SQL zero lock '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }finally{if($pdo->inTransaction()){$pdo->rollBack();}}
}
