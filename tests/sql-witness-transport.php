<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';
$multiAttribute=PHP_VERSION_ID>=80400?\Pdo\Mysql::ATTR_MULTI_STATEMENTS:PDO::MYSQL_ATTR_MULTI_STATEMENTS;
$bufferedAttribute=PHP_VERSION_ID>=80400?\Pdo\Mysql::ATTR_USE_BUFFERED_QUERY:PDO::MYSQL_ATTR_USE_BUFFERED_QUERY;
foreach(['refresh','first-error','second-error','multi-disabled','ended','early-rollback','unbuffered','nested-savepoints'] as $mode){
 $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];if($mode==='multi-disabled'){$options[$multiAttribute]=false;}if($mode==='unbuffered'){$options[$bufferedAttribute]=false;}
 $pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$error=null;$result=null;$marker='sosecurity_owned_transport_marker';$before='sosecurity_owned_transport_before';$missing='sosecurity_owned_transport_absent';
 try{
  Check::same(true,$pdo->beginTransaction());$pdo->exec('SAVEPOINT '.$before);$pdo->exec('SAVEPOINT '.$marker);
  if($mode==='nested-savepoints'){
   $probe=static function(PDO $connection,string $name):bool{try{$connection->exec('RELEASE SAVEPOINT '.$name);return true;}catch(PDOException $error){Check::same(1305,(int)$error->errorInfo[1]);return false;}};
   $child='sosecurity_owned_transport_child';$pdo->exec('SAVEPOINT '.$child);Check::same(0,$pdo->exec('RELEASE SAVEPOINT '.$marker.'; SAVEPOINT '.$marker));Check::same(true,$probe($pdo,$marker));$combinedChild=$probe($pdo,$child);Check::same(0,$pdo->exec('RELEASE SAVEPOINT '.$before));$pdo->rollBack();
   $pdo->beginTransaction();$pdo->exec('SAVEPOINT '.$before);$pdo->exec('SAVEPOINT '.$marker);$pdo->exec('SAVEPOINT '.$child);$pdo->exec('RELEASE SAVEPOINT '.$marker);$pdo->exec('SAVEPOINT '.$marker);Check::same(true,$probe($pdo,$marker));$separateChild=$probe($pdo,$child);Check::same(0,$pdo->exec('RELEASE SAVEPOINT '.$before));Check::same($separateChild,$combinedChild);
   echo 'OBSERVATION nested savepoints separate '.($separateChild?'retained':'removed').' combined '.($combinedChild?'retained':'removed').' PHP '.PHP_VERSION.PHP_EOL;
   echo 'PASS witness transport '.$mode.' PHP '.PHP_VERSION.PHP_EOL;continue;
  }
  if($mode==='ended'){$pdo->exec('COMMIT');}
  if($mode==='early-rollback'){$pdo->exec('ROLLBACK TO SAVEPOINT '.$before);}
  $first=$mode==='first-error'?$missing:$marker;$second=$mode==='second-error'?'RELEASE SAVEPOINT '.$missing:'SAVEPOINT '.($mode==='first-error'?$missing:$marker);
  try{$result=$pdo->exec('RELEASE SAVEPOINT '.$first.'; '.$second);}catch(PDOException $caught){$error=$caught;}
  if(in_array($mode,['first-error','ended','early-rollback'],true)){Check::same(true,$error instanceof PDOException);Check::same(1305,(int)$error->errorInfo[1]);}
  elseif($mode==='multi-disabled'){Check::same(true,$error instanceof PDOException);Check::same(1064,(int)$error->errorInfo[1]);Check::same('42000',$error->errorInfo[0]);Check::same(0,$pdo->exec('RELEASE SAVEPOINT '.$marker));$pdo->exec('SAVEPOINT '.$marker);}
  elseif($mode==='second-error'){
   if($error===null){Check::same(null,$error);Check::same(1,$result);Check::same(false,$result===0);echo 'OBSERVATION legacy second error returned success PHP '.PHP_VERSION.PHP_EOL;}
   else{Check::same(true,$error instanceof PDOException);Check::same(1305,(int)$error->errorInfo[1]);}
  }else{Check::same(null,$error);Check::same(0,$result);Check::same(0,$pdo->exec('RELEASE SAVEPOINT '.$marker));$pdo->exec('SAVEPOINT '.$marker);}
  if(in_array($mode,['first-error','second-error','ended','early-rollback'],true)){
   // A failed RELEASE must never be followed by creation of a new apparent witness.
   $missingError=null;try{$pdo->exec('RELEASE SAVEPOINT '.$marker);}catch(PDOException $caught){$missingError=$caught;}
   if($mode==='first-error'){Check::same(null,$missingError);$uncreated=null;try{$pdo->exec('RELEASE SAVEPOINT '.$missing);}catch(PDOException $caught){$uncreated=$caught;}Check::same(true,$uncreated instanceof PDOException);Check::same(1305,(int)$uncreated->errorInfo[1]);}else{Check::same(true,$missingError instanceof PDOException);Check::same(1305,(int)$missingError->errorInfo[1]);}
  }
  $q=$pdo->query('SELECT 1');Check::same(1,(int)$q->fetchColumn());Check::same(true,$q->closeCursor());
  echo 'PASS witness transport '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }finally{if($mode!=='ended'){$pdo->exec('ROLLBACK');}$pdo=null;}
}
