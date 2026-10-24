<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SystemClock;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

$mysql=($argv[1]??'sqlite')==='mysql';$directory=$mysql?null:privateDirectory();
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';}else{$dsn='sqlite:'.$directory.'/readonly.sqlite';}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
$connect=static function()use($dsn,$mysql,$options):PDO{return new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);};
$admin=$connect();if(!$mysql){$admin->exec('PRAGMA journal_mode=DELETE');$admin->exec('PRAGMA synchronous=FULL');}
$created=false;$failures=[];$count=0;
try{
 $admin->exec('CREATE TABLE sosecurity_readonly_borrow(id INTEGER NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$created=true;
 foreach(['plain','opaque'] as $guard){foreach(['read','insert','invoke','nested','caught-insert','caught-invoke','caught-nested','ordinary-error','guard-insert','guard-invoke','guard-nested','guard-caught-insert','guard-caught-invoke','guard-caught-nested'] as $mode){
  $guarded=strpos($mode,'guard-')===0;if(($guarded&&$guard!=='opaque')||(($argv[2]??'')==='guard-only'&&!$guarded)){continue;}
  $pdo=$connect();$guardCalls=0;$onGuard=null;if($guard==='opaque'){SqlStateAccess::bind($pdo,hash('sha256','owned-readonly-'.$mode),hash('sha256','owned-readonly-binding-'.$mode),static function()use(&$guardCalls,&$onGuard):void{++$guardCalls;if($onGuard!==null){$operation=$onGuard;$onGuard=null;$operation();}});}
  $owner=new SqlTransaction($pdo,new SystemClock(),10000);$child=new SqlTransaction($pdo,new SystemClock(),10000);$grandchild=new SqlTransaction($pdo,new SystemClock(),10000);$inner=null;$caught=null;$effects=0;$reuse=0;$result=null;
  $owner->run(static function()use($owner,$child,$grandchild,$mode,&$inner,&$caught,&$effects,&$result,&$onGuard):void{
   try{$result=$child->readIn($owner,static function()use($child,$grandchild,$mode,&$caught,&$effects,&$onGuard):int{
    $guarded=strpos($mode,'guard-')===0;$operationMode=$guarded?substr($mode,6):$mode;$handled=strpos($operationMode,'caught-')===0;$action=$handled?substr($operationMode,7):$operationMode;
    $operation=static function()use($child,$grandchild,$action,&$effects):void{
     if($action==='insert'){$child->query('INSERT INTO sosecurity_readonly_borrow VALUES(2)')->closeCursor();}
     elseif($action==='invoke'){$child->invoke(static function()use(&$effects):void{++$effects;},[],'test.host_callback');}
     elseif($action==='nested'){$grandchild->readIn($child,static function()use(&$effects):void{++$effects;});}
     elseif($action==='ordinary-error'){throw new StorageException('Ordinary owned refusal.','test.refused');}
     else{Check::same(0,(int)$child->metadataRows('SELECT COUNT(*) AS n FROM sosecurity_readonly_borrow')[0]['n']);}
    };
    $execute=static function()use($guarded,$operation,$child,&$onGuard):void{if($guarded){$onGuard=$operation;$child->metadataRows('SELECT id FROM sosecurity_readonly_borrow');}else{$operation();}};
    if($handled){try{$execute();}catch(Throwable $e){$caught=$e;}}else{$execute();}
    return 17;
   });}catch(Throwable $e){$inner=$e;}
   $owner->query('INSERT INTO sosecurity_readonly_borrow VALUES(1)')->closeCursor();
  });
  $child->run(static function()use($child,&$reuse):void{$child->invoke(static function()use(&$reuse):void{++$reuse;},[],'test.reuse');$child->query('INSERT INTO sosecurity_readonly_borrow VALUES(3)')->closeCursor();});
  $ids=array_map('intval',$admin->query('SELECT id FROM sosecurity_readonly_borrow ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));$reason=static function($error):?string{return $error instanceof SecurityException||$error instanceof ConfigurationException?$error->reason():null;};
  $operationMode=$guarded?substr($mode,6):$mode;$handled=strpos($operationMode,'caught-')===0;$action=$handled?substr($operationMode,7):$operationMode;$expected=$action==='read'?null:($action==='ordinary-error'?'test.refused':($action==='nested'?'configuration.sql_transaction':'configuration.state_observation'));
  echo 'OBSERVATION readonly '.json_encode(['guard'=>$guard,'mode'=>$mode,'ids'=>$ids,'effects'=>$effects,'inner'=>$reason($inner),'caught'=>$reason($caught),'reuse'=>$reuse,'guard_calls'=>$guardCalls]).PHP_EOL;
  try{Check::same([1,3],$ids);Check::same(0,$effects);Check::same(1,$reuse);Check::same($handled?null:$expected,$reason($inner));Check::same($handled?$expected:null,$reason($caught));Check::same($expected===null||$handled?17:null,$result);Check::same(false,$pdo->inTransaction());if($guard==='opaque'){Check::same(true,$guardCalls>0);}++$count;echo 'PASS readonly borrow '.($mysql?'mysql':'sqlite').' '.$guard.' '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$guard.' '.$mode;echo 'FAIL readonly borrow '.$guard.' '.$mode.' '.$e->getMessage().PHP_EOL;}
  $admin->exec('DELETE FROM sosecurity_readonly_borrow');
 }}
}finally{if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}if($created){$admin->exec('DROP TABLE sosecurity_readonly_borrow');}if($directory!==null){$owner=null;$child=null;$grandchild=null;$pdo=null;$admin=null;cleanDirectory($directory);}}
if($failures){throw new RuntimeException('Read-only borrow cases failed: '.implode(', ',$failures));}
echo 'PASS readonly borrow complete '.$count.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
