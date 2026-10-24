<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
final class PolicyDriftClock implements SoSecurity\Support\Clock{
 public $action;
 public function now():int{if($this->action!==null){$action=$this->action;$this->action=null;$action();}return 100000;}
}
$mysql=($argv[1]??'sqlite')==='mysql';$directory=$mysql?null:privateDirectory();
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';}else{$dsn='sqlite:'.$directory.'/policy.sqlite';}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
$connect=static function()use($dsn,$mysql,$options):PDO{return new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);};
$admin=$connect();$created=false;$failures=[];$count=0;
try{
 $admin->exec('CREATE TABLE sosecurity_policy_drift(id INTEGER NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$created=true;
 foreach($mysql?['emulate','silent','warning']:['silent','warning'] as $attribute){foreach(['owned','borrowed'] as $ownership){foreach(['body','guard','clock'] as $entry){foreach(['query','metadata'] as $api){
  $pdo=$connect();$clock=new PolicyDriftClock();$guardAction=null;
  if($entry==='guard'){SqlStateAccess::bind($pdo,hash('sha256','policy-context-'.($count++)),hash('sha256','policy-binding-'.($count)),static function()use(&$guardAction):void{if($guardAction!==null){$action=$guardAction;$guardAction=null;$action();}});}
  $unit=new SqlTransaction($pdo,$clock,10000);$owner=new SqlTransaction($pdo,$clock,10000);$failure=null;$returned=false;$mutations=0;
  $mutate=static function()use($pdo,$attribute,&$mutations):void{++$mutations;$pdo->setAttribute($attribute==='emulate'?PDO::ATTR_EMULATE_PREPARES:PDO::ATTR_ERRMODE,$attribute==='emulate'?true:($attribute==='silent'?PDO::ERRMODE_SILENT:PDO::ERRMODE_WARNING));};
  $restore=static function()use($pdo,$mysql):void{$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);if($mysql){$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}};
  $body=static function()use($pdo,$unit,$api,$entry,$mutate,$restore,$clock,&$guardAction,&$failure,&$returned):void{
   try{
    if($entry==='guard'){$guardAction=$mutate;}elseif($entry==='clock'){$clock->action=$mutate;}else{$mutate();}
    $sql='SELECT 1 AS n; INSERT INTO sosecurity_policy_drift VALUES(1)';
    if($api==='query'){$unit->query($sql)->closeCursor();}else{$unit->metadataRows($sql);}$returned=true;
   }catch(Throwable $e){$failure=$e;}finally{$guardAction=null;$clock->action=null;$restore();}
  };
  if($ownership==='borrowed'){$owner->run(static function()use($owner,$unit,$body):void{$unit->readIn($owner,$body);$owner->query('INSERT INTO sosecurity_policy_drift VALUES(2)')->closeCursor();});}
  else{$unit->run(static function()use($unit,$body):void{$body();$unit->query('INSERT INTO sosecurity_policy_drift VALUES(2)')->closeCursor();});}
  $ids=array_map('intval',$admin->query('SELECT id FROM sosecurity_policy_drift ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));$reason=$failure instanceof SecurityException||$failure instanceof ConfigurationException?$failure->reason():null;
  $label=$attribute.' '.$ownership.' '.$entry.' '.$api;echo 'OBSERVATION policy '.json_encode(['case'=>$label,'mutations'=>$mutations,'returned'=>$returned,'ids'=>$ids,'reason'=>$reason]).PHP_EOL;
  try{Check::same(1,$mutations);Check::same(false,$returned);Check::same('configuration.sql_transaction',$reason);Check::same([2],$ids);Check::same(false,$pdo->inTransaction());echo 'PASS policy drift '.$label.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$label;echo 'FAIL policy drift '.$label.' '.$e->getMessage().PHP_EOL;}
  $admin->exec('DELETE FROM sosecurity_policy_drift');
 }}}}
}finally{if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}if($created){$admin->exec('DROP TABLE sosecurity_policy_drift');}if($directory!==null){$unit=null;$owner=null;$pdo=null;$admin=null;cleanDirectory($directory);}}
if($failures){throw new RuntimeException('Policy drift cases failed: '.count($failures));}
echo 'PASS policy drift complete '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
