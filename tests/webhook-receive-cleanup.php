<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
final class ReceiveCleanupStatement extends InboxTestStatement {
 public static $stage='';public static $mode='';public static $seen=0;public static $closes=0;public static $counts=[];private $selected=false;
 private function matches():bool {$sql=$this->queryString;$s=self::$stage;
  if(in_array($s,['insert','update','normal-write'],true)){return (($s==='insert'||$s==='normal-write')&&strpos($sql,'INSERT')===0&&strpos($sql,'sosecurity_webhook_inbox(')!==false)||(($s==='update'||$s==='normal-write')&&strpos($sql,'UPDATE ')===0&&strpos($sql,'sosecurity_webhook_inbox SET seen_at=')!==false);}
  if(in_array($s,['record-first','record-final','observe-empty','observe-existing'],true)){return strpos($sql,'SELECT ')===0&&strpos($sql,' AS bytes FROM ')!==false&&strpos($sql,'sosecurity_webhook_inbox WHERE endpoint_key=:endpoint AND event_key=:event')!==false;}
  if(in_array($s,['capacity-empty','capacity-existing'],true)){return preg_match('/\ASELECT COUNT\(\*\) FROM (?:main\.)?sosecurity_webhook_inbox\z/',$sql)===1;}
  if($s==='payload'){return strpos($sql,'SELECT 1 FROM ')===0&&strpos($sql,' AND payload=:payload')!==false;}
  return $s==='mdl'&&strpos($sql,'SELECT receipt_id FROM ')===0&&substr($sql,-8)===' LIMIT 0';
 }
 public function execute($params=null):bool {$this->selected=$this->matches();if($this->selected){++self::$seen;if(self::$stage==='record-final'&&self::$seen!==2){$this->selected=false;}}return parent::execute($params);}
 private function fetchFault():void {if($this->selected&&in_array(self::$mode,['fetch-throw','combined'],true)){throw new RuntimeException('owned-private-receive-fetch');}}
 #[\ReturnTypeWillChange]
 public function fetch($mode=0,$orientation=PDO::FETCH_ORI_NEXT,$offset=0){$this->fetchFault();return parent::fetch($mode,$orientation,$offset);}
 #[\ReturnTypeWillChange]
 public function fetchColumn($column=0){$this->fetchFault();return parent::fetchColumn($column);}
 public function fetchAll($mode=null,$className=null,$constructorArguments=null,...$args):array {$this->fetchFault();return parent::fetchAll(...func_get_args());}
 public function rowCount():int {$value=parent::rowCount();if($this->selected){self::$counts[]=[$this->queryString,$value];if(in_array(self::$mode,['count-throw','combined'],true)){throw new RuntimeException('owned-private-receive-count');}if(self::$mode==='count-negative'){return -1;}if(self::$mode==='count-many'){return 3;}}return $value;}
 public function closeCursor():bool {if($this->selected){++self::$closes;if(self::$mode==='close-false'){return false;}if(in_array(self::$mode,['close-throw','combined'],true)){throw new RuntimeException('owned-private-receive-close');}}return parent::closeCursor();}
}
function receiveObservation($service,string $id):array {$m=new ReflectionMethod($service,'observation');if(PHP_VERSION_ID<80100){$m->setAccessible(true);}return $m->invoke($service,hash('sha256',$id),new SoSecurity\Support\Deadline(30000));}
function receiveFailed($service):bool {$p=new ReflectionProperty($service,'failed');if(PHP_VERSION_ID<80100){$p->setAccessible(true);}return $p->getValue($service);}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use owned disposable SQL only.');}
$spec=[];foreach(['record-first','record-final','payload','observe-empty','observe-existing','capacity-empty','capacity-existing'] as $stage){foreach(['close-false','close-throw','fetch-throw','combined'] as $mode){$spec[]=[$stage,$mode];}}
foreach(['insert','update'] as $stage){foreach(['close-false','close-throw','count-throw','count-negative','count-many','combined'] as $mode){$spec[]=[$stage,$mode];}}
if($mysql){foreach(['close-false','close-throw'] as $mode){$spec[]=['mdl',$mode];}}
$cases=0;$faultCases=0;$normalCases=0;$failures=[];
foreach($spec as $pair){list($stage,$mode)=$pair;$e=null;
 try{
  $e=new InboxEnvironment($mysql);$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ReceiveCleanupStatement::class,[$e->pdo]]);$service=$e->inbox;if(in_array($stage,['observe-existing','capacity-existing'],true)){Check::same(true,$e->receive() instanceof SoSecurity\Webhook\Receipt);}
  $before=hash('sha256',json_encode($e->snapshot()));$mapCalls=$e->mapCalls;ReceiveCleanupStatement::$stage=$stage;ReceiveCleanupStatement::$mode=$mode;ReceiveCleanupStatement::$seen=0;ReceiveCleanupStatement::$closes=0;ReceiveCleanupStatement::$counts=[];$caught=null;$returned=false;$observation=strpos($stage,'observe-')===0||strpos($stage,'capacity-')===0;
  try{if($observation){receiveObservation($service,$stage==='capacity-existing'?'missing-event':'msg_test');}else{$e->receive();}$returned=true;}catch(SecurityException $error){$caught=$error;}
  ReceiveCleanupStatement::$stage='';$tainted=!in_array($mode,['fetch-throw','count-many'],true);$reason=$mode==='count-many'?'webhook.inbox_corrupt':($mode==='fetch-throw'?($observation?'sql.unavailable':'webhook.inbox_unavailable'):($observation?'sql.cleanup':'webhook.inbox_cleanup'));
  Check::same(false,$returned);Check::same(true,$caught instanceof SecurityException);Check::same($reason,$caught->reason());Check::same(1,ReceiveCleanupStatement::$closes);Check::same($before,hash('sha256',json_encode($e->snapshot())));Check::same(false,$e->pdo->inTransaction());Check::same($tainted,receiveFailed($service));Check::same(false,strpos((string)$caught,'owned-private-receive-')!==false);
  $chain=$caught;$depth=0;while($chain!==null){Check::same(true,++$depth<=8);Check::same(SoSecurity\Storage\StorageException::class,get_class($chain));$chain=$chain->getPrevious();}
  if($observation){Check::same($mapCalls,$e->mapCalls);}if($tainted){$calls=$e->keyCalls;try{$e->receive();throw new RuntimeException('Failed receiver reused');}catch(SecurityException $error){Check::same('webhook.inbox_cleanup',$error->reason());}Check::same($calls,$e->keyCalls);}++$cases;++$faultCases;
 }catch(Throwable $error){$failures[]=['case'=>$stage.'/'.$mode,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{ReceiveCleanupStatement::$stage='';if($e!==null){$e->close();}}
}
foreach(['fresh-known-duplicate','association-denied','bad-signature','mapping-null','revoke-before-commit','stale-proof','observation-empty','observation-existing','observation-capacity'] as $mode){$e=null;
 try{
  $e=new InboxEnvironment($mysql);$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ReceiveCleanupStatement::class,[$e->pdo]]);
  if($mode==='fresh-known-duplicate'){ReceiveCleanupStatement::$stage='normal-write';ReceiveCleanupStatement::$mode='normal';ReceiveCleanupStatement::$counts=[];$first=$e->receive();$again=$e->receive();ReceiveCleanupStatement::$stage='';Check::same(false,$first->duplicate());Check::same(true,$again->duplicate());Check::same($first->id(),$again->id());Check::same(1,$e->count());$updates=[];$inserts=[];foreach(ReceiveCleanupStatement::$counts as $r){if(strpos($r[0],'UPDATE ')===0){$updates[]=$r[1];}else{$inserts[]=$r[1];}}Check::same([1,0],$inserts);Check::same($mysql?[0,0]:[1,1],$updates);}
  elseif($mode==='association-denied'){$e->association=false;Check::same(null,$e->receive());Check::same(0,$e->count());}
  elseif($mode==='bad-signature'){Check::same(null,$e->receive($e->request(null,null,['Webhook-Signature'=>'v1,invalid'])));Check::same(0,$e->count());}
  elseif($mode==='mapping-null'){Check::same(null,$e->inbox->accept($e->request(),static function(){return null;}));Check::same(0,$e->count());}
  elseif($mode==='revoke-before-commit'){$e->onAssociation=static function(int $calls)use($e):void{if($calls===3){$e->association=false;}};Check::throws(SecurityException::class,static function()use($e){$e->receive();});Check::same(0,$e->count());}
  elseif($mode==='stale-proof'){$e->onKey=static function(int $calls)use($e):void{if($calls===3){$e->clock->time+=301;}};Check::same(null,$e->receive());Check::same(0,$e->count());}
  else{if($mode!=='observation-empty'){Check::same(true,$e->receive() instanceof SoSecurity\Webhook\Receipt);}$maps=$e->mapCalls;$view=receiveObservation($e->inbox,$mode==='observation-capacity'?'missing-event':'msg_test');Check::same($maps,$e->mapCalls);Check::same($mode==='observation-capacity'?1:0,$view['count']);Check::same($mode==='observation-existing',is_array($view['row']));}
  Check::same(false,$e->pdo->inTransaction());Check::same(false,receiveFailed($e->inbox));++$cases;++$normalCases;
 }catch(Throwable $error){$failures[]=['case'=>$mode,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{ReceiveCleanupStatement::$stage='';if($e!==null){$e->close();}}
}
echo json_encode(['cases'=>$cases,'fault_cases'=>$faultCases,'normal_and_denial_cases'=>$normalCases,'failures'=>$failures,'assertions'=>Check::$assertions]).PHP_EOL;if($failures){throw new RuntimeException('Receive cleanup failures retained');}echo 'PASS webhook receive cleanup '.($mysql?'mysql':'sqlite').PHP_EOL;
