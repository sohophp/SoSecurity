<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';require __DIR__.'/webhook-pending-support.php';
use SoSecurity\Exception\SecurityException;
final class PendingReadStatement extends InboxTestStatement
{
 public static $active=false;public static $fault='';public static $closes=0;public static $held=[];
 private function selected():bool{return self::$active&&strpos($this->queryString,' LEFT JOIN ')!==false;}
 public function execute($params=null):bool{$ok=parent::execute($params);if($this->selected()&&self::$fault==='execute-close'){throw new RuntimeException('PRIVATE-PENDING-EXECUTE');}return $ok;}
 public function fetchAll($mode=null,$className=null,$ctorArgs=null,...$extra):array{
  if($this->selected()&&in_array(self::$fault,['read','read-close'],true)){throw new RuntimeException('PRIVATE-PENDING-READ');}$rows=parent::fetchAll(...func_get_args());
  if($this->selected()&&$rows){if(self::$fault==='overflow'){$rows[]=$rows[0];}elseif(self::$fault==='missing'){unset($rows[0]['due_at']);}elseif(self::$fault==='scalar'){$rows[0]='PRIVATE-PENDING-ROW';}elseif(self::$fault==='null-with-counter'){$rows[0]['status']=null;$rows[0]['due_at']=0;}}
  return $rows;
 }
 public function closeCursor():bool{if($this->selected()){++self::$closes;self::$held[]=$this;if(self::$fault==='close-throw'){throw new RuntimeException('PRIVATE-PENDING-CLOSE');}if(in_array(self::$fault,['close-false','read-close','execute-close'],true)){return false;}}return parent::closeCursor();}
 private function releaseOwned():void{parent::closeCursor();}
 public static function drain():void{foreach(self::$held as $q){$q->releaseOwned();}self::$held=[];}
}
function pendingFailed($processor):bool{$p=new ReflectionProperty($processor,'failed');if(PHP_VERSION_ID<80100){$p->setAccessible(true);}return $p->getValue($processor);}
function pendingStamp(InboxEnvironment $e):array{
 $rows=[];foreach(['sosecurity_webhook_inbox'=>['receipt_id','payload'],'sosecurity_webhook_processing'=>['status','due_at','lease_until']] as $table=>$fields){$select=['COUNT(*) AS n'];foreach($fields as $field){$select[]='MAX('.($e->mysql?'OCTET_LENGTH('.$field.')':'length(CAST('.$field.' AS BLOB))').') AS '.$field;}$q=$e->pdo->query('SELECT '.implode(',',$select).' FROM '.$table);$rows[$table]=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();}return $rows;
}
function pendingPrivate(?Throwable $error):void{$n=0;while($error!==null){Check::same(true,++$n<=8);Check::same(true,$error instanceof SecurityException);Check::same(false,strpos($error->getMessage(),'PRIVATE-PENDING')!==false);$error=$error->getPrevious();}}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
$plans=['close-false','close-throw','read-close','execute-close','read','overflow','missing','scalar','null-with-counter','receipt-bytes','status-bytes','due-bytes','lease-bytes','duplicate','invalid-id','invalid-state'];if(!$mysql){$plans[]='cursor-equal';$plans[]='cursor-max';}
$plans=array_merge($plans,['empty','absent','ready','future','succeeded','dead','one-page','maximum-page','binary-values','integer-19','denied']);$cases=0;$failures=[];
foreach($plans as $case){$e=null;$caught=null;
 try{
  $e=new InboxEnvironment($mysql);$receipt=$e->receive();Check::same(true,$receipt instanceof SoSecurity\Webhook\Receipt);$calls=0;$processor=pendingProcessor($e,static function()use(&$calls,$case){++$calls;return $case!=='denied';});$id=$receipt->id();$limit=$case==='overflow'||$case==='one-page'?1:20;$after='';
  if(in_array($case,['status-bytes','due-bytes','lease-bytes','invalid-state','ready','future','succeeded','dead','binary-values','integer-19'],true)){pendingSeed($e,in_array($case,['succeeded','dead'],true)?$case:'ready',$case==='future'?$e->clock->time+100:($case==='integer-19'?PHP_INT_MAX-200000:null));}
  if(in_array($case,['receipt-bytes','status-bytes','due-bytes','lease-bytes'],true)){$field=['receipt-bytes'=>'receipt_id','status-bytes'=>'status','due-bytes'=>'due_at','lease-bytes'=>'lease_until'][$case];$table=$case==='receipt-bytes'?'sosecurity_webhook_inbox':'sosecurity_webhook_processing';
   if($mysql){$value=$case==='receipt-bytes'?str_repeat('z',32):($case==='status-bytes'?str_repeat('x',10):'18446744073709551615');$q=$e->pdo->prepare('UPDATE '.$table.' SET '.$field.'=:value');$q->execute(['value'=>$value]);$q->closeCursor();}
   else{$e->pdo->exec("UPDATE ".$table." SET ".$field."=replace(hex(zeroblob(1048576)),'00','x')");}
  }
  if($case==='invalid-id'){$e->pdo->exec("UPDATE sosecurity_webhook_inbox SET receipt_id='".str_repeat('z',32)."'");}
  if($case==='invalid-state'){$e->pdo->exec("UPDATE sosecurity_webhook_processing SET status='invalid'");}
  if($case==='duplicate'){pendingClone($e,$id);}
  if(in_array($case,['cursor-equal','cursor-max'],true)){$e->pdo->exec('UPDATE sosecurity_webhook_inbox SET receipt_id=CAST(receipt_id AS BLOB)');$after=$case==='cursor-equal'?$id:str_repeat('f',32);}
  if($case==='empty'){$e->pdo->exec('DELETE FROM sosecurity_webhook_inbox');}
  if($case==='maximum-page'){for($i=1;$i<=51;++$i){pendingClone($e,str_pad(dechex($i),32,'0',STR_PAD_LEFT));}$limit=50;}
  if($case==='binary-values'){$cast=$mysql?'BINARY':'BLOB';$e->pdo->exec('UPDATE sosecurity_webhook_processing SET status=CAST(status AS '.$cast.'),due_at=CAST(due_at AS '.($mysql?'CHAR':'BLOB').'),lease_until=CAST(lease_until AS '.($mysql?'CHAR':'BLOB').')');}
  $before=pendingStamp($e);$writes=0;$e->pdo->afterStatement=static function(string $sql)use(&$writes){if(preg_match('/\A(?:INSERT|UPDATE|DELETE) /',$sql)){++$writes;}};$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PendingReadStatement::class,[$e->pdo]]);PendingReadStatement::$active=true;PendingReadStatement::$fault=$case;PendingReadStatement::$closes=0;$result=null;
  try{$result=$processor->pending('owned-reader',$limit,$after);}catch(SecurityException $error){$caught=$error;}
  $bad=in_array($case,array_slice($plans,0,$mysql?16:18),true);
  if($bad){Check::same(null,$result);Check::same(true,$caught instanceof SecurityException);$cleanup=in_array($case,['close-false','close-throw','read-close','execute-close'],true);$reason=$cleanup?'webhook.processing_cleanup':($case==='read'?'webhook.inbox_unavailable':(in_array($case,['receipt-bytes','invalid-id','duplicate','cursor-equal','cursor-max'],true)?'webhook.processing_source':(in_array($case,['due-bytes','lease-bytes'],true)?'webhook.inbox_corrupt':'webhook.processing_corrupt')));Check::same($reason,$caught->reason());pendingPrivate($caught);Check::same($cleanup,pendingFailed($processor));
   if($cleanup){$oldCalls=$calls;$second=null;try{$processor->pending('owned-reader');}catch(SecurityException $error){$second=$error;}Check::same(true,$second instanceof SecurityException);Check::same('webhook.processing_cleanup',$second->reason());Check::same($oldCalls,$calls);}
   Check::same(1,PendingReadStatement::$closes);
  }else{Check::same(null,$caught);Check::same(false,pendingFailed($processor));$none=in_array($case,['empty','future','succeeded','dead','integer-19','denied'],true);$cursor=in_array($case,['empty','denied'],true)?'':$id;
   if($case==='maximum-page'){$all=array_column($e->snapshot(),'receipt_id');sort($all,SORT_STRING);Check::same(array_slice($all,0,50),$result['receipt_ids']);Check::same($all[49],$result['next_cursor']);Check::same(false,$result['complete']);$next=$processor->pending('owned-reader',50,$result['next_cursor']);Check::same(array_slice($all,50),$next['receipt_ids']);Check::same(true,$next['complete']);Check::same($all[count($all)-1],$next['next_cursor']);Check::same(2,PendingReadStatement::$closes);}
   elseif($case==='one-page'){Check::same(['receipt_ids'=>[$id],'next_cursor'=>$id,'complete'=>false],$result);Check::same(['receipt_ids'=>[],'next_cursor'=>$id,'complete'=>true],$processor->pending('owned-reader',1,$id));Check::same(2,PendingReadStatement::$closes);}
   else{Check::same(['receipt_ids'=>$none?[]:[$id],'next_cursor'=>$cursor,'complete'=>true],$result);Check::same($case==='denied'?0:1,PendingReadStatement::$closes);}
  }
  PendingReadStatement::$active=false;$e->pdo->afterStatement=null;Check::same($before,pendingStamp($e));Check::same(0,$writes);Check::same(false,$e->pdo->inTransaction());Check::same(true,memory_get_peak_usage(true)<=8388608);++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$case,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','caught_reason'=>$caught instanceof SecurityException?$caught->reason():null,'close_calls'=>PendingReadStatement::$closes,'assertion'=>$error instanceof SecurityException?null:$error->getMessage(),'duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{PendingReadStatement::$active=false;PendingReadStatement::drain();if($e!==null){$e->pdo->afterStatement=null;pendingClose($e);}}
}
echo json_encode(['cases'=>$cases,'failures'=>$failures,'assertions'=>Check::$assertions,'peak_bytes'=>memory_get_peak_usage(true)]).PHP_EOL;if($failures){throw new RuntimeException('Pending read failures retained');}echo 'PASS Webhook pending read '.($mysql?'mysql':'sqlite').PHP_EOL;
