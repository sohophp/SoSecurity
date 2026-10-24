<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';require __DIR__.'/webhook-pending-support.php';
use SoSecurity\Exception\SecurityException;
final class PendingAuthorityStatement extends InboxTestStatement
{
 public static $afterClose;public static $closes=0;
 public function closeCursor():bool{$closed=parent::closeCursor();if(strpos($this->queryString,' LEFT JOIN ')!==false){++self::$closes;if(self::$afterClose!==null){(self::$afterClose)();}}return $closed;}
}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Owned SQL required');}
$cases=0;$failures=[];
foreach(['close-revoked','commit-revoked','guard-error'] as $case){$e=null;$caught=null;
 try{$e=new InboxEnvironment($mysql);$receipt=$e->receive();Check::same(true,$receipt instanceof SoSecurity\Webhook\Receipt);$allowed=true;$guardCalls=0;$processor=pendingProcessor($e,static function()use(&$allowed,&$guardCalls,$case){++$guardCalls;if($case==='guard-error'&&$guardCalls>1){throw new RuntimeException('PRIVATE-PENDING-AUTHORITY');}return $allowed;});
  $before=$e->snapshot();$writes=0;$e->pdo->afterStatement=static function(string $sql)use(&$writes){if(preg_match('/\A(?:INSERT|DELETE|UPDATE) /',$sql)){++$writes;}};$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PendingAuthorityStatement::class,[$e->pdo]]);PendingAuthorityStatement::$closes=0;PendingAuthorityStatement::$afterClose=$case==='close-revoked'?static function()use(&$allowed){$allowed=false;}:null;if($case==='commit-revoked'){$e->pdo->beforeCommit=static function()use(&$allowed){$allowed=false;};}$result=null;
  try{$result=$processor->pending('owned-reader');}catch(SecurityException $error){$caught=$error;}
  PendingAuthorityStatement::$afterClose=null;$e->pdo->beforeCommit=null;$e->pdo->afterStatement=null;
  if($case==='close-revoked'){Check::same(null,$caught);Check::same(['receipt_ids'=>[],'next_cursor'=>'','complete'=>true],$result);}
  else{Check::same(null,$result);Check::same(true,$caught instanceof SecurityException);Check::same($case==='commit-revoked'?'webhook.processing_denied':'webhook.processing_authority',$caught->reason());$error=$caught;$depth=0;while($error!==null){Check::same(true,++$depth<=8);Check::same(true,$error instanceof SecurityException);Check::same(false,strpos($error->getMessage(),'PRIVATE-PENDING')!==false);$error=$error->getPrevious();}}
  Check::same(1,PendingAuthorityStatement::$closes);Check::same(true,$guardCalls>=2);Check::same($before,$e->snapshot());Check::same(0,$writes);Check::same(false,$e->pdo->inTransaction());++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$case,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','caught_reason'=>$caught instanceof SecurityException?$caught->reason():null,'assertion'=>$error instanceof SecurityException?null:$error->getMessage(),'duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{PendingAuthorityStatement::$afterClose=null;if($e!==null){$e->pdo->beforeCommit=null;$e->pdo->afterStatement=null;pendingClose($e);}}
}
echo json_encode(['cases'=>$cases,'failures'=>$failures,'assertions'=>Check::$assertions]).PHP_EOL;if($failures){throw new RuntimeException('Pending authority failures retained');}echo 'PASS pending authority '.($mysql?'mysql':'sqlite').PHP_EOL;
