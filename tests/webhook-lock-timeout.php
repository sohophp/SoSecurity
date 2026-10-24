<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Webhook\InboxSchema;
use SoSecurity\Support\Deadline;
use SoSecurity\Storage\StorageException;
final class WebhookPolicyStatement extends PDOStatement {
 public static $mode;public static $closed=0;
 public function execute($params=null):bool{$r=$params===null?parent::execute():parent::execute($params);if(self::$mode==='timeout-spoof'){throw new StorageException('PRIVATE-POLICY-TIMEOUT','webhook.timeout');}if(self::$mode==='late-expired'){usleep(50000);}if(self::$mode==='execute-throw'){throw new RuntimeException('PRIVATE-POLICY-EXECUTE');}return self::$mode==='execute-false'?false:$r;}
 public function closeCursor():bool{$r=parent::closeCursor();++self::$closed;if(self::$mode==='close-throw'){throw new RuntimeException('PRIVATE-POLICY-CLOSE');}return self::$mode==='close-false'?false:$r;}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{
  $r=parent::fetchAll(...func_get_args());if(self::$mode==='fetch-throw'){throw new RuntimeException('PRIVATE-POLICY-FETCH');}
  if(self::$mode==='empty'){return [];}if(self::$mode==='extra-row'){return array_merge($r,$r);}if(self::$mode==='extra-column'){$r[0][]=1;}
  if(self::$mode==='invalid'){$r[0][0]='-1';}if(self::$mode==='zero'){$r[0][0]='0';}if(self::$mode==='overflow'){$r[0][0]='9223372036854775808';}return $r;
 }
}
$backend=$argv[1]??'sqlite';$mysql=$backend==='mysql';if(!in_array($backend,['mysql','sqlite'],true)){throw new RuntimeException('Owned backend required');}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
$modes=['normal','timeout-spoof','late-expired','execute-false','execute-throw','fetch-throw','close-false','close-throw','empty','extra-row','extra-column','invalid','zero','overflow','expired','arbitrary'];
foreach($mysql?['SELECT @@SESSION.innodb_lock_wait_timeout','SELECT @@SESSION.lock_wait_timeout']:['PRAGMA busy_timeout'] as $sql){foreach($modes as $mode){
 $directory=privateDirectory();$pdo=null;$reason=null;$failed=false;$result=null;
 try{
  $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/owned.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
  $pdo->exec($mysql?'SET SESSION innodb_lock_wait_timeout=19,lock_wait_timeout=23':'PRAGMA busy_timeout=19000');$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[WebhookPolicyStatement::class]);WebhookPolicyStatement::$mode=$mode;WebhookPolicyStatement::$closed=0;
  $deadline=new Deadline($mode==='expired'?1:($mode==='late-expired'?30:1000));if($mode==='expired'){usleep(5000);}
  try{$result=InboxSchema::lockTimeout($pdo,$mode==='arbitrary'?'SELECT 1':$sql,$deadline,$failed);}catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();Check::same(false,strpos($error->getMessage(),'PRIVATE-')!==false);Check::same(null,$error->getPrevious());}
  if($mode==='normal'||($mode==='zero'&&!$mysql)){Check::same(null,$reason);Check::same($mode==='zero'?0:($mysql?($sql==='SELECT @@SESSION.lock_wait_timeout'?23:19):19000),$result);}
  elseif(in_array($mode,['expired','late-expired'],true)){Check::same('webhook.timeout',$reason);}
  elseif($mode==='arbitrary'){Check::same('configuration.webhook_inbox',$reason);}
  elseif(in_array($mode,['close-false','close-throw'],true)){Check::same('webhook.inbox_cleanup',$reason);}
  elseif(in_array($mode,['empty','extra-row','extra-column','invalid','zero','overflow'],true)){Check::same('webhook.inbox_corrupt',$reason);}
  else{Check::same('webhook.inbox_unavailable',$reason);}
  Check::same(in_array($mode,['close-false','close-throw'],true),$failed);Check::same(in_array($mode,['expired','arbitrary'],true)?0:1,WebhookPolicyStatement::$closed);
  Check::same(false,$pdo->inTransaction());echo 'PASS Webhook SQL policy read '.json_encode(['backend'=>$backend,'query'=>$sql,'mode'=>$mode,'reason'=>$reason,'php'=>PHP_VERSION]).PHP_EOL;
 }finally{$pdo=null;cleanDirectory($directory);}
}}
