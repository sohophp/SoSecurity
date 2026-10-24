<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Exception\SecurityException;
use SoSecurity\Webhook\InboxSchema;
final class SchemaCleanupStatement extends InboxTestStatement
{
    public static $needle='';public static $fault='';public static $closes=0;public static $pending=[];
    public static function drain():void{foreach(self::$pending as $q){$q->releaseOwnedCursor();}self::$pending=[];}
    private function releaseOwnedCursor():void{parent::closeCursor();}
    private function selected():bool{return self::$needle!==''&&strpos($this->queryString,self::$needle)!==false;}
    public function execute($params=null):bool{$ok=parent::execute($params);if($this->selected()){if(self::$fault==='execute-close'){throw new RuntimeException('PRIVATE-SCHEMA-EXECUTE');}if(self::$fault==='timeout'){usleep(40000);}}return $ok;}
    private function reading():void{if($this->selected()&&in_array(self::$fault,['read-close','read'],true)){throw new RuntimeException('PRIVATE-SCHEMA-READ');}}
    public function fetchAll($mode=null,$className=null,$ctorArgs=null,...$extra):array{$this->reading();return parent::fetchAll(...func_get_args());}
    #[\ReturnTypeWillChange]
    public function fetch($mode=PDO::FETCH_DEFAULT,$orientation=PDO::FETCH_ORI_NEXT,$offset=0){$this->reading();return parent::fetch($mode,$orientation,$offset);}
    #[\ReturnTypeWillChange]
    public function fetchColumn($column=0){$this->reading();return parent::fetchColumn($column);}
    public function closeCursor():bool{if($this->selected()){++self::$closes;self::$pending[]=$this;if(self::$fault==='throw'){throw new RuntimeException('PRIVATE-SCHEMA-CLOSE');}if(in_array(self::$fault,['false','read-close','execute-close'],true)){return false;}}return parent::closeCursor();}
}
function schemaPrivate(?Throwable $error):void{$depth=0;while($error!==null){Check::same(true,++$depth<=8);Check::same(true,$error instanceof SecurityException);Check::same(false,strpos($error->getMessage(),'PRIVATE-SCHEMA')!==false);$error=$error->getPrevious();}}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Owned SQL required');}
$needles=$mysql?['information_schema.TABLES','@@GLOBAL.innodb_flush_log_at_trx_commit','information_schema.REFERENTIAL_CONSTRAINTS','CURRENT_USER()','information_schema.SCHEMA_PRIVILEGES','information_schema.COLUMNS','information_schema.STATISTICS']:['PRAGMA database_list','PRAGMA main.journal_mode','PRAGMA main.synchronous','pragma_foreign_key_list','main.sqlite_master','temp.sqlite_master','main.pragma_table_info(','main.pragma_index_list(','main.pragma_index_info('];
$selection=$argv[2]??'all';if(!in_array($selection,['all','locks-only'],true)){throw new RuntimeException('Use a fixed cleanup selection');}
$cases=0;$failures=[];
$plans=[];foreach($needles as $needle){foreach(['false','throw'] as $fault){$plans[]=['receive',$needle,$fault];}}
foreach(['receive','status'] as $operation){foreach(['read-close','execute-close','read'] as $fault){$plans[]=[$operation,$mysql?'information_schema.COLUMNS':'main.pragma_table_info(',$fault];}}
if($mysql){foreach(['false','throw'] as $fault){$plans[]=['status',"TABLE_NAME='sosecurity_webhook_processing'",$fault];}}
if($mysql){foreach(['sosecurity_webhook_processing','sosecurity_webhook_inbox'] as $table){foreach(['false','throw'] as $fault){$plans[]=['status','SELECT receipt_id FROM '.$table.' LIMIT 0',$fault];}}}
foreach(['normal','timeout'] as $fault){$plans[]=['statement','SELECT 73 AS owned_schema_probe',$fault];}
foreach(['receive','status'] as $operation){$plans[]=[$operation,'','normal'];}
foreach($plans as $plan){if($selection==='locks-only'&&strpos($plan[1],' LIMIT 0')===false){continue;}list($operation,$needle,$fault)=$plan;$e=null;$caught=null;
 try{
  $e=new InboxEnvironment($mysql);$processor=null;$guards=0;
  if($operation==='status'){$e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');foreach(explode(';',file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($mysql?'mysql':'sqlite').'.sql')) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}$processor=new SoSecurity\Webhook\SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,static function(){throw new RuntimeException('Mapper must not run');},static function(){throw new RuntimeException('Association must not run');},static function()use(&$guards){++$guards;return true;},null,$e->clock);}
  $e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[SchemaCleanupStatement::class,[$e->pdo]]);SchemaCleanupStatement::$needle=$needle;SchemaCleanupStatement::$fault=$fault;SchemaCleanupStatement::$closes=0;$result=null;
  try{if($operation==='statement'){$q=InboxSchema::statement($e->pdo,$needle,[],new SoSecurity\Support\Deadline($fault==='timeout'?20:30000));$result=InboxSchema::read($q,'column');}elseif($operation==='receive'){$result=$e->receive();}else{$result=$processor->status(str_repeat('a',32),'owned-worker');}}catch(SecurityException $error){$caught=$error;}
  SchemaCleanupStatement::$needle='';
  if($fault==='normal'){Check::same(null,$caught);if($operation==='statement'){Check::same(73,(int)$result);Check::same(1,SchemaCleanupStatement::$closes);}elseif($operation==='receive'){Check::same(true,$result instanceof SoSecurity\Webhook\Receipt);}else{Check::same(null,$result);}}
  else{
   Check::same(true,$caught instanceof SecurityException);$reason=$fault==='timeout'?'webhook.timeout':($fault==='read'?'webhook.inbox_unavailable':($operation==='status'?'webhook.processing_cleanup':'webhook.inbox_cleanup'));Check::same($reason,$caught->reason());Check::same(1,SchemaCleanupStatement::$closes);schemaPrivate($caught);Check::same(0,$e->count());
   if($operation!=='statement'){$object=$operation==='status'?$processor:$e->inbox;$p=new ReflectionProperty($object,'failed');if(PHP_VERSION_ID<80100){$p->setAccessible(true);}Check::same($fault!=='read',$p->getValue($object));
    if($fault!=='read'){$calls=$operation==='status'?$guards:$e->keyCalls;$second=null;try{if($operation==='status'){$processor->status(str_repeat('a',32),'owned-worker');}else{$e->receive();}}catch(SecurityException $error){$second=$error;}Check::same(true,$second instanceof SecurityException);Check::same($reason,$second->reason());Check::same($calls,$operation==='status'?$guards:$e->keyCalls);}
   }
  }
  Check::same(false,$e->pdo->inTransaction());Check::same(true,memory_get_peak_usage(true)<=8388608);++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$plan,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','caught_reason'=>$caught instanceof SecurityException?$caught->reason():null,'close_calls'=>SchemaCleanupStatement::$closes,'assertion'=>$error instanceof SecurityException?null:$error->getMessage(),'duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{SchemaCleanupStatement::$needle='';SchemaCleanupStatement::drain();if($e!==null){if($operation==='status'){$e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');}$e->close();}}
}
echo json_encode(['cases'=>$cases,'failures'=>$failures,'assertions'=>Check::$assertions,'peak_bytes'=>memory_get_peak_usage(true)]).PHP_EOL;if($failures){throw new RuntimeException('Webhook schema cleanup failures retained');}echo 'PASS webhook schema cleanup '.($mysql?'mysql':'sqlite').PHP_EOL;
