<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function limitControl(string $sql):string{
 $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);
}
class LimitAdapter extends PDO {}
class LimitStatement extends PDOStatement {}
class LimitSwitchStatement extends PDOStatement {
 private $pdo;public static $armed=true;
 protected function __construct(PDO $pdo){$this->pdo=$pdo;}
 public function execute($parameters=null):bool{$ok=parent::execute($parameters);if(self::$armed&&$this->queryString==='SELECT @@SESSION.innodb_lock_wait_timeout'){self::$armed=false;$this->pdo->exec('SET SESSION innodb_lock_wait_timeout=11');$this->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PDOStatement::class]);}return $ok;}
}
$modes=['zero-run','zero-enlist','native-run','native-enlist','native-context-own','native-context-host','change-run','change-enlist','error-run','error-enlist','limit-run','limit-enlist','custom-clock','pdo-adapter','statement-adapter','statement-switch','opaque-guard'];
try{foreach($modes as $mode){
 if(isset($argv[1])&&$argv[1]!==$mode){continue;}
 $dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$pdo=$mode==='pdo-adapter'?new LimitAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);
 if($mode==='statement-adapter'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[LimitStatement::class]);}if($mode==='statement-switch'){LimitSwitchStatement::$armed=true;$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[LimitSwitchStatement::class,[$pdo]]);}
 if($mode==='opaque-guard'){SqlStateAccess::bind($pdo,hash('sha256','owned-limit'),hash('sha256','owned-limit-binding'),static function():void{});}
 $initial=strpos($mode,'zero-')===0?0:(strpos($mode,'limit-')===0?19:1);$requested=$initial;$pdo->exec('SET SESSION innodb_lock_wait_timeout='.$initial);$q=$pdo->query('SELECT @@SESSION.innodb_lock_wait_timeout /* owned_initial */');$initial=(int)$q->fetchColumn();$q->closeCursor();Check::same($requested===0?1:$requested,$initial);echo 'NORMALIZED_LIMIT '.$mode.' requested '.$requested.' actual '.$initial.PHP_EOL;$q=$pdo->query('SELECT CONNECTION_ID()');$id=(int)$q->fetchColumn();$q->closeCursor();
 $read=static function()use($pdo):int{$q=$pdo->query('SELECT @@SESSION.innodb_lock_wait_timeout /* owned_limit_observe */');$v=(int)$q->fetchColumn();$q->closeCursor();return $v;};
 $clock=$mode==='custom-clock'?new TestClock():new SoSecurity\Support\SystemClock();$unit=new SqlTransaction($pdo,$clock,1000);$joined=strpos($mode,'enlist')!==false||$mode==='native-context-host';$method=strpos($mode,'context')!==false?'inContext':($joined?'enlist':'run');if($joined){$pdo->beginTransaction();}
 limitControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");$reason=null;$calls=0;
 try{$result=$unit->$method(static function()use($read,$pdo,$unit,$mode,&$calls):int{++$calls;$value=$read();echo 'LIMIT_BODY '.$mode.' '.$value.PHP_EOL;Check::same(1,$value);if(strpos($mode,'change-')===0){$pdo->exec('SET SESSION innodb_lock_wait_timeout=7');}if(strpos($mode,'error-')===0){$unit->invoke(static function()use($pdo):void{$pdo->exec('SET SESSION innodb_lock_wait_timeout=7');throw new RuntimeException('PRIVATE-LIMIT-CALLBACK');},[],'test.limit');}return 23;});}catch(SoSecurity\Exception\SecurityException $error){$reason=$error->reason();Check::same(false,strpos((string)$error,'PRIVATE-LIMIT-')!==false);}
 limitControl('SET GLOBAL general_log=OFF');Check::same(1,$calls);Check::same(strpos($mode,'error-')===0?'test.limit':null,$reason);if($reason===null){Check::same(23,$result);}Check::same($initial,$read());if($joined){Check::same(true,$pdo->inTransaction());$pdo->rollBack();}
 $sets=(int)limitControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Query' AND argument='SET SESSION innodb_lock_wait_timeout=1'");
 $fallback=in_array($mode,['custom-clock','pdo-adapter','statement-adapter','statement-switch','opaque-guard'],true);$expected=$initial===0?0:($initial===19?1:($fallback?2:1));
 echo 'OBSERVATION lock limit '.json_encode(['mode'=>$mode,'set_one_commands'=>$sets,'expected'=>$expected,'restored'=>$read()]).PHP_EOL;Check::same($expected,$sets);
 Check::same(31,$unit->run(static function():int{return 31;}));Check::same($initial,$read());
 echo 'PASS SQL lock limit '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
}}finally{limitControl('SET GLOBAL general_log=OFF');if(isset($pdo)&&$pdo instanceof PDO&&$pdo->inTransaction()){$pdo->rollBack();}}
