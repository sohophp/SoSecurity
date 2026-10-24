<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\Ledger;
use SoSecurity\Support\SqlTransaction;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function batchControl(string $sql):string{
 $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);
}
class BatchAdapter extends PDO {}
class BatchStatement extends PDOStatement {}
$modes=['native','empty','fenced','paged','missing','uninitialized','orphan','root-corrupt','other-corrupt','deleted-other','body-corrupt','large-body','callback-body','callback-write','custom-clock','pdo-adapter','statement-adapter','opaque-guard','row-locks','gap-locks'];
$created=[];$admin=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
try{
 $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'));foreach(explode(';',$ddl) as $sql){if(trim($sql)!==''){$admin->exec($sql);if(preg_match('/CREATE TABLE\s+(\w+)/i',$sql,$match)){$created[]=$match[1];}}}
 foreach($modes as $mode){
 if(isset($argv[1])&&$argv[1]!==$mode){continue;}
 $dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$opts=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$pdo=$mode==='pdo-adapter'?new BatchAdapter($dsn,'sosecurity_test','integration-only',$opts):new PDO($dsn,'sosecurity_test','integration-only',$opts);
 if($mode==='statement-adapter'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[BatchStatement::class]);}
 if($mode==='opaque-guard'){SoSecurity\Support\SqlStateAccess::bind($pdo,hash('sha256','owned-batch'),hash('sha256','owned-binding'),static function():void{});}
 $clock=$mode==='custom-clock'?new TestClock():new SoSecurity\Support\SystemClock();if($clock instanceof TestClock){$clock->time=time();}
 $keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$policy=new SoSecurity\Account\Policy(['maximum_entries'=>100]);$unit=new SqlTransaction($pdo,$clock,30000);$ledger=new Ledger($unit,'owned-batch-'.$mode,'tenant',str_repeat('e',64),$keys,$policy,$mode==='fenced'?2:1,$mode==='fenced'?str_repeat('f',64):null);
 $count=in_array($mode,['empty','fenced','gap-locks','uninitialized'],true)?0:($mode==='paged'?65:3);$id=static function(int $n):string{return str_pad(dechex($n),64,'0',STR_PAD_LEFT);};$target=$id($mode==='missing'?999:$count);$namespace=null;
 if($mode!=='uninitialized'){$checkpoint=$unit->run(static function()use($ledger,$count,$id,$clock):array{$ledger->initialize();for($i=1;$i<=$count;++$i){$ledger->put($id($i),str_repeat('b',64),'notice','owned-body-'.$i,$clock->now()+3600);}return $ledger->checkpoint();});$namespace=$checkpoint['namespace'];}
 if($mode==='orphan'){$q=$admin->prepare('DELETE FROM sosecurity_account_roots WHERE namespace=?');$q->execute([$namespace]);}
 if($mode==='root-corrupt'){$q=$admin->prepare('UPDATE sosecurity_account_roots SET seal=? WHERE namespace=?');$q->execute([str_repeat('0',64),$namespace]);}
 if($mode==='other-corrupt'){$q=$admin->prepare('UPDATE sosecurity_account_records SET seal=? WHERE namespace=? AND record_id=?');$q->execute([str_repeat('0',64),$namespace,$id(1)]);}
 if($mode==='deleted-other'){$q=$admin->prepare('DELETE FROM sosecurity_account_records WHERE namespace=? AND record_id=?');$q->execute([$namespace,$id(1)]);}
 if(in_array($mode,['body-corrupt','large-body'],true)){$q=$admin->prepare("UPDATE sosecurity_account_records SET payload=REPEAT('x',".($mode==='large-body'?'8388608':'length(payload)').') WHERE namespace=? AND record_id=?');$q->execute([$namespace,$target]);}
 $digest=static function()use($admin):string{return hash('sha256',json_encode([$admin->query('SELECT namespace,seal FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$admin->query('SELECT namespace,record_id,seal,length(payload),SHA2(payload,256) FROM sosecurity_account_records ORDER BY namespace,record_id')->fetchAll(PDO::FETCH_ASSOC)]));};$before=$digest();
 $q=$pdo->query('SELECT CONNECTION_ID()');$thread=(int)$q->fetchColumn();$q->closeCursor();$native=$unit->canBatchLedgerReads();$reason=null;$calls=0;
 batchControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
 try{$result=$unit->run(static function()use($ledger,$mode,$target,$count,$pdo,$admin,$namespace,$unit,$clock,&$calls){
  if($mode==='orphan'){return $ledger->initialize();}
  if(in_array($mode,['callback-body','callback-write'],true)){
   $old=$ledger->checkpoint();$ledger->readCheckpoint($target,static function()use($ledger,$mode,$pdo,$namespace,$target,$unit,$clock,&$calls):void{$unit->invoke(static function()use($ledger,$mode,$pdo,$namespace,$target,$clock,&$calls):void{++$calls;if($mode==='callback-body'){$q=$pdo->prepare("UPDATE sosecurity_account_records SET payload=REPEAT('x',length(payload)) WHERE namespace=? AND record_id=?");$q->execute([$namespace,$target]);}else{$ledger->put($target,str_repeat('b',64),'notice','owned-body-3',$clock->now()+3600,1);}},[],'test.callback');});
   Check::same(null,$ledger->readIfCheckpoint($target,$old));throw new SoSecurity\Storage\StorageException('Undo owned test change.','test.rollback');
  }
  if(in_array($mode,['body-corrupt','large-body','missing'],true)){return $ledger->read($target);}
  $value=$ledger->checkpoint();
  if(in_array($mode,['row-locks','gap-locks'],true)){
   $admin->exec('SET SESSION innodb_lock_wait_timeout=1');$queries=[['UPDATE sosecurity_account_roots SET revision=revision WHERE namespace=?',[$namespace]]];
   if($mode==='row-locks'){$queries[]=['UPDATE sosecurity_account_records SET revision=revision WHERE namespace=? AND record_id=?',[$namespace,str_pad('1',64,'0',STR_PAD_LEFT)]];}
   else{$fields=array_keys(Ledger::recordTypes());$queries[]=['INSERT INTO sosecurity_account_records('.implode(',',$fields).') VALUES('.implode(',',array_fill(0,count($fields),'?')).')',[$namespace,str_repeat('a',64),str_repeat('b',64),'notice',1,1,10,1,1,str_repeat('d',64),'owned',str_repeat('e',64),'x']];}
   foreach($queries as $item){$locked=false;try{$q=$admin->prepare($item[0]);$q->execute($item[1]);}catch(PDOException $error){$locked=isset($error->errorInfo[1])&&(int)$error->errorInfo[1]===1205;}Check::same(true,$locked);}
  }return $value;
 });}catch(SoSecurity\Exception\SecurityException $error){$reason=$error->reason();}
 batchControl('SET GLOBAL general_log=OFF');
 $expected=in_array($mode,['uninitialized','orphan'],true)?'account.uninitialized':(in_array($mode,['root-corrupt','other-corrupt','deleted-other','body-corrupt','large-body','callback-body'],true)?'account.corrupt':($mode==='callback-write'?'test.rollback':null));Check::same($expected,$reason);
 if($expected===null){if($mode==='missing'){Check::same(null,$result);}else{Check::same($count,$result['entries']);}}
 if(strpos($mode,'callback-')===0){Check::same(1,$calls);}
 if(!in_array($mode,['callback-body','callback-write','orphan'],true)){
 $reads=(int)batchControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$thread." AND command_type='Execute' AND argument LIKE 'SELECT CASE WHEN %' AND (argument LIKE '% FROM sosecurity_account_roots %' OR (argument LIKE '% FROM sosecurity_account_records %' AND argument LIKE '% ORDER BY %'))");
 $expectedReads=$native?1:2;if($mode==='paged'){++$expectedReads;}if(in_array($mode,['uninitialized','root-corrupt'],true)){$expectedReads=1;}
 echo 'OBSERVATION batch reads '.$mode.' '.$reads.' native '.($native?'yes':'no').PHP_EOL;Check::same($expectedReads,$reads);
 }
 Check::same($before,$digest());Check::same(false,$pdo->inTransaction());Check::same(true,memory_get_peak_usage(true)<8388608);echo 'PASS ledger root batch '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }
}finally{batchControl('SET GLOBAL general_log=OFF');if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
