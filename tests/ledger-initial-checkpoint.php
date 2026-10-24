<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Account\Ledger;
use SoSecurity\Support\SqlTransaction;
$mysql=($argv[1]??'sqlite')==='mysql';$mode=$argv[2]??'normal';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
$directory=privateDirectory();$pdo=null;
try{
 $pdo=new InboxTestConnection($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/read.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$pdo]]);
 $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-'.($mysql?'mysql':'sqlite').'.sql'));foreach(explode(';',$ddl) as $sql){if(trim($sql)!==''){$pdo->exec($sql);}}
 $clock=new TestClock();$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$policy=new SoSecurity\Account\Policy(['maximum_entries'=>100]);$unit=new SqlTransaction($pdo,$clock,30000);$ledger=new Ledger($unit,'owned-read','tenant',str_repeat('e',64),$keys,$policy);$count=$mode==='paged'?65:3;$id=static function(int $n):string{return str_pad(dechex($n),64,'0',STR_PAD_LEFT);};
 $unit->run(static function()use($ledger,$count,$id):void{$ledger->initialize();for($i=1;$i<=$count;++$i){$ledger->put($id($i),str_repeat('a',64),'notice','owned-'.$i,100100);}});
 if($mode==='other-corrupt'){$pdo->prepare('UPDATE sosecurity_account_records SET seal=? WHERE record_id=?')->execute([str_repeat('0',64),$id(1)]);}
 if($mode==='deleted-other'){$pdo->prepare('DELETE FROM sosecurity_account_records WHERE record_id=?')->execute([$id(1)]);}
 if($mode==='body-corrupt'){$q=$pdo->prepare('UPDATE sosecurity_account_records SET payload=? WHERE record_id=?');$q->bindValue(1,str_repeat('x',strlen('owned-'.$count)),PDO::PARAM_LOB);$q->bindValue(2,$id($count));$q->execute();}
 $metadata=0;$bodies=0;$pdo->beforeStatement=static function(string $sql)use(&$metadata,&$bodies):void{if(strpos($sql,'record_id=:id')!==false&&strpos($sql,'AS payload_digest')!==false){++$metadata;}if(strpos($sql,'SELECT payload,')===0){++$bodies;}};
 $reader=SqlTransaction::forObservation($pdo,$clock,30000);$view=new Ledger($reader,'owned-read','tenant',str_repeat('e',64),$keys,$policy);$target=$mode==='missing'?$id(999):$id($count);
 $digest=static function()use($pdo):string{return hash('sha256',json_encode([$pdo->query('SELECT * FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$pdo->query('SELECT * FROM sosecurity_account_records ORDER BY namespace,record_id')->fetchAll(PDO::FETCH_ASSOC)]));};$before=$digest();
 $run=static function()use($reader,$view,$target){return $reader->run(static function()use($view,$target){return $view->readCheckpoint($target);});};
 if(in_array($mode,['other-corrupt','deleted-other','body-corrupt'],true)){Check::throws(SoSecurity\Storage\StorageException::class,$run);}
 else{$paired=$run();$row=$paired['row'];Check::same($count,$paired['checkpoint']['entries']);Check::same($mode==='missing'?null:'owned-'.$count,$row===null?null:$row['payload']);Check::same(0,$metadata);Check::same($mode==='missing'?0:1,$bodies);}
 Check::same($before,$digest());Check::same(false,$pdo->inTransaction());echo 'PASS ledger initial checkpoint '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}finally{if($pdo!==null&&$mysql){$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_records');$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_roots');}$pdo=null;gc_collect_cycles();cleanDirectory($directory);}
