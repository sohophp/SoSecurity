<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Account\Ledger;
final class FixedContextAdapter extends PDO {}
final class FixedContextStatement extends PDOStatement {}
function fixedContextControl(string $sql):string
{
    $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if(!is_resource($p)){throw new RuntimeException('Owned controller unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned controller failed');}return trim($out);
}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];
try{
    foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)===''){continue;}$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}
    $admin->exec('CREATE TABLE sosecurity_fixed_business(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created[]='sosecurity_fixed_business';
    foreach(['native','custom-clock','pdo-adapter','statement-adapter','opaque-guard','generic','generic-ended','generic-throw','native-budget'] as $mode){
        $pdo=$mode==='pdo-adapter'?new FixedContextAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);
        if($mode==='statement-adapter'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[FixedContextStatement::class]);}
        if($mode==='opaque-guard'){SqlStateAccess::bind($pdo,hash('sha256','owned-fixed-context'),hash('sha256','owned-fixed-binding'),static function():void{});}
        $clock=$mode==='custom-clock'?new TestClock():new SoSecurity\Support\SystemClock();$unit=new SqlTransaction($pdo,$clock,$mode==='native-budget'?1000:10000);
        $ledger=new Ledger($unit,'owned','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]),new SoSecurity\Account\Policy());
        $q=$pdo->query('SELECT CONNECTION_ID()');$thread=(int)$q->fetchColumn();$q->closeCursor();
        $count=static function()use($thread):int{return (int)fixedContextControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$thread." AND command_type='Query' AND argument LIKE 'RELEASE SAVEPOINT sosecurity_unit_%'");};
        $armed=false;$delta=null;$completed=false;$reason=null;
        $verify=static function()use($ledger,$unit,$pdo,$mode,&$armed):void{
            if(strpos($mode,'generic')===0){$unit->verifySchema('owned-generic',static function():void{},static function()use($pdo,$mode,&$armed):array{if($armed&&$mode==='generic-ended'){$pdo->exec('COMMIT');$pdo->exec('START TRANSACTION');}if($armed&&$mode==='generic-throw'){throw new RuntimeException('PRIVATE-FIXED-CONTEXT');}return ['owned'=>true];});}
            else{$ledger->verifySchema();}
        };
        try{
            fixedContextControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
            try{$unit->run(static function()use($unit,$pdo,$admin,$verify,$count,$mode,&$armed,&$delta,&$completed):void{
                $unit->query('INSERT INTO sosecurity_fixed_business VALUES(1)')->closeCursor();Check::same(0,(int)$admin->query('SELECT COUNT(*) FROM sosecurity_fixed_business')->fetchColumn());
                $verify();$armed=true;$before=$count();
                try{if($mode==='native-budget'){usleep(1100000);}$verify();$completed=true;}finally{$delta=$count()-$before;}
            });}catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();Check::same(false,strpos((string)$error,'PRIVATE-FIXED-CONTEXT')!==false);}
            fixedContextControl('SET GLOBAL general_log=OFF');
            echo 'OBSERVATION fixed context '.json_encode(['mode'=>$mode,'witness_refreshes'=>$delta,'completed'=>$completed,'reason'=>$reason]).PHP_EOL;
            $expected=in_array($mode,['native'],true)?1:(strpos($mode,'generic')===0?($mode==='generic-throw'?1:2):0);
            Check::same($expected,$delta);
            $failure=in_array($mode,['generic-ended','generic-throw','native-budget'],true);
            Check::same(!$failure,$completed);Check::same($mode==='generic-ended'?'sql.cleanup':($mode==='generic-throw'?'sql.unavailable':($mode==='native-budget'?'sql.timeout':null)),$reason);
            Check::same(in_array($mode,['generic-throw','native-budget'],true)?0:1,(int)$admin->query('SELECT COUNT(*) FROM sosecurity_fixed_business')->fetchColumn());
            echo 'PASS SQL fixed context '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
        }finally{fixedContextControl('SET GLOBAL general_log=OFF');try{$pdo->exec('ROLLBACK');}catch(Throwable $cleanup){}$admin->exec('DELETE FROM sosecurity_fixed_business');$pdo=null;}
    }
}finally{fixedContextControl('SET GLOBAL general_log=OFF');foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
