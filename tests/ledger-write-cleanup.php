<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\Ledger;
use SoSecurity\Account\Policy;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
ini_set('zend.exception_ignore_args','0');
final class LedgerWriteCleanupStatement extends PDOStatement
{
    protected function __construct(){}
    public static $stage='';public static $fault='';public static $counts=0;public static $closes=0;
    private function target():bool
    {
        if(!preg_match('/\A(INSERT INTO|UPDATE|DELETE FROM) (?:main\.)?sosecurity_account_(roots|records)\b/',$this->queryString,$m)){return false;}
        $stage=$m[2]==='roots'?($m[1]==='INSERT INTO'?'root-insert':'root-update'):($m[1]==='INSERT INTO'?'record-insert':($m[1]==='DELETE FROM'?'record-delete':'record-update'));
        return self::$stage===$stage||(self::$stage==='record-reseal'&&$stage==='record-update');
    }
    public function rowCount():int
    {
        if($this->target()){
            ++self::$counts;
            if(in_array(self::$fault,['count-throw','combined'],true)){throw new RuntimeException('owned-private-write-count');}
            if(self::$fault==='count-negative'){return -1;}
        }
        return parent::rowCount();
    }
    public function closeCursor():bool
    {
        if($this->target()){
            ++self::$closes;if(in_array(self::$fault,['close-throw','combined'],true)){throw new RuntimeException('owned-private-write-close');}
            if(self::$fault==='close-false'){return false;}
        }
        return parent::closeCursor();
    }
}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use the owned disposable SQL test server.');}
$directory=privateDirectory();$pdo=null;$cases=0;
try{
    $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_STATEMENT_CLASS=>[LedgerWriteCleanupStatement::class]];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
    $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/ledger.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
    if($mysql){$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_records');$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_roots');}else{$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
    $pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/account-'.($mysql?'mysql':'sqlite').'.sql'));
    $pdo->exec('CREATE TABLE sosecurity_owned_write_probe(id INTEGER NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));
    $clock=new TestClock();$keys=new HmacKeys('one',['one'=>str_repeat('k',32)]);$policy=new Policy();$id=str_repeat('a',64);$owner=str_repeat('b',64);
    $digest=static function()use($pdo):string{return hash('sha256',json_encode([$pdo->query('SELECT * FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$pdo->query('SELECT * FROM sosecurity_account_records ORDER BY namespace,record_id')->fetchAll(PDO::FETCH_ASSOC)]));};
    foreach(['root-insert','record-insert','record-update','root-update','record-delete','record-reseal'] as $stage){foreach(['close-false','close-throw','count-throw','count-negative','combined'] as $fault){
        LedgerWriteCleanupStatement::$stage='';LedgerWriteCleanupStatement::$fault='';LedgerWriteCleanupStatement::$counts=0;LedgerWriteCleanupStatement::$closes=0;
        $pdo->exec('DELETE FROM sosecurity_account_records');$pdo->exec('DELETE FROM sosecurity_account_roots');
        $unit=new SqlTransaction($pdo,$clock,10000);$ledger=new Ledger($unit,'site','tenant',str_repeat('e',64),$keys,$policy);
        if($stage!=='root-insert'){$unit->run(static function()use($ledger,$stage,$id,$owner):void{$ledger->initialize();if($stage!=='record-insert'){$ledger->put($id,$owner,'notice','owned-old-body',100900);}});}
        if($stage==='record-reseal'){$ledger=new Ledger($unit,'site','tenant',str_repeat('e',64),new HmacKeys('two',['one'=>str_repeat('k',32),'two'=>str_repeat('j',32)]),$policy);}
        $before=$digest();$caught=false;$returned=false;$continued=false;$outer=null;
        try{$unit->run(static function()use($unit,$ledger,$stage,$fault,$id,$owner,&$caught,&$returned,&$continued):void{
            $unit->query('INSERT INTO sosecurity_owned_write_probe VALUES(1)')->closeCursor();
            LedgerWriteCleanupStatement::$stage=$stage;LedgerWriteCleanupStatement::$fault=$fault;
            try{
                if($stage==='root-insert'){$ledger->initialize();}
                elseif($stage==='record-delete'){$ledger->remove([$id=>1]);}
                elseif($stage==='record-reseal'){$ledger->reseal([$id=>1]);}
                else{$ledger->put($id,$owner,'notice','owned-new-body',100900,$stage==='record-insert'?null:1);}
                $returned=true;
            }catch(SecurityException $error){
                Check::same(in_array($fault,['count-throw','count-negative'],true)?'sql.unavailable':'sql.cleanup',$error->reason());
                Check::same(false,strpos((string)$error,'owned-private-write-')!==false);Check::same(null,$error->getPrevious());$caught=true;
            }
            try{$unit->query('SELECT 1');$continued=true;}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}
            LedgerWriteCleanupStatement::$stage='';
        });}catch(SecurityException $error){$outer=$error->reason();}finally{LedgerWriteCleanupStatement::$stage='';}
        Check::same(true,$caught);Check::same(false,$returned);Check::same(false,$continued);Check::same('sql.cleanup',$outer);Check::same(false,$unit->committed());
        Check::same(1,LedgerWriteCleanupStatement::$counts);Check::same(1,LedgerWriteCleanupStatement::$closes);Check::same($before,$digest());
        Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_owned_write_probe')->fetchColumn());Check::same(false,$pdo->inTransaction());++$cases;
    }}
    // Normal counts, zero matching rows, rejected reads/DDL, and read-only refusal keep their exact behavior.
    $unit=new SqlTransaction($pdo,$clock,10000);
    $unit->run(static function()use($unit):void{
        Check::same(1,$unit->execute('INSERT INTO sosecurity_owned_write_probe VALUES(1)'));
        Check::same(0,$unit->execute('DELETE FROM sosecurity_owned_write_probe WHERE id=2'));
        foreach(['SELECT 1','PRAGMA synchronous','CREATE TABLE forbidden_write_probe(id INTEGER)'] as $sql){Check::throws(ConfigurationException::class,static function()use($unit,$sql):void{$unit->execute($sql);});}
        Check::same(1,$unit->execute('DELETE FROM sosecurity_owned_write_probe WHERE id=1'));
    });
    $reader=SqlTransaction::forObservation($pdo,$clock,10000);$reader->run(static function()use($reader):void{Check::throws(ConfigurationException::class,static function()use($reader):void{$reader->execute('INSERT INTO sosecurity_owned_write_probe VALUES(1)');});});
    Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_owned_write_probe')->fetchColumn());
    echo 'PASS ledger write cleanup '.($mysql?'mysql':'sqlite').' '.$cases.' cases '.Check::$assertions.' assertions'.PHP_EOL;
}finally{
    LedgerWriteCleanupStatement::$stage='';if($pdo instanceof PDO&&$pdo->inTransaction()){$pdo->rollBack();}
    if($mysql&&$pdo instanceof PDO){$pdo->exec('DROP TABLE IF EXISTS sosecurity_owned_write_probe');$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_records');$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_roots');}
    $pdo=null;cleanDirectory($directory);
}
