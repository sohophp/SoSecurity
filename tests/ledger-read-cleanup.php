<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\Ledger;
use SoSecurity\Account\Policy;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
final class LedgerCleanupStatement extends PDOStatement
{
    protected function __construct(){}
    public static $target='';public static $fault='';public static $hits=0;
    private function target():bool
    {
        $sql=$this->queryString;
        if(strpos($sql,'SELECT ')!==0){return false;}
        $root=strpos($sql,'FROM main.sosecurity_account_roots WHERE')!==false||strpos($sql,'FROM sosecurity_account_roots WHERE')!==false;
        $records=strpos($sql,'FROM main.sosecurity_account_records WHERE')!==false||strpos($sql,'FROM sosecurity_account_records WHERE')!==false;
        if(self::$target==='root'){return $root;}
        if(!$records){return false;}
        if(self::$target==='empty'){return strpos($sql,'SELECT 1 FROM ')===0;}
        if(self::$target==='body'){return strpos($sql,'SELECT payload,')===0;}
        if(self::$target==='latest'){return strpos($sql,' AND owner=:owner AND kind=:kind ')!==false;}
        if(self::$target==='record'){return strpos($sql,' AND record_id=:id')!==false&&strpos($sql,'SELECT payload,')!==0;}
        if(self::$target==='page'){return strpos($sql,' LIMIT 3')!==false;}
        return self::$target==='history'&&strpos($sql,' LIMIT 64')!==false;
    }
    public function closeCursor():bool
    {
        if($this->target()){Check::same(1,preg_match('/ LIMIT (?:1|3|64)(?: FOR UPDATE)?\z/D',$this->queryString));++self::$hits;if(self::$fault==='throw'){throw new RuntimeException('owned-private-ledger-close');}if(self::$fault==='false'){return false;}}
        return parent::closeCursor();
    }
}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use the owned disposable SQL test server.');}
$directory=privateDirectory();$pdo=null;$cases=0;
try{
    $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_STATEMENT_CLASS=>[LedgerCleanupStatement::class]];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
    $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/ledger.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
    if($mysql){$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_records');$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_roots');}
    else{$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
    $pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/account-'.($mysql?'mysql':'sqlite').'.sql'));
    $clock=new TestClock();$keys=new HmacKeys('one',['one'=>str_repeat('k',32)]);$policy=new Policy();$id=str_repeat('a',64);$owner=str_repeat('b',64);
    foreach(['root','history','body','record','latest','page','empty'] as $target){foreach(['false','throw'] as $fault){
        LedgerCleanupStatement::$target='';LedgerCleanupStatement::$fault='';LedgerCleanupStatement::$hits=0;
        $pdo->exec('DELETE FROM sosecurity_account_records');$pdo->exec('DELETE FROM sosecurity_account_roots');
        $unit=new SqlTransaction($pdo,$clock,10000);$ledger=new Ledger($unit,'site','tenant',str_repeat('e',64),$keys,$policy);
        if($target!=='empty'){$unit->run(static function()use($ledger,$id,$owner):void{$ledger->initialize();$ledger->put($id,$owner,'notice','owned-body',100900);});}
        $before=$pdo->query('SELECT revision,history_digest FROM sosecurity_account_roots')->fetchAll(PDO::FETCH_ASSOC);
        $caught=false;$continued=false;$returned=false;$outer=null;
        try{$unit->run(static function()use($unit,$ledger,$target,$fault,$id,$owner,&$caught,&$continued,&$returned):void{
            LedgerCleanupStatement::$target=$target;LedgerCleanupStatement::$fault=$fault;
            try{
                if($target==='body'){$ledger->read($id);}
                elseif($target==='record'){$ledger->put($id,$owner,'notice','replacement',100900,1);}
                elseif($target==='latest'){$ledger->latest($owner,'notice');}
                elseif($target==='page'){$ledger->page(3);}
                elseif($target==='empty'){$ledger->initialize();}
                else{$ledger->checkpoint();}
                $returned=true;
            }catch(SecurityException $error){
                Check::same('sql.cleanup',$error->reason());Check::same(false,strpos((string)$error,'owned-private-ledger-close')!==false);Check::same(null,$error->getPrevious());$caught=true;
            }
            try{$unit->query('SELECT 1');$continued=true;}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}
            LedgerCleanupStatement::$target='';
        });}catch(SecurityException $error){$outer=$error->reason();}
        finally{LedgerCleanupStatement::$target='';}
        Check::same(true,$caught);Check::same(false,$returned);Check::same(false,$continued);Check::same('sql.cleanup',$outer);Check::same(1,LedgerCleanupStatement::$hits);
        Check::same($before,$pdo->query('SELECT revision,history_digest FROM sosecurity_account_roots')->fetchAll(PDO::FETCH_ASSOC));Check::same(false,$pdo->inTransaction());++$cases;
    }}
    echo 'PASS ledger read cleanup '.($mysql?'mysql':'sqlite').' '.$cases.' cases '.Check::$assertions.' assertions'.PHP_EOL;
}finally{
    LedgerCleanupStatement::$target='';if($pdo instanceof PDO&&$pdo->inTransaction()){$pdo->rollBack();}
    if($mysql&&$pdo instanceof PDO){$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_records');$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_roots');}
    $pdo=null;cleanDirectory($directory);
}
