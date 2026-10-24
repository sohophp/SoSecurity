<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
ini_set('zend.exception_ignore_args','0');
use SoSecurity\Account\SqlStateSnapshot;
use SoSecurity\Exception\SecurityException;

final class SnapshotStreamStatement extends PDOStatement
{
    protected function __construct(){}
    public static $stage='';
    public static $fault='';
    public static $closed=0;
    private function target():bool
    {
        $sql=$this->queryString;
        if(self::$stage==='alias'){return strpos($sql,"SELECT 1 FROM main.sqlite_master WHERE name COLLATE NOCASE='pragma_table_info'")===0;}
        if(self::$stage==='columns'){return strpos($sql,'FROM main.pragma_table_info(')!==false;}
        if(self::$stage==='objects'){return strpos($sql,"SELECT 0 AS scope_order,'main' AS schema_scope")===0;}
        return strpos($sql,'__sw_valid')!==false;
    }
    #[\ReturnTypeWillChange]
    public function fetch($mode=0,$orientation=PDO::FETCH_ORI_NEXT,$offset=0)
    {
        if($this->target()&&strpos(self::$fault,'fetch')===0){throw new RuntimeException('PRIVATE-SNAPSHOT-FETCH');}
        $row=parent::fetch(...func_get_args());
        if($this->target()&&strpos(self::$fault,'invalid')===0&&is_array($row)){
            if(self::$stage==='columns'){$row['storage_type']='PRIVATE-INVALID';}
            elseif(self::$stage==='objects'){$row['definition_kind']=2;}
            else{$row['__sw_valid']=0;}
        }
        return $row;
    }
    #[\ReturnTypeWillChange]
    public function fetchColumn($column=0)
    {
        if($this->target()&&strpos(self::$fault,'fetch')===0){throw new RuntimeException('PRIVATE-SNAPSHOT-FETCH');}
        if($this->target()&&strpos(self::$fault,'invalid')===0){return 1;}
        return parent::fetchColumn($column);
    }
    public function closeCursor():bool
    {
        $result=parent::closeCursor();
        if(!$this->target()||self::$fault===''){return $result;}
        ++self::$closed;
        if(strpos(self::$fault,'throw')!==false){throw new RuntimeException('PRIVATE-SNAPSHOT-CLOSE');}
        return strpos(self::$fault,'false')!==false?false:$result;
    }
}
$mysql=($argv[1]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
$directory=$mysql?null:privateDirectory();
$pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/snapshot.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
$created=false;$failures=[];$cases=0;
try{
    $pdo->exec($mysql?'CREATE TABLE snapshot_cursor_owned(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB':'CREATE TABLE snapshot_cursor_owned(id INTEGER NOT NULL PRIMARY KEY)');$created=true;
    $pdo->exec('INSERT INTO snapshot_cursor_owned VALUES(7)');
    $source=new SqlStateSnapshot($pdo,'owned-stream-cleanup',['snapshot_cursor_owned'=>['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2]],10000);
    $expected=$source->digest();$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[SnapshotStreamStatement::class,[]]);
    foreach($mysql?['rows']:['alias','columns','objects','rows'] as $stage){
        foreach(['digest','capture'] as $operation){foreach(['normal','close-false','close-throw','fetch','fetch-close-false','fetch-close-throw','invalid','invalid-close-false','invalid-close-throw'] as $fault){
            ++$cases;SnapshotStreamStatement::$stage=$stage;SnapshotStreamStatement::$fault=$fault==='normal'?'':$fault;SnapshotStreamStatement::$closed=0;
            $result=null;$error=null;
            try{if($operation==='capture'){$capture=$source->capture(['selected'=>['table'=>'snapshot_cursor_owned','key'=>['id'=>7],'columns'=>['id']]]);Check::same(['id'=>7],$capture->row('selected'));$result=$capture->digest();}else{$result=$source->digest();}}catch(Throwable $caught){$error=$caught;}
            $closes=SnapshotStreamStatement::$closed;
            SnapshotStreamStatement::$fault='';
            try{
                if($fault==='normal'){Check::same(null,$error);Check::same($expected,$result);}
                else{
                    Check::same(null,$result);Check::same(true,$error instanceof SecurityException);
                    Check::same(strpos($fault,'close')!==false?'sql.cleanup':($fault==='invalid'?'account.snapshot_corrupt':'sql.unavailable'),$error->reason());
                    Check::same(null,$error->getPrevious());foreach([(string)$error,var_export($error,true),print_r($error,true),json_encode($error)] as $dump){Check::same(false,strpos($dump,'PRIVATE-SNAPSHOT-')!==false);}
                    Check::same(1,$closes);
                }
                Check::same(false,$pdo->inTransaction());
                Check::same(7,(int)$pdo->query('SELECT id FROM snapshot_cursor_owned')->fetchColumn());
                Check::same($expected,$source->digest());
                echo 'PASS snapshot stream '.$operation.' '.$stage.' '.$fault.' '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION.PHP_EOL;
            }catch(Throwable $assertion){$failures[]=$operation.'/'.$stage.'/'.$fault.': '.$assertion->getMessage();echo 'FAIL '.end($failures).PHP_EOL;}
        }}
    }
}finally{SnapshotStreamStatement::$fault='';if($pdo->inTransaction()){$pdo->rollBack();}if($created){$pdo->exec('DROP TABLE snapshot_cursor_owned');}$pdo=null;if($directory!==null){cleanDirectory($directory);}}
if($failures){throw new RuntimeException(count($failures).' snapshot stream cases failed');}
echo 'PASS snapshot stream complete '.$cases.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
