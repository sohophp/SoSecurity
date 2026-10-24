<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
final class PrivateSchemaStatement extends PDOStatement
{
    protected function __construct(){}
    public static $stage='';public static $fault='';public static $closed=0;
    private function target():bool
    {
        $sql=$this->queryString;
        if(self::$stage==='database-list'){return $sql==='PRAGMA database_list';}
        if(self::$stage==='journal'){return $sql==='PRAGMA main.journal_mode';}
        if(self::$stage==='synchronous'){return $sql==='PRAGMA main.synchronous';}
        if(self::$stage==='resolution'){return strpos($sql,'SELECT 1 FROM main.sosecurity_cursor_')===0||strpos($sql,'SELECT 1 FROM `sosecurity_cursor_')===0;}
        if(self::$stage==='foreign-shadow'){return strpos($sql,"name COLLATE NOCASE='pragma_foreign_key_list'")!==false;}
        if(self::$stage==='foreign'){return strpos($sql,'JOIN main.pragma_foreign_key_list(')!==false;}
        if(self::$stage==='shadow'){return strpos($sql,"name COLLATE NOCASE IN ('pragma_table_info'")!==false;}
        if(self::$stage==='columns'){return strpos($sql,'FROM main.pragma_table_info(')!==false;}
        if(self::$stage==='indexes'){return strpos($sql,'FROM main.pragma_index_list(')!==false;}
        if(self::$stage==='index-columns'){return strpos($sql,'FROM main.pragma_index_info(')!==false;}
        return strpos($sql,"WHERE type='trigger' AND tbl_name COLLATE NOCASE=")!==false;
    }
    public function fetchAll($mode=0,...$arguments):array
    {
        if($this->target()&&self::$fault==='fetch-close-false'){throw new RuntimeException('PRIVATE-SCHEMA-FETCH');}return parent::fetchAll(...func_get_args());
    }
    #[\ReturnTypeWillChange]
    public function fetchColumn($column=0)
    {
        if($this->target()&&self::$fault==='fetch-close-false'){throw new RuntimeException('PRIVATE-SCHEMA-FETCH');}return parent::fetchColumn($column);
    }
    public function closeCursor():bool
    {
        $result=parent::closeCursor();if(!$this->target()||self::$fault===''){return $result;}++self::$closed;
        if(self::$fault==='close-throw'){throw new RuntimeException('PRIVATE-SCHEMA-CLOSE');}return false;
    }
}
$mysql=($argv[1]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
$directory=$mysql?null:privateDirectory();$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
$pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/schema.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);$created=[];$failures=[];$cases=0;$guardCases=0;
try{
    foreach(['a','b'] as $side){$table='sosecurity_cursor_'.$side;$pdo->exec('CREATE TABLE '.$table.'(id '.($mysql?'BIGINT UNSIGNED':'INTEGER').' NOT NULL PRIMARY KEY,value '.($mysql?'BIGINT UNSIGNED':'INTEGER').' NOT NULL)'.($mysql?' ENGINE=InnoDB':''));$created[]=$table;$pdo->exec('CREATE INDEX cursor_'.$side.'_value ON '.$table.'(value)');$pdo->exec('INSERT INTO '.$table.' VALUES(7,9)');}
    $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PrivateSchemaStatement::class,[]]);
    $invalid=$mysql?[['PRAGMA database_list',[]],['PRAGMA main.journal_mode',[]],['PRAGMA main.synchronous',[]]]:[['PRAGMA main.synchronous=OFF',[]],['PRAGMA main.journal_mode=OFF',[]],['PRAGMA database_list; DROP TABLE sosecurity_cursor_a',[]],['PRAGMA database_list ',[]],['pragma database_list',[]],['PRAGMA user_version',[]],['PRAGMA busy_timeout',[]],['PRAGMA database_list',['unused'=>1]]];
    foreach($invalid as $attempt){
        ++$guardCases;$unit=new SqlTransaction($pdo,new TestClock(),10000);$error=null;
        try{$unit->run(static function()use($unit,$attempt):void{$unit->metadataRows($attempt[0],$attempt[1]);});}catch(SoSecurity\Exception\ConfigurationException $caught){$error=$caught;}
        Check::same(true,$error!==null);Check::same('configuration.sql_schema',$error->reason());Check::same(false,$pdo->inTransaction());
    }
    foreach($mysql?[false,true]:[false] as $protected){
        if($protected){SoSecurity\Support\SqlStateAccess::bind($pdo,str_repeat('c',64),str_repeat('d',64),static function():void{});}
        foreach(['table','tables'] as $method){foreach($mysql?['resolution']:['database-list','journal','synchronous','resolution','foreign-shadow','foreign','shadow','columns','indexes','index-columns','trigger'] as $stage){foreach(['normal','close-false','close-throw','fetch-close-false'] as $fault){
            ++$cases;$unit=new SqlTransaction($pdo,new TestClock(),10000);$returned=false;$continued=false;$inner=null;$outer=null;
            PrivateSchemaStatement::$stage=$stage;PrivateSchemaStatement::$fault=$fault==='normal'?'':$fault;PrivateSchemaStatement::$closed=0;
            try{$unit->run(static function()use($unit,$method,&$returned,&$continued,&$inner):void{
                try{SqlSchema::durable($unit);$unit->verifySchema('owned-private-cursor',static function()use($unit,$method):void{
                    $tables=[];foreach(['a','b'] as $side){$tables['sosecurity_cursor_'.$side]=['types'=>['id'=>'int','value'=>'int'],'primary'=>['id'],'indexes'=>['cursor_'.$side.'_value'=>['unique'=>false,'columns'=>['value']]]];}
                    if($method==='table'){$s=$tables['sosecurity_cursor_a'];SqlSchema::table($unit,'sosecurity_cursor_a',$s['types'],$s['primary'],$s['indexes']);}else{SqlSchema::tables($unit,$tables);}
                });$returned=true;}catch(Throwable $error){$inner=$error instanceof SecurityException?$error->reason():'other';}
                try{$unit->query('SELECT 1')->closeCursor();$continued=true;}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}
            });}catch(Throwable $error){$outer=$error instanceof SecurityException?$error->reason():'other';foreach([(string)$error,var_export($error,true),print_r($error,true),json_encode($error)] as $dump){Check::same(false,strpos($dump,'PRIVATE-SCHEMA-')!==false);}}
            $closes=PrivateSchemaStatement::$closed;PrivateSchemaStatement::$fault='';
            try{
                Check::same($fault==='normal',$returned);Check::same($fault==='normal',$continued);Check::same($fault==='normal'?null:'sql.cleanup',$inner);Check::same($fault==='normal'?null:'sql.cleanup',$outer);
                if($fault!=='normal'){Check::same(1,$closes);}Check::same(false,$pdo->inTransaction());Check::same([['7','9']],array_map(static function(array $row):array{return array_map('strval',$row);},$pdo->query('SELECT id,value FROM sosecurity_cursor_a')->fetchAll(PDO::FETCH_NUM)));
                echo 'PASS private schema '.$method.' '.$stage.' '.$fault.' protected='.($protected?'yes':'no').' '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION.PHP_EOL;
            }catch(Throwable $error){$failures[]=$method.'/'.$stage.'/'.$fault.'/'.($protected?'protected':'raw');echo 'FAIL private schema '.end($failures).' '.$error->getMessage().PHP_EOL;}
        }}}
    }
}finally{PrivateSchemaStatement::$fault='';if($pdo->inTransaction()){$pdo->rollBack();}foreach(array_reverse($created) as $table){$pdo->exec('DROP TABLE '.$table);}$pdo=null;if($directory!==null){cleanDirectory($directory);}}
if($failures){throw new RuntimeException(count($failures).' private schema cases failed');}echo 'PASS private schema complete '.($cases+$guardCases).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
