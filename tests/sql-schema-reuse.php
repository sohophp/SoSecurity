<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
$mysql=($argv[1]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned no-network MySQL required.');}
$created=[];$directory=privateDirectory();$e=(object)['pdo'=>null,'observer'=>null,'clock'=>new TestClock(),'keys'=>new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('s',32)])];
try{
    $dsn=$mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/schema.sqlite';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>2];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
    $e->pdo=new InboxTestConnection($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$e->pdo]]);
    $e->observer=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
    foreach(['sosecurity_account_records','sosecurity_account_roots'] as $table){$e->pdo->exec('DROP TABLE IF EXISTS '.$table);}
    $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-'.($mysql?'mysql':'sqlite').'.sql'));
    foreach(explode(';',$ddl) as $statement){if(trim($statement)!==''){$e->pdo->exec($statement);if(preg_match('/\ACREATE TABLE (sosecurity_account_(?:roots|records))\b/',trim($statement),$match)){$created[]=$match[1];}}}
    if(!$mysql){chmod($directory.'/schema.sqlite',0600);}

    $unit=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);$policy=new SoSecurity\Account\Policy();
    $ledger=new SoSecurity\Account\Ledger($unit,'owned-schema-reuse','tenant',str_repeat('e',64),$e->keys,$policy);$metadata=0;
    $e->pdo->beforeStatement=static function(string $sql)use(&$metadata):void{if(strpos($sql,'information_schema.COLUMNS')!==false||strpos($sql,'main.pragma_table_info')!==false){++$metadata;}};
    $unit->run(static function()use($ledger):void{$ledger->initialize();});
    Check::same($mysql?1:2,$metadata);
    $unit->run(static function()use($e,$unit,$ledger,&$metadata):void{
        $ledger->checkpoint();$before=$metadata;$ledger->checkpoint();Check::same($e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql',$metadata===$before);
        $unit->invoke(static function():bool{return true;},[],'owned.callback');$before=$metadata;$ledger->checkpoint();Check::same(true,$metadata>$before);
        $unit->query('UPDATE sosecurity_account_roots SET observed_at=observed_at WHERE namespace=:namespace',['namespace'=>hash('sha256',json_encode(['SoSecurity.Account.Ledger.1','owned-schema-reuse','tenant',str_repeat('e',64)],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES))])->closeCursor();$before=$metadata;$ledger->checkpoint();Check::same(true,$metadata>$before);
    },null,null,static function()use($ledger,&$metadata):void{$ledger->checkpoint();$before=$metadata;$ledger->checkpoint();Check::same(true,$metadata>$before);});
    $before=$metadata;$unit->run(static function()use($ledger):void{$ledger->checkpoint();});Check::same(true,$metadata>$before);
    // A callback can add a trigger transactionally on SQLite, or cause an implicit commit on MySQL.
    // Neither case may let a previous schema check authorize a later ledger read.
    $name='owned_schema_reuse_trigger';$sql=$e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql'
        ?'CREATE TRIGGER '.$name.' BEFORE INSERT ON sosecurity_account_records FOR EACH ROW SET NEW.revision=NEW.revision'
        :'CREATE TRIGGER '.$name.' BEFORE INSERT ON sosecurity_account_records BEGIN SELECT 1; END';
    $error=null;
    try{$unit->run(static function()use($e,$unit,$ledger,$sql):void{$ledger->checkpoint();$unit->invoke(static function()use($e,$sql):bool{$e->pdo->exec($sql);return true;},[],'owned.ddl');$ledger->checkpoint();});}catch(Throwable $caught){$error=$caught;}
    Check::same(true,($error instanceof SoSecurity\Exception\ConfigurationException||$error instanceof SoSecurity\Storage\StorageException));Check::same(in_array($error->reason(),['configuration.sql_schema','configuration.sql_transaction_lost','sql.cleanup'],true),true);
    $e->observer->exec('DROP TRIGGER IF EXISTS '.$name);$e->pdo->beforeStatement=null;
}finally{$e->observer=null;if($mysql&&$e->pdo instanceof PDO){$e->pdo->beforeStatement=null;foreach(array_reverse($created) as $table){$e->pdo->exec('DROP TABLE IF EXISTS '.$table);}}$e->pdo=null;gc_collect_cycles();cleanDirectory($directory);}
echo 'PASS SQL schema reuse boundaries: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; same-batch MySQL reuse only, callback/transaction/post-commit revalidation and actual DDL refusal',PHP_EOL;
