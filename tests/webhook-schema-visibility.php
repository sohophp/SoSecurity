<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned private MySQL required');}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
// Only mysql_check.py's disposable server and synthetic account are modified.
// The controller uses the installed MySQL client; old PHP clients do not support root's
// caching_sha2_password. Product calls below still use each selected PHP's real PDO driver.
$control=static function(string $sql)use($socket):void{
    $process=proc_open('mysql --no-defaults --protocol=SOCKET --socket='.escapeshellarg($socket).' --user=root --database=sosecurity_test --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if(!is_resource($process)){throw new RuntimeException('Owned controller unavailable');}
    $input=$sql.';'.PHP_EOL;$written=fwrite($pipes[0],$input);fclose($pipes[0]);
    stream_get_contents($pipes[1],8192);fclose($pipes[1]);stream_get_contents($pipes[2],8192);fclose($pipes[2]);$exit=proc_close($process);
    if($written!==strlen($input)||$exit!==0){throw new RuntimeException('Owned controller command failed');}
};
foreach(['missing','schema','table','global','revoked','trigger','global-restricted','role-only','schema-race','table-race'] as $mode){
    $control("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'sosecurity_reader'@'localhost'");
    $control("GRANT SELECT,INSERT,UPDATE,DELETE ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");
    $e=new InboxEnvironment(true);
    try{
        $e->pdo->exec('CREATE TABLE webhook_schema_effects(value INTEGER NOT NULL) ENGINE=InnoDB');
        if(in_array($mode,['schema','revoked','trigger','schema-race'],true)){$control("GRANT TRIGGER ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");}
        elseif(in_array($mode,['table','table-race'],true)){$control("GRANT TRIGGER ON sosecurity_test.sosecurity_webhook_inbox TO 'sosecurity_reader'@'localhost'");}
        elseif(in_array($mode,['global','global-restricted'],true)){$control("GRANT TRIGGER ON *.* TO 'sosecurity_reader'@'localhost'");if($mode==='global-restricted'){$control('SET GLOBAL partial_revokes=ON');}}
        elseif($mode==='role-only'){$control("CREATE ROLE 'owned_webhook_role'");$control("GRANT TRIGGER ON sosecurity_test.* TO 'owned_webhook_role'");$control("GRANT 'owned_webhook_role' TO 'sosecurity_reader'@'localhost'");}
        if(in_array($mode,['missing','revoked','trigger','schema-race','table-race'],true)){$e->pdo->exec('CREATE TRIGGER owned_hidden_trigger AFTER INSERT ON sosecurity_webhook_inbox FOR EACH ROW INSERT INTO webhook_schema_effects VALUES(1)');}
        $reader=new InboxTestConnection($dsn,'sosecurity_reader','integration-read-only',$options);
        $reader->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$reader]]);$revoked=false;
        if(in_array($mode,['schema-race','table-race'],true)){$reader->afterStatement=static function(string $sql)use($control,$mode,&$revoked):void{
            if(!$revoked&&strpos($sql,'information_schema.SCHEMA_PRIVILEGES')!==false){$revoked=true;$control("REVOKE TRIGGER ON sosecurity_test.".($mode==='table-race'?'sosecurity_webhook_inbox':'*')." FROM 'sosecurity_reader'@'localhost'");}
        };}
        if($mode==='role-only'){$reader->exec('SET ROLE ALL');}
        $service=new SoSecurity\Webhook\SqlInbox($reader,'inbox-test-site',$e->verifier,$e->seals,static function():bool{return true;},$e->clock);
        if($mode==='revoked'){$control("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'");}
        if(in_array($mode,['missing','revoked','trigger','global-restricted','role-only','schema-race','table-race'],true)){
            try{$service->accept($e->request(),$e->mapper());throw new RuntimeException('Unproven/invalid schema accepted');}
            catch(SoSecurity\Exception\ConfigurationException $error){Check::same('configuration.webhook_inbox_schema',$error->reason());}
            Check::same(0,$e->count());
        }else{Check::same(false,$service->accept($e->request(),$e->mapper())->duplicate());Check::same(1,$e->count());}
        Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_schema_effects')->fetchColumn());Check::same(false,$reader->inTransaction());
        if(in_array($mode,['schema-race','table-race'],true)){Check::same(true,$revoked);}
        echo 'CASE visibility '.$mode.' PASS'.PHP_EOL;
    }finally{$reader=null;$e->close();$control('DROP TABLE IF EXISTS webhook_schema_effects');if($mode==='global-restricted'){$control('SET GLOBAL partial_revokes=OFF');}if($mode==='role-only'){$control("DROP ROLE 'owned_webhook_role'");}}
}
echo 'PASS Webhook metadata visibility '.Check::$assertions.' assertions MySQL PHP '.PHP_VERSION.PHP_EOL;
