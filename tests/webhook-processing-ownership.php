<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';

$mysql=($argv[1] ?? '')==='mysql';
$mode=$argv[2] ?? 'processing';
$intake=$mode==='inbox';
$implicit=($argv[3] ?? '')==='implicit';
$errorMode=$argv[4] ?? 'exception';
$e=new InboxEnvironment($mysql);$fixtureConnection=$e->pdo;
try {
    $receipt=$e->receive();
    $processor=new SoSecurity\Webhook\SqlProcessor(
        $e->pdo,'inbox-test-site',$e->endpoint,$e->seals,
        static function(){throw new RuntimeException('Must not reach mapper inside caller transaction.');},
        static function(){return true;},static function(){return true;},null,$e->clock
    );
    // Fault-hook PDO intentionally throws on false exec; use native PDO to test its actual silent/warning contract.
    if($mysql&&$errorMode!=='exception'){$e->pdo=new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);}
    $store=null;
    if($mysql&&in_array($mode,['store','prune','install'],true)){SoSecurity\Storage\MySqlStore::install($e->pdo);$store=new SoSecurity\Storage\MySqlStore($e->pdo,'ownership-test',$e->clock);}
    if($errorMode==='silent'){$e->pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_SILENT);}elseif($errorMode==='warning'){$e->pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_WARNING);}
    $observer=$mysql
        ?new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only')
        :new PDO('sqlite:'.$e->database);
    $sql="SELECT enabled FROM webhook_test_resources WHERE tenant='tenant' AND id='b'";
    if($mysql&&$implicit){$e->pdo->exec('SET autocommit=0');}else{$e->pdo->exec($mysql?'START TRANSACTION':'BEGIN IMMEDIATE');}
    $e->pdo->exec("UPDATE webhook_test_resources SET enabled=0 WHERE tenant='tenant' AND id='b'");
    Check::same(0,(int)$e->pdo->query($sql)->fetchColumn());
    Check::same(1,(int)$observer->query($sql)->fetchColumn());
    $denied=false;
    try {if($intake){$e->receive();}elseif($mode==='store'){$store->transact('test',static function(){throw new RuntimeException('Must not run inside caller transaction.');});}elseif($mode==='prune'){$store->prune(1);}elseif($mode==='install'){SoSecurity\Storage\MySqlStore::install($e->pdo);}else{$processor->claim($receipt->id(),'worker');}}
    catch (SoSecurity\Exception\ConfigurationException $error) {$denied=true;}
    catch (SoSecurity\Storage\StorageException $error) {$denied=true;}
    Check::same(true,$denied);
    Check::same(0,(int)$e->pdo->query($sql)->fetchColumn());
    Check::same(1,(int)$observer->query($sql)->fetchColumn());
    $e->pdo->exec('ROLLBACK');
    Check::same(1,(int)$e->pdo->query($sql)->fetchColumn());
    Check::same(1,(int)$observer->query($sql)->fetchColumn());
    if($mysql&&$implicit){$e->pdo->exec('SET autocommit=1');}
    if($mode==='inbox'){Check::same(true,$e->receive()->duplicate());}
    elseif($mode==='store'){Check::same(true,$store->transact('positive',static function(){return new SoSecurity\Storage\Change([],0,true);}));}
    elseif($mode==='prune'){Check::same(0,$store->prune(1));}
    elseif($mode==='install'){SoSecurity\Storage\MySqlStore::install($e->pdo);Check::same(1,(int)$e->pdo->query('SELECT @@SESSION.autocommit')->fetchColumn());}
    if($store!==null){$cleanup=$e->pdo->prepare('DELETE FROM sosecurity_state WHERE namespace_hash=:namespace');$cleanup->execute(['namespace'=>hash('sha256','ownership-test')]);}
    $observer=null;
} finally {
    // This fixture owns both disposable connections; release its locks even when an assertion fails.
    if($mysql){try{$e->pdo->exec('ROLLBACK');}catch(Throwable $ignored){}}
    $e->pdo=$fixtureConnection;$e->close();
}
echo 'PASS '.$mode.' caller transaction: '.Check::$assertions.' assertions; actual '.($mysql?'MySQL':'SQLite').' '.($implicit?'autocommit=0':'SQL BEGIN').', cross-connection uncommitted visibility, refusal and host rollback on PHP '.PHP_VERSION."\n";
