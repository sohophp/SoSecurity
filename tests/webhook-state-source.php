<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account as A;
use SoSecurity\Webhook as W;
use SoSecurity\Support\HmacKeys;
$mysql=($argv[1]??'')==='mysql';$created=false;$pdo=null;
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned private MySQL required.');}}
$directory=privateDirectory();
try{
    mkdir($directory.'/witness',0700);
    $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/owned.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}$pdo->exec('CREATE TABLE owned(id INTEGER NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$created=true;
    $endpoint=new W\Endpoint('hook','tenant','provider','https://hooks.example/events','standard-hmac');
    $keys=new W\KeySet($endpoint,['one'=>str_repeat('a',32),'two'=>str_repeat('b',32)]);
    $seals=new HmacKeys('one',['one'=>str_repeat('c',32),'two'=>str_repeat('d',32)]);$policy=new W\ProcessingPolicy();
    $source=new A\WebhookStateSnapshot($pdo,'owned-webhook',$endpoint,$keys,$seals,$policy);
    Check::same($pdo,$source->connection());Check::same([],$source->storageDomains());Check::same(true,$source->uses($endpoint,$keys,$seals,$policy));
    Check::same(64,strlen($source->digest()));Check::same($source->digest(),$source->digest());
    $same=new A\WebhookStateSnapshot($pdo,'owned-webhook',$endpoint,new W\KeySet($endpoint,['one'=>str_repeat('a',32),'two'=>str_repeat('b',32)]),new HmacKeys('one',['two'=>str_repeat('d',32),'one'=>str_repeat('c',32)]),new W\ProcessingPolicy());
    Check::same($source->fingerprint(),$same->fingerprint());Check::same($source->digest(),$same->digest());Check::same(false,$same->uses($endpoint,$keys,$seals,$policy));
    $sql=new A\SqlStateSnapshot($pdo,'owned-sql',['owned'=>['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>10]],10000);
    $composite=new A\CompositeStateSnapshot($pdo,['sql'=>$sql,'webhook'=>$source]);
    $capture=$composite->capture(['sql'=>['item'=>['table'=>'owned','key'=>['id'=>1],'columns'=>['id']]]]);Check::same($composite->digest(),$capture->digest());Check::same(null,$capture->part('sql')->row('item'));
    $witnessKeys=new HmacKeys('witness',['witness'=>str_repeat('w',32)]);
    $makeWitness=static function($state)use($pdo,$directory,$witnessKeys){return new A\LocalStateWitness($pdo,$directory.'/witness','owned','tenant',str_repeat('e',64),$witnessKeys,$state,new A\LocalStatePersistence($directory.'/witness',10000),10000,2);};
    $witness=$makeWitness($composite);$witness->initialize($composite->digest());$boundary=new A\StateBoundary($witness,static function():bool{return true;});
    Check::same('ok',$boundary->run('owned.read',static function():string{return 'ok';}));$record=$witness->inspect(static function():bool{return true;});
    $variants=[
        [$endpoint,new W\KeySet($endpoint,['one'=>str_repeat('z',32),'two'=>str_repeat('b',32)]),$seals,$policy],
        [$endpoint,new W\KeySet($endpoint,['two'=>str_repeat('b',32),'one'=>str_repeat('a',32)]),$seals,$policy],
        [$endpoint,new W\KeySet($endpoint,['one'=>str_repeat('a',32)]),$seals,$policy],
        [$endpoint,$keys,new HmacKeys('two',['one'=>str_repeat('c',32),'two'=>str_repeat('d',32)]),$policy],
        [$endpoint,$keys,new HmacKeys('one',['one'=>str_repeat('c',32)]),$policy],
        [$endpoint,$keys,new HmacKeys('one',['one'=>str_repeat('c',32),'two'=>str_repeat('x',32)]),$policy],
        [$endpoint,$keys,$seals,new W\ProcessingPolicy(['lease_seconds'=>61])],
        [$endpoint,$keys,$seals,null],
    ];
    $changed=new W\Endpoint('hook','tenant','provider','https://hooks.example/changed','standard-hmac');$variants[]=[$changed,new W\KeySet($changed,['one'=>str_repeat('a',32),'two'=>str_repeat('b',32)]),$seals,$policy];
    foreach($variants as $v){
        $next=new A\WebhookStateSnapshot($pdo,'owned-webhook',$v[0],$v[1],$v[2],$v[3]);Check::same($source->fingerprint(),$next->fingerprint());Check::same(false,$source->digest()===$next->digest());
        $nextComposite=new A\CompositeStateSnapshot($pdo,['sql'=>$sql,'webhook'=>$next]);Check::same($composite->fingerprint(),$nextComposite->fingerprint());$nextWitness=$makeWitness($nextComposite);$nextBoundary=new A\StateBoundary($nextWitness,static function():bool{return true;});$calls=0;
        try{$nextBoundary->run('owned.changed',static function()use(&$calls):void{++$calls;});throw new LogicException('Changed key configuration accepted');}
        catch(SoSecurity\Storage\StorageException $error){Check::same('account.witness_stale',$error->reason());}
        Check::same(0,$calls);Check::same($record,$witness->inspect(static function():bool{return true;}));
    }
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($pdo,$changed,$keys,$seals):void{new A\WebhookStateSnapshot($pdo,'owned-webhook',$changed,$keys,$seals);});
    foreach([$source,$keys,$seals] as $value){ob_start();var_dump($value);$dump=ob_get_clean().var_export($value,true);foreach(['a','b','c','d'] as $byte){Check::same(false,strpos($dump,str_repeat($byte,32))!==false);}Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($value):void{serialize($value);});}
    foreach(['standard-hmac','stripe-v1','github-sha256','standard-ed25519'] as $protocol){
        if($protocol==='standard-ed25519'&&!extension_loaded('sodium')){echo 'NOT RUN Ed25519 state source: ext-sodium required',PHP_EOL;continue;}
        $ep=new W\Endpoint('hook','tenant','provider','https://hooks.example/events',$protocol,$protocol==='github-sha256'?['allow_untimed'=>true]:[]);
        $material=new W\KeySet($ep,['one'=>str_repeat('p',32)]);$profile=new A\WebhookStateSnapshot($pdo,'protocol-test',$ep,$material,$seals);
        Check::same(true,$profile->uses($ep,$material,$seals));Check::same(64,strlen($profile->digest()));Check::same(false,$source->digest()===$profile->digest());
    }
    echo 'PASS immutable Webhook state source: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').'; local fixed keys, no online authority or recovery'.PHP_EOL;
}finally{if($mysql&&$created){$pdo->exec('DROP TABLE owned');}if(is_dir($directory.'/witness')){cleanDirectory($directory.'/witness');}cleanDirectory($directory);}
