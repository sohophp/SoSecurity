<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Account as A;
use SoSecurity\Support\SqlStateAccess;
$mysql=($argv[1]??'')==='mysql';
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required.');}}
inboxCase($mysql,static function(InboxEnvironment $e)use($mysql):void{
    $directory=privateDirectory();$installed=false;$effectsCreated=false;
    try{
        $ddl=file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($mysql?'mysql':'sqlite').'.sql');
        foreach(explode(';',$ddl) as $statement){if(trim($statement)!==''){$e->pdo->exec($statement);}}$installed=true;
        $e->pdo->exec('CREATE TABLE webhook_owned_effects(receipt_id VARCHAR(32) NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$effectsCreated=true;
        $calls=0;$guard=static function()use(&$calls):bool{++$calls;return true;};
        $mapper=static function(string $body):SoSecurity\Webhook\Message{$v=json_decode($body,true);return new SoSecurity\Webhook\Message($v['id'],$v['type'],$v['resource'],['version'=>$v['version']]);};
        $build=static function()use($e,$mapper,$guard):SoSecurity\Webhook\SqlProcessor{return new SoSecurity\Webhook\SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,$mapper,$guard,$guard,null,$e->clock,$guard);};
        $old=$build();
        $inbox=['endpoint_key'=>'digest','event_key'=>'digest','receipt_id'=>'bytes:32','event_id'=>'bytes:256','event_type'=>'bytes:128','resource_id'=>'bytes:256','descriptor'=>'digest','body_digest'=>'digest','payload'=>'blob:1048576','created_at'=>'int','seen_at'=>'int','source_key'=>'bytes:64','source_time'=>'nullable_int','seal_key'=>'bytes:64','seal'=>'digest'];
        $processing=['endpoint_key'=>'digest','receipt_id'=>'bytes:32','event_key'=>'digest','body_digest'=>'digest','descriptor'=>'digest','policy'=>'digest','status'=>'bytes:16','attempt'=>'int','total_attempts'=>'int','manual_retries'=>'int','revision'=>'int','due_at'=>'int','lease_until'=>'int','claim_digest'=>'bytes:64','worker_digest'=>'bytes:64','error_code'=>'bytes:64','created_at'=>'int','updated_at'=>'int','seal_key'=>'bytes:64','seal'=>'digest'];
        $effects=['columns'=>['receipt_id'=>'bytes:32'],'primary'=>['receipt_id'],'where'=>[],'maximum_rows'=>100];if(!$mysql){$effects['sqlite_declarations']=['receipt_id'=>'VARCHAR(32)'];}
        $source=new A\SqlStateSnapshot($e->pdo,'owned-webhook-sql',[
            'webhook_owned_effects'=>$effects,
            'sosecurity_webhook_inbox'=>['columns'=>$inbox,'primary'=>['endpoint_key','event_key'],'where'=>[],'maximum_rows'=>100],
            'sosecurity_webhook_processing'=>['columns'=>$processing,'primary'=>['endpoint_key','receipt_id'],'where'=>[],'maximum_rows'=>100],
        ],30000);
        $witness=new A\LocalStateWitness($e->pdo,$directory,'inbox-test-site','tenant',str_repeat('e',64),$e->seals,$source,new A\LocalStatePersistence($directory,30000),30000,2);
        $witness->initialize($source->digest());$boundary=new A\StateBoundary($witness,static function():bool{return true;});
        // Exercise the actual internal PDO registration used by protected connection declarations.
        // This is not a substitute for a public Webhook coverage/key-policy declaration.
        SqlStateAccess::bind($e->pdo,SqlStateAccess::context('inbox-test-site','tenant',str_repeat('e',64)),hash('sha256','owned-webhook-connection'),$boundary->sqlGuard($e->pdo));
        $new=$build();$receipt=str_repeat('a',32);$token='wc1.'.$receipt.'.1.'.str_repeat('b',64);
        $refuse=static function(callable $call)use($e,&$calls):void{
            $queries=$e->pdo->queries;$before=[$e->keyCalls,$e->mapCalls,$e->associationCalls,$calls];
            try{$call();throw new LogicException('Webhook entered a protected PDO outside its boundary.');}
            catch(SoSecurity\Storage\StorageException $error){Check::same('account.state_required',$error->reason());}
            Check::same($queries,$e->pdo->queries);Check::same($before,[$e->keyCalls,$e->mapCalls,$e->associationCalls,$calls]);
        };
        $refuse(static function()use($e):void{$e->receive();});
        foreach([$old,$new] as $service){
            $refuse(static function()use($service,$receipt):void{$service->claim($receipt,'worker');});
            $refuse(static function()use($service,$token):void{$service->execute('worker',$token,static function():bool{throw new LogicException('Handler must not execute');});});
            $refuse(static function()use($service,$token):void{$service->fail('worker',$token,'owned.failure');});
            $refuse(static function()use($service,$receipt):void{$service->retry($receipt,'operator');});
            $refuse(static function()use($service,$receipt):void{$service->status($receipt,'worker');});
            $refuse(static function()use($service):void{$service->pending('worker');});
        }
        $received=$boundary->run('webhook.receive',static function()use($e){return $e->receive();});Check::same(true,$received instanceof SoSecurity\Webhook\Receipt);
        $id=$received->id();$claim=$boundary->run('webhook.claim',static function()use($new,$id){return $new->claim($id,'worker');});Check::same(true,$claim instanceof SoSecurity\Webhook\ProcessingClaim);
        $done=$boundary->run('webhook.execute',static function()use($new,$claim,$id){return $new->execute('worker',$claim->token(),static function(PDO $pdo)use($id):bool{$q=$pdo->prepare('INSERT INTO webhook_owned_effects VALUES(?)');$q->execute([$id]);return true;});});Check::same('succeeded',$done->status());
        Check::same($id,$e->pdo->query('SELECT receipt_id FROM webhook_owned_effects')->fetchColumn());
        Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);
        Check::same('current',$witness->inspect(static function():bool{return true;})['status']);
        $e->pdo->exec('DELETE FROM webhook_owned_effects');$before=$calls;
        try{$boundary->run('webhook.stale',static function()use($new,$id){return $new->status($id,'worker');});throw new LogicException('Changed covered SQL accepted');}
        catch(SoSecurity\Storage\StorageException $error){Check::same('account.witness_stale',$error->reason());}Check::same($before,$calls);
    }finally{if($mysql&&$effectsCreated){$e->pdo->exec('DROP TABLE webhook_owned_effects');}if($mysql&&$installed){$e->pdo->exec('DROP TABLE sosecurity_webhook_processing');}cleanDirectory($directory);}
});
echo 'PASS webhook protected PDO access: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;
