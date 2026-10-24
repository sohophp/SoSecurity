<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
$mysql=($argv[1]??'')==='mysql';
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned private MySQL required.');}}
foreach(['first-key','second-key','initial','return-error','return-expiry','valid','commit'] as $mode){
    inboxCase($mysql,static function(InboxEnvironment $e)use($mode):void{
        $allowed=$mode!=='initial';$guards=0;$lookups=0;$inserted=false;
        if($mode==='commit'){$e->pdo->afterStatement=static function(string $sql)use(&$inserted):void{if(strpos($sql,'INSERT')===0&&strpos($sql,'sosecurity_webhook_inbox')!==false){$inserted=true;}};}
        $keys=static function()use($e,$mode,&$allowed,&$lookups){++$lookups;if(($mode==='first-key'&&$lookups===1)||($mode==='second-key'&&$lookups===2)||($mode==='commit'&&$lookups===6)){$allowed=false;}return $e->keys;};
        $guard=static function()use($e,$mode,&$allowed,&$guards):bool{++$guards;if($guards===2){if($mode==='return-error'){throw new RuntimeException('SYNTHETIC-PRIVATE-REQUEST');}if($mode==='return-expiry'){$e->clock->time+=1000;}}return $allowed;};
        $verifier=new SoSecurity\Webhook\Verifier($e->endpoint,$keys,$guard,$e->clock);
        if(in_array($mode,['first-key','second-key','initial','commit'],true)){
            try{
                if($mode==='commit'){$inbox=new SoSecurity\Webhook\SqlInbox($e->pdo,'inbox-test',$verifier,$e->seals,static function():bool{return true;},$e->clock);$inbox->accept($e->request(),$e->mapper());}
                else{$verifier->verify($e->request());}
                throw new LogicException('Withdrawn request authority accepted: '.$mode);
            }catch(SoSecurity\Exception\SecurityException $error){Check::same('webhook.denied',$error->reason());}
            Check::same($mode==='initial'?1:($mode==='commit'?6:2),$guards);Check::same($mode==='initial'?0:($mode==='commit'?6:2),$lookups);
        }elseif($mode==='return-error'){
            try{$verifier->verify($e->request());throw new LogicException('Expected sanitized final request failure');}
            catch(SoSecurity\Exception\DependencyException $error){Check::same('webhook.request_unavailable',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'SYNTHETIC')!==false);}
        }else{
            $proof=$verifier->verify($e->request());Check::same($mode==='valid',$proof instanceof SoSecurity\Webhook\VerifiedWebhook);Check::same(2,$guards);
        }
        if($mode==='commit'){Check::same(true,$inserted);}
        Check::same(0,$e->count());Check::same(false,$e->pdo->inTransaction());
    });
}
foreach(['guard','keys'] as $mode){
    inboxCase($mysql,static function(InboxEnvironment $e)use($mode):void{
        $original=$e->endpoint;$replacement=new SoSecurity\Webhook\Endpoint('other','other','other','https://other.example/events','standard-hmac');
        $provider=static function(&$endpoint)use($e,$replacement,$mode){if($mode==='keys'){$endpoint=$replacement;}return $e->keys;};
        $guard=static function(&$endpoint,&$request)use($replacement,$mode):bool{if($mode==='guard'){$endpoint=$replacement;$request=new SoSecurity\Webhook\Request('POST','https://other.example/events','changed',[]);}return true;};
        $verifier=new SoSecurity\Webhook\Verifier($original,$provider,$guard,$e->clock);$request=$e->request();$proof=$verifier->verify($request);
        Check::same($original,$verifier->endpoint());Check::same(true,$proof instanceof SoSecurity\Webhook\VerifiedWebhook);Check::same($original,$proof->endpoint());Check::same(hash('sha256',$request->body()),$proof->bodyDigest());Check::same(0,$e->count());
    });
}
echo 'PASS webhook request authority: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;
