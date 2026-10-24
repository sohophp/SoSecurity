<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $api=new SoSecurity\Api\ApiKeys($x->store,$x->e->clock);$token=$x->boundary->run('owned.api.issue',static function()use($api):string{return $api->issue('user',['read'])->token();});$old=entryFiles($x);$frame=$api->stateEpoch($x->store,$x->e->clock,'user',str_repeat('a',64));$x->boundary->run('owned.api.epoch',static function()use($x,$frame):void{$v=json_decode($frame['after'],true)['value'];$x->store->transact($frame['key'],static function()use($v){return new SoSecurity\Storage\Change($v,0,true);});});Check::same(null,$x->boundary->run('owned.api.verify',static function()use($api,$token){return $api->authenticate($token);}));$current=$x->inspect();$new=entryFiles($x);entryRestore($x,$old);$called=0;witnessReason('account.witness_stale',static function()use($x,$api,$token,&$called):void{$x->boundary->run('owned.api.replayed',static function()use($api,$token,&$called):void{++$called;$api->authenticate($token);});});Check::same(0,$called);Check::same($current,$x->inspect());entryRestore($x,$new);
});
echo 'PASS API epoch complete file replay: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; restored legacy key and missing marker rejected before provider/business effects by independent full-source witness\n";
