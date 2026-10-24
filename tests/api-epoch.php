<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
final class EpochInterleavingStore implements SoSecurity\Storage\AtomicStore
{
    public $base;public $after;public function __construct(){ $this->base=new SoSecurity\Storage\MemoryStore(new TestClock()); }
    public function transact(string $key,callable $callback){$r=$this->base->transact($key,$callback);if($this->after!==null){($this->after)($key,$r);}return $r;}
}
function setEpoch(EpochInterleavingStore $s,string $epoch):void{$s->base->transact('api-key-epoch:'.hash('sha256','user'),static function()use($epoch){return new SoSecurity\Storage\Change(['v'=>1,'subject'=>'user','epoch'=>$epoch],0,true);});}
function epochReason(string $reason,callable $body):void{try{$body();}catch(SoSecurity\Exception\SecurityException $e){Check::same($reason,$e->reason());return;}throw new RuntimeException('Expected '.$reason);}
$clock=new TestClock();$s=new EpochInterleavingStore();$api=new SoSecurity\Api\ApiKeys($s,$clock);$old=$api->issue('user',['read']);Check::same('user',$api->authenticate($old->token())->subject());
$s->after=static function(string $key,$result)use($s):void{if(strpos($key,'api-key:')===0&&$result===true){$s->after=null;setEpoch($s,str_repeat('a',64));}};
epochReason('api.issuance_unknown',static function()use($api):void{$api->issue('user');});Check::same(null,$api->authenticate($old->token()));$fresh=$api->issue('user',['read']);Check::same('user',$api->authenticate($fresh->token())->subject());
$s->after=static function(string $key,$result)use($s):void{if(strpos($key,'api-key:')===0&&$result===true){$s->after=null;setEpoch($s,str_repeat('b',64));}};
epochReason('api.rotation_unknown',static function()use($api,$fresh):void{$api->rotate($fresh->identity()->id());});Check::same(null,$api->authenticate($fresh->token()));$current=$api->issue('user');
$s->after=static function(string $key,$result)use($s):void{if(strpos($key,'api-key-epoch:')===0&&is_string($result)){$s->after=null;setEpoch($s,str_repeat('c',64));}};Check::same(null,$api->authenticate($current->token()));
$current=$api->issue('user');$s->base->transact('api-key-epoch:'.hash('sha256','user'),static function(){return new SoSecurity\Storage\Change(null,0,true);});Check::same(null,$api->authenticate($current->token()));Check::same('user',$api->authenticate($old->token())->subject());
$s->base->transact('api-key-epoch:'.hash('sha256','user'),static function(){return new SoSecurity\Storage\Change(['v'=>1,'subject'=>'wrong','epoch'=>str_repeat('a',64)],0,true);});Check::throws(SoSecurity\Storage\StorageException::class,static function()use($api,$old):void{$api->authenticate($old->token());});
echo 'PASS API epoch interleavings: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; issuance/rotation outcomes unknown on concurrent retirement, authentication rechecks, v2 missing-root refuses, legacy missing-root counterexample requires witness, malformed roots rejected\n";
