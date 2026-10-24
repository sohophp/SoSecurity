<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__).'/vendor/autoload.php';
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\WebAuthn\ChallengeStore;
use SoSecurity\WebAuthn\Ceremonies;
use Webauthn\PublicKeyCredentialUserEntity;
final class ChallengeTimeClock implements Clock {
    public $time=1000;public $fail=false;
    public function now():int {if($this->fail){throw new RuntimeException('SYNTHETIC-PRIVATE-CLOCK');}return $this->time;}
}
final class ChallengeLagStore implements AtomicStore {
    public $delta=0;public $calls=0;private $inner;private $clock;
    public function __construct(ChallengeTimeClock $clock){$this->clock=$clock;$this->inner=new MemoryStore($clock);}
    public function transact(string $key,callable $callback){++$this->calls;$result=$this->inner->transact($key,$callback);$this->clock->time+=$this->delta;return $result;}
}
$mode=$argv[2]??'consume-expired';$clock=new ChallengeTimeClock();$backend=new ChallengeLagStore($clock);$store=new ChallengeStore($backend,'site',$clock,30);
$options=(new Ceremonies('Test','example.test','https://example.test'))->beginRegistration(PublicKeyCredentialUserEntity::create('alice','alice-id','Alice'),[]);$checks=0;
$check=static function(bool $ok)use(&$checks):void{if(!$ok){throw new RuntimeException('Challenge time invariant failed');}++$checks;};
$reject=static function(callable $run,string $reason)use($check):void{try{$run();}catch(StorageException $error){$check($error->reason()===$reason);$check($error->getPrevious()===null);$check(strpos($error->getMessage(),'SYNTHETIC')===false);return;}throw new RuntimeException('Expected clock rejection');};
if($mode==='issue-expired'){$backend->delta=30;$reject(static function()use($store,$options):void{$store->issue($options,'alice-id','session');},'webauthn.expired');}
elseif($mode==='invalid-clock'){
    foreach([-1,PHP_INT_MAX] as $invalid){$clock->time=$invalid;$reject(static function()use($store,$options):void{$store->issue($options,'alice-id','session');},'webauthn.clock');}
    $clock->fail=true;$reject(static function()use($store,$options):void{$store->issue($options,'alice-id','session');},'webauthn.clock');$check($backend->calls===0);
}else{
    $handle=$store->issue($options,'alice-id','session');$backend->delta=$mode==='consume-backward'?-1:($mode==='consume-valid'?29:30);
    if($mode==='consume-backward'){$reject(static function()use($store,$handle):void{$store->consume($handle,'register','alice-id','session');},'webauthn.clock');}
    else{$result=$store->consume($handle,'register','alice-id','session');$check($mode==='consume-valid'?$result!==null:$result===null);}
    $backend->delta=0;$check($store->consume($handle,'register','alice-id','session')===null);
}
echo 'PASS WebAuthn challenge time '.$mode.': '.$checks.' assertions PHP '.PHP_VERSION.PHP_EOL;
