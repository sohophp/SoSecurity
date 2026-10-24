<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\MemoryStore;

// Delay after the underlying store reads state, or after it commits consumption.
final class CsrfDelayedStore implements AtomicStore
{
    public $before = 0;
    public $after = 0;
    private $store;
    private $clock;
    public function __construct(TestClock $clock, ?AtomicStore $store = null) {$this->clock=$clock;$this->store=$store??new MemoryStore($clock);}
    public function transact(string $key, callable $callback)
    {
        $result=$this->store->transact($key,function($state)use($callback){$this->clock->time+=$this->before;return $callback($state);});
        $this->clock->time+=$this->after;
        return $result;
    }
}
foreach (['before','after'] as $phase) {
    foreach ([false,true] as $singleUse) {
        $clock=new TestClock();$store=new CsrfDelayedStore($clock);$csrf=new CsrfTokens($store,30,4,$clock);
        $token=$csrf->issue('form','browser');$store->$phase=30;
        Check::same(false,$csrf->verify('form','browser',$token,$singleUse));
    }
}
$clock=new TestClock();$store=new CsrfDelayedStore($clock);$csrf=new CsrfTokens($store,30,4,$clock);
$token=$csrf->issue('form','browser');$store->after=29;
Check::same(true,$csrf->verify('form','browser',$token,true));$store->after=0;
Check::same(false,$csrf->verify('form','browser',$token,true));
final class CsrfFaultClock implements SoSecurity\Support\Clock
{
    public $values = [];
    public function now(): int
    {
        $value=array_shift($this->values);
        if($value==='throw'){throw new RuntimeException('private-clock-secret');}
        return $value;
    }
}
foreach (['throw',null,-1,99999] as $fault) {
    $clock=new TestClock();$store=new MemoryStore($clock);$csrf=new CsrfTokens($store,30,4,$clock);
    $token=$csrf->issue('form','browser');$broken=new CsrfFaultClock();$broken->values=[100000,$fault];
    try {(new CsrfTokens($store,30,4,$broken))->verify('form','browser',$token,true);throw new RuntimeException('Expected clock refusal.');}
    catch(SoSecurity\Storage\StorageException $error){
        Check::same('csrf.clock',$error->reason());Check::same(null,$error->getPrevious());
        Check::same(false,strpos($error->getMessage(),'private-')!==false);
    }
    Check::same(false,$csrf->verify('form','browser',$token,true));
}
// A discarded optimistic attempt must not leak its match into the final result.
final class CsrfRetryStore implements AtomicStore
{
    public function transact(string $key,callable $callback)
    {
        $callback([hash('sha256',str_repeat('a',64))=>100030]);
        return $callback(null)->result();
    }
}
Check::same(false,(new CsrfTokens(new CsrfRetryStore(),30,4,new TestClock()))->verify('form','browser',str_repeat('a',64),true));
foreach (['before','after'] as $phase) {
    $clock=new TestClock();$store=new CsrfDelayedStore($clock);
    $captcha=new SoSecurity\Captcha\Captcha($store,30,3,4,$clock);
    $challenge=$captcha->arithmetic('form','browser');
    preg_match('/^(\d+) \+ (\d+)/',$challenge->prompt,$parts);
    $store->$phase=30;
    Check::same(false,$captcha->verify('form','browser',$challenge->id,(string)($parts[1]+$parts[2])));
}
foreach (['throw',null,-1,99999] as $fault) {
    $clock=new TestClock();$store=new MemoryStore($clock);$captcha=new SoSecurity\Captcha\Captcha($store,30,3,4,$clock);
    $challenge=$captcha->arithmetic('form','browser');preg_match('/^(\d+) \+ (\d+)/',$challenge->prompt,$parts);$answer=(string)($parts[1]+$parts[2]);
    $broken=new CsrfFaultClock();$broken->values=[100000,$fault];
    try {(new SoSecurity\Captcha\Captcha($store,30,3,4,$broken))->verify('form','browser',$challenge->id,$answer);throw new RuntimeException('Expected clock refusal.');}
    catch(SoSecurity\Storage\StorageException $error){
        Check::same('captcha.clock',$error->reason());Check::same(null,$error->getPrevious());
        Check::same(false,strpos($error->getMessage(),'private-')!==false);
    }
    Check::same(false,$captcha->verify('form','browser',$challenge->id,$answer));
}
$directory=privateDirectory();
try {
    foreach (['before','after'] as $phase) {
        $clock=new TestClock();$store=new CsrfDelayedStore($clock,new SoSecurity\Storage\FileStore($directory,'proof-time-'.$phase,$clock));
        $csrf=new CsrfTokens($store,30,4,$clock);$captcha=new SoSecurity\Captcha\Captcha($store,30,3,4,$clock);
        $token=$csrf->issue('form','browser');$store->$phase=30;
        Check::same(false,$csrf->verify('form','browser',$token,true));$store->$phase=0;
        $challenge=$captcha->arithmetic('form','browser');preg_match('/^(\d+) \+ (\d+)/',$challenge->prompt,$parts);$store->$phase=30;
        Check::same(false,$captcha->verify('form','browser',$challenge->id,(string)($parts[1]+$parts[2])));
    }
} finally {cleanDirectory($directory);}
echo 'PASS CSRF/CAPTCHA storage latency: '.Check::$assertions.' assertions PHP '.PHP_VERSION,PHP_EOL;
