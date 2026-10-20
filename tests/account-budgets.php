<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\Address;
use SoSecurity\Account\RequestBudgets;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

final class AccountBudgetStore implements AtomicStore
{
    public $calls=0;public $states=[];public $inner;public $before;public $after;public $retry=false;public $reorder=false;
    public function __construct(TestClock $clock){$this->inner=new MemoryStore($clock);}
    public function transact(string $key,callable $callback){
        ++$this->calls;if($this->before!==null){($this->before)($key);}
        $result=$this->inner->transact($key,function($state)use($key,$callback):Change{
            if($this->reorder&&is_array($state)&&strpos($key,'account-budget-config:')===0){$state=array_reverse($state,true);}$change=$callback($state);if($this->retry){$again=$callback($state);Check::same($change->value(),$again->value());Check::same($change->expiresAt(),$again->expiresAt());Check::same(true,$change->result()==$again->result());}
            $this->states[$key]=$change->value();return $change;
        });if($this->after!==null){($this->after)($key);}return $result;
    }
    public function eraseAnchor():void {foreach(array_keys($this->states) as $key){if(strpos($key,'account-budget-config:')===0){$this->inner->transact($key,static function():Change{return new Change(null,0,null);});}}}
}
function accountBudgetPolicies(array $limits=[]):array {$p=[];foreach(['site','source','target','subject'] as $name){$p[$name]=new BudgetPolicy('fixed_window',$limits[$name] ?? 1000,60);}return $p;}
function accountBudgetFixture(array $limits=[],int $maximum=32):array {$clock=new TestClock();$store=new AccountBudgetStore($clock);return [$clock,$store,new RequestBudgets($store,'private-site',str_repeat('s',32),accountBudgetPolicies($limits),$clock,$maximum)];}
function accountBudgetId(int $value):string {return str_pad(dechex($value),32,'0',STR_PAD_LEFT);}
function accountBudgetComplete(RequestBudgets $b,string $id,?Address $a=null,string $scope='tenant',string $owner='alice',string $source='source'):void {
    Check::same(true,$b('request','public',$scope,$source,$a,null,$id));Check::same(true,$b('request','subject',$scope,$source,$a,$owner,$id));Check::same(true,$b('request','final',$scope,$source,$a,$owner,$id));
}
list($clock,$store,$b)=accountBudgetFixture();Check::same(0,$store->calls);
foreach([['site'=>'bad'],[],array_merge(accountBudgetPolicies(),['extra'=>new BudgetPolicy()])] as $policies){Check::throws(ConfigurationException::class,static function()use($store,$policies,$clock):void{new RequestBudgets($store,'site',str_repeat('s',32),$policies,$clock);});}
foreach(['',str_repeat('s',31),str_repeat('s',129)] as $key){Check::throws(ConfigurationException::class,static function()use($store,$key,$clock):void{new RequestBudgets($store,'site',$key,accountBudgetPolicies(),$clock);});}
foreach([0,65] as $max){Check::throws(ConfigurationException::class,static function()use($store,$clock,$max):void{new RequestBudgets($store,'site',str_repeat('s',32),accountBudgetPolicies(),$clock,$max);});}
Check::same(0,$store->calls);
foreach([['unknown','public','tenant','source'],['request','unknown','tenant','source'],['request','public',"bad\xff",'source'],['request','public','tenant',"bad\0source"]] as $args){Check::throws(InvalidArgumentException::class,static function()use($b,$args):void{$b(...$args);});}
Check::throws(ValidationException::class,static function()use($b):void{$b('request','public','tenant','source',null,null,'not-an-id');});Check::same(0,$store->calls);
$a=new Address('Owner+tag@EXAMPLE.COM');$id=accountBudgetId(1);accountBudgetComplete($b,$id,$a);$calls=$store->calls;Check::same(false,$b('request','final','tenant','source',$a,'alice',$id));Check::same($calls,$store->calls);
// Independent IDs for identical bindings may finish in either order; neither can borrow the other's admission.
list($clock,$store,$b)=accountBudgetFixture();$x=accountBudgetId(2);$y=accountBudgetId(3);
foreach([$x,$y] as $id){Check::same(true,$b('request','public','tenant','source',$a,null,$id));}
foreach([$x,$y] as $id){Check::same(true,$b('request','subject','tenant','source',$a,'alice',$id));}
foreach([$y,$x] as $id){Check::same(true,$b('request','final','tenant','source',$a,'alice',$id));}
foreach(['action','scope','source','address','owner'] as $change){
    list($clock,$store,$b)=accountBudgetFixture();$id=accountBudgetId(4);Check::same(true,$b('request','public','tenant','source',$a,'alice',$id));
    $args=['request','subject','tenant','source',$a,'alice',$id];$positions=['action'=>0,'scope'=>2,'source'=>3,'address'=>4,'owner'=>5];$args[$positions[$change]]=$change==='address'?new Address('other@example.com'):($change==='action'?'confirm':'other');$calls=$store->calls;
    Check::same(false,$b(...$args));Check::same($calls,$store->calls);Check::same(false,$b('request','subject','tenant','source',$a,'alice',$id));
}
list($clock,$store,$b)=accountBudgetFixture();$id=accountBudgetId(5);Check::same(true,$b('confirm','public','tenant','source',null,null,$id));Check::same(true,$b('confirm','subject','tenant','source',$a,'alice',$id));Check::same(true,$b('confirm','final','tenant','source',$a,'alice',$id));
list($clock,$store,$b)=accountBudgetFixture();$id=accountBudgetId(6);Check::same(true,$b('confirm','public','tenant','source',null,null,$id));Check::same(true,$b('confirm','subject','tenant','source',null,'alice',$id));Check::same(true,$b('confirm','final','tenant','source',null,'alice',$id));
// Preview charging retains no reservation; missing IDs can never finish a state-changing call.
list($clock,$store,$b)=accountBudgetFixture([],1);for($i=0;$i<4;++$i){Check::same(true,$b('request','public','tenant','source',$a));}Check::same(false,$b('request','subject','tenant','source',$a,'alice'));Check::same(false,$b('request','final','tenant','source',$a,'alice'));
// Site/source/target quotas are shared across tenants, actors and adapter instances.
list($clock,$store,$b)=accountBudgetFixture(['site'=>1]);Check::same(true,$b('request','public','tenant','source',$a));$other=new RequestBudgets($store,'private-site',str_repeat('s',32),accountBudgetPolicies(['site'=>1]),$clock);Check::same(false,$other('confirm','public','other','other-source'));
list($clock,$store,$b)=accountBudgetFixture(['source'=>1]);Check::same(true,$b('request','public','tenant','source',$a));Check::same(false,$b('confirm','public','other','source'));
list($clock,$store,$b)=accountBudgetFixture(['target'=>1]);Check::same(true,$b('request','public','tenant','source',$a));Check::same(false,$b('request','public','other','other-source',$a));Check::same(true,$b('confirm','public','tenant','third-source'));
list($clock,$store,$b)=accountBudgetFixture(['subject'=>1]);accountBudgetComplete($b,accountBudgetId(7),$a);$id=accountBudgetId(8);Check::same(true,$b('request','public','tenant','source',$a,null,$id));Check::same(false,$b('request','subject','tenant','source',$a,'alice',$id));accountBudgetComplete($b,accountBudgetId(9),$a,'other');
// Ordered charges remain spent when the later target/subject dimension rejects.
list($clock,$store,$b)=accountBudgetFixture(['source'=>2,'target'=>1]);Check::same(true,$b('request','public','tenant','source',$a));Check::same(false,$b('request','public','tenant','source',$a));Check::same(false,$b('request','public','tenant','source',new Address('fresh@example.com')));
list($clock,$store,$b)=accountBudgetFixture([],1);$id=accountBudgetId(10);$next=accountBudgetId(11);Check::same(true,$b('request','public','tenant','source',$a,null,$id));$calls=$store->calls;Check::same(false,$b('request','public','tenant','source',$a,null,$next));Check::same($calls,$store->calls);Check::same(true,$b('request','subject','tenant','source',$a,'alice',$id));Check::same(true,$b('request','final','tenant','source',$a,'alice',$id));Check::same(true,$b('request','public','tenant','source',$a,null,$next));
list($clock,$store,$b)=accountBudgetFixture();$id=accountBudgetId(12);Check::same(true,$b('request','public','tenant','source',$a,null,$id));Check::same(false,$b('request','public','tenant','source',$a,null,$id));Check::same(false,$b('request','subject','tenant','source',$a,'alice',$id));
list($clock,$store,$b)=accountBudgetFixture();$id=accountBudgetId(13);Check::same(true,$b('request','public','tenant','source',$a,null,$id));$clock->time+=60;$calls=$store->calls;Check::same(false,$b('request','subject','tenant','source',$a,'alice',$id));Check::same($calls,$store->calls);Check::same(true,$b('request','public','tenant','source',$a,null,accountBudgetId(14)));
// Key/policy drift refuses during live counters, then is possible only after the drained horizon.
list($clock,$store,$b)=accountBudgetFixture();Check::same(true,$b('request','public','tenant','source',$a));
foreach([new RequestBudgets($store,'private-site',str_repeat('x',32),accountBudgetPolicies(),$clock),new RequestBudgets($store,'private-site',str_repeat('s',32),accountBudgetPolicies(['target'=>2]),$clock)] as $changed){Check::throws(StorageException::class,static function()use($changed,$a):void{$changed('request','public','tenant','source',$a);});}
$clock->time+=60;$changed=new RequestBudgets($store,'private-site',str_repeat('x',32),accountBudgetPolicies(['target'=>2]),$clock);Check::same(true,$changed('request','public','tenant','source',$a));
list($clock,$store,$b)=accountBudgetFixture();$id=accountBudgetId(15);Check::same(true,$b('request','public','tenant','source',$a,null,$id));Check::same(true,$b('request','subject','tenant','source',$a,'alice',$id));$store->eraseAnchor();Check::throws(StorageException::class,static function()use($b,$a,$id):void{$b('request','final','tenant','source',$a,'alice',$id);});Check::same(false,$b('request','final','tenant','source',$a,'alice',$id));
list($clock,$store,$b)=accountBudgetFixture();$store->retry=true;accountBudgetComplete($b,accountBudgetId(16),$a);
list($clock,$store,$b)=accountBudgetFixture();$id=accountBudgetId(17);Check::same(true,$b('request','public','tenant','source',$a,null,$id));Check::same(true,$b('request','subject','tenant','source',$a,'alice',$id));$store->after=static function()use($clock):void{$clock->time+=60;};Check::same(false,$b('request','final','tenant','source',$a,'alice',$id));$store->after=null;Check::same(false,$b('request','final','tenant','source',$a,'alice',$id));
list($clock,$store,$b)=accountBudgetFixture();$store->before=static function():void{throw new StorageException('Private synthetic failure.');};Check::throws(StorageException::class,static function()use($b,$a):void{$b('request','public','tenant','source',$a,null,accountBudgetId(18));});$store->before=null;Check::same(false,$b('request','subject','tenant','source',$a,'alice',accountBudgetId(18)));
list($clock,$store,$b)=accountBudgetFixture();Check::same(true,$b('request','public','tenant','source',$a));--$clock->time;Check::throws(StorageException::class,static function()use($b,$a):void{$b('request','public','tenant','source',$a);});
list($clock,$store,$b)=accountBudgetFixture();accountBudgetComplete($b,accountBudgetId(19),$a,'tenant','private-actor','private-source');$encoded=json_encode($store->states);
foreach([$a->value(),'private-actor','private-source',str_repeat('s',32)] as $secret){Check::same(false,strpos($encoded,$secret)!==false);Check::same(false,strpos(var_export($b,true),$secret)!==false);}
Check::same('{}',json_encode($b));Check::throws(ConfigurationException::class,static function()use($b):void{serialize($b);});Check::throws(ConfigurationException::class,static function()use($b):void{$copy=clone $b;});Check::throws(ConfigurationException::class,static function()use($b):void{$b->extra='x';});$class=RequestBudgets::class;Check::throws(ConfigurationException::class,static function()use($class):void{unserialize('O:'.strlen($class).':"'.$class.'":0:{}');});
list($clock,$store,$b)=accountBudgetFixture(['target'=>1]);accountBudgetComplete($b,accountBudgetId(20),$a);Check::same(false,$b('request','public','tenant','source',$a));
list($clock,$store,$b)=accountBudgetFixture();$store->reorder=true;accountBudgetComplete($b,accountBudgetId(21),$a);
list($clock,$store,$b)=accountBudgetFixture();$id=accountBudgetId(22);Check::same(true,$b('request','public','tenant','source',$a,null,$id));$calls=$store->calls;$store->after=static function()use($clock):void{$clock->time+=60;};Check::same(false,$b('request','subject','tenant','source',$a,'alice',$id));Check::same($calls+1,$store->calls);
list($clock,$store,$b)=accountBudgetFixture();$store->after=static function()use($clock):void{$clock->time+=60;};Check::same(false,$b('request','public','tenant','source',$a,null,accountBudgetId(23)));Check::same(1,$store->calls);
// Configuration diagnostics must inspect structure without touching the clock/backend or starting sessions.
final class AccountBudgetUncalledClock implements SoSecurity\Support\Clock {
    public $calls=0;
    public function now():int {++$this->calls;throw new RuntimeException('Configuration validation must not read time.');}
}
$configurationClock=new AccountBudgetUncalledClock();$configurationStore=new AccountBudgetStore(new TestClock());
$configurationBudget=new RequestBudgets($configurationStore,'configuration-site',str_repeat('k',32),accountBudgetPolicies(),$configurationClock);
$configurationBudget->validateConfiguration('configuration-site',$configurationClock);
Check::throws(ConfigurationException::class,static function()use($configurationBudget):void{$configurationBudget->validateConfiguration('other-site');});
Check::throws(ConfigurationException::class,static function()use($configurationBudget):void{$configurationBudget->validateConfiguration('configuration-site',new TestClock());});
Check::same(0,$configurationClock->calls);Check::same(0,$configurationStore->calls);
$defaultClockBudget=new RequestBudgets($configurationStore,'configuration-site',str_repeat('k',32),accountBudgetPolicies());
$defaultClockBudget->validateConfiguration('configuration-site',new SoSecurity\Support\SystemClock());Check::same(0,$configurationStore->calls);
foreach([new MemoryStore(),new SoSecurity\Storage\NamespacedStore(new MemoryStore(),'nested'),new SoSecurity\Storage\SessionStore('inactive')] as $unsafe){
    $candidate=new RequestBudgets($unsafe,'configuration-site',str_repeat('k',32),accountBudgetPolicies(),$configurationClock);
    Check::throws(ConfigurationException::class,static function()use($candidate,$configurationClock):void{$candidate->validateConfiguration('configuration-site',$configurationClock);});
    $candidate->validateConfiguration('configuration-site',$configurationClock,false);
}
$nested=$configurationStore;for($i=0;$i<9;++$i){$nested=new SoSecurity\Storage\NamespacedStore($nested,'level-'.$i);}
$candidate=new RequestBudgets($nested,'configuration-site',str_repeat('k',32),accountBudgetPolicies(),$configurationClock);
Check::throws(ConfigurationException::class,static function()use($candidate):void{$candidate->validateConfiguration('configuration-site');});
$noticeCodec=new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)],$configurationClock);
$noticeCodec->validateConfiguration($configurationClock);
Check::throws(ConfigurationException::class,static function()use($noticeCodec):void{$noticeCodec->validateConfiguration(new TestClock());});
Check::throws(ConfigurationException::class,static function()use($noticeCodec,$configurationClock):void{$noticeCodec->validateConfiguration($configurationClock,true);});
$utf8Codec=new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)],$configurationClock,true);$utf8Codec->validateConfiguration($configurationClock,true);
$systemCodec=new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)]);$systemCodec->validateConfiguration(new SoSecurity\Support\SystemClock());
Check::same(0,$configurationClock->calls);Check::same(0,$configurationStore->calls);
Check::same(PHP_SESSION_NONE,session_status());
echo 'PASS account request budgets: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; isolated operation IDs, global quotas, private bindings, drift/expiry/failure refusal; not SMTP send budgets\n";
