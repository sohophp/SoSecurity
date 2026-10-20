<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\RateLimit\BudgetLimiter;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\RateLimit\CompositeLimiter;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Shared request counters, not authentication or SMTP permission. Construct one private adapter per request. */
final class RequestBudgets
{
    private $invoke;
    private $configuration;
    public function __construct(AtomicStore $store,string $site,string $pseudonymKey,array $policies,?Clock $clock=null,int $maximumPending=32)
    {
        self::label($site);$names=array_keys($policies);sort($names);
        if($names!==['site','source','subject','target']||strlen($pseudonymKey)<32||strlen($pseudonymKey)>128||$maximumPending<1||$maximumPending>64){throw new ConfigurationException('Configure four account budgets, a dedicated private key and bounded admissions.','configuration.account_budget');}
        $horizon=1;
        foreach($policies as $policy){
            if(!$policy instanceof BudgetPolicy){throw new ConfigurationException('Use explicit site, source, target and subject budget policies.','configuration.account_budget');}
            $numerator=$policy->capacity()*$policy->window();$refill=intdiv($numerator,$policy->limit())+($numerator%$policy->limit()===0?0:1);$horizon=max($horizon,$policy->window(),$refill);
        }
        $clock=$clock ?? new SystemClock();
        $public=new CompositeLimiter(['site'=>new BudgetLimiter($store,$policies['site'],$clock),'source'=>new BudgetLimiter($store,$policies['source'],$clock)],$clock);
        $target=new BudgetLimiter($store,$policies['target'],$clock);$subject=new BudgetLimiter($store,$policies['subject'],$clock);
        $namespace=hash('sha256',self::json(['SoSecurity.Account.RequestBudgets.1',$site]));$configuration=[];
        foreach(['site','source','target','subject'] as $name){$configuration[$name]=$policies[$name]->fingerprint();}
        $fingerprint=hash_hmac('sha256',self::json(['configuration',$namespace,$configuration]),$pseudonymKey);
        $this->configuration=static function()use($site,$store,$clock):array{return [$site,$store,$clock];};
        $pending=[];$observed=0;
        // Captures keep keys, backend contents, bindings and in-flight state out of var_export().
        $this->invoke=static function(string $action,string $phase,string $scope,string $source,?Address $address,?string $owner,string $operation)use($store,$clock,$public,$target,$subject,$namespace,$fingerprint,$pseudonymKey,$horizon,$maximumPending,&$pending,&$observed):bool{
            if(!in_array($action,['request','confirm','cancel','complete'],true)||!in_array($phase,['public','subject','final'],true)||($operation!==''&&!preg_match('/\A[a-f0-9]{32}\z/D',$operation))){throw new ValidationException('Use the original bounded account budget context.','account.budget_context');}
            self::label($scope);self::label($source);if($owner!==null){self::label($owner);}
            $context=self::tag($pseudonymKey,$namespace,'context',[$action,$scope,$source]);
            $addressTag=$address===null?null:self::tag($pseudonymKey,$namespace,'target',[$address->value()]);
            $ownerTag=$owner===null?null:self::tag($pseudonymKey,$namespace,'subject',[$scope,$owner]);
            $now=self::now($clock,$observed);
            foreach($pending as $id=>$entry){if($entry['until']<=$now){unset($pending[$id]);}}
            if($phase==='public'){
                if($operation!==''&&(isset($pending[$operation])||count($pending)>=$maximumPending)){unset($pending[$operation]);return false;}
                self::anchor($store,$namespace,$fingerprint,$horizon,$now,true);
                if(self::now($clock,$observed)>=$now+$horizon){return false;}
                $result=$public->consume($namespace,['site'=>'all','source'=>self::tag($pseudonymKey,$namespace,'source',[$source])]);
                if(!$result->allowed()){return false;}$until=min($result->reservedUntil(),$now+$horizon);
                if($addressTag!==null){$decision=$target->consume($namespace.'.target',$addressTag);if(!$decision->allowed()){return false;}$until=min($until,$decision->reservedUntil());}
                if(self::now($clock,$observed)>=$until){return false;}
                // Read-only proposal admission has no later stages and needs no retained context.
                if($operation!==''){$pending[$operation]=['context'=>$context,'address'=>$addressTag,'owner'=>$ownerTag,'until'=>$until,'stage'=>'public'];}
                return true;
            }
            if($operation===''||!isset($pending[$operation])){return false;}
            $entry=$pending[$operation];unset($pending[$operation]);
            if(!hash_equals($entry['context'],$context)||$ownerTag===null||($entry['owner']!==null&&!hash_equals($entry['owner'],$ownerTag))||($entry['address']!==null&&$entry['address']!==$addressTag)){return false;}
            if($phase==='subject'){
                if($entry['stage']!=='public'){return false;}
                self::anchor($store,$namespace,$fingerprint,$horizon,$now,false);
                if(self::now($clock,$observed)>=$entry['until']){return false;}
                if($entry['address']===null&&$addressTag!==null){$decision=$target->consume($namespace.'.target',$addressTag);if(!$decision->allowed()){return false;}$entry['until']=min($entry['until'],$decision->reservedUntil());}
                $decision=$subject->consume($namespace.'.subject',$ownerTag);if(!$decision->allowed()){return false;}$entry['until']=min($entry['until'],$decision->reservedUntil());
                if(self::now($clock,$observed)>=$entry['until']){return false;}
                $entry['stage']='subject';$entry['address']=$addressTag;$entry['owner']=$ownerTag;$pending[$operation]=$entry;return true;
            }
            if($entry['stage']!=='subject'||$entry['address']!==$addressTag){return false;}
            self::anchor($store,$namespace,$fingerprint,$horizon,$now,false);
            return self::now($clock,$observed)<$entry['until'];
        };
    }
    private static function label(string $label):void {Guard::label($label);if(preg_match('//u',$label)!==1){throw new ValidationException('Use UTF-8 account budget labels.','account.budget_context');}}
    private static function json(array $values):string {return json_encode($values,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    private static function tag(string $key,string $namespace,string $purpose,array $values):string {return hash_hmac('sha256',self::json([$namespace,$purpose,$values]),$key);}
    private static function now(Clock $clock,int &$observed):int
    {
        try{$now=$clock->now();}catch(\Throwable $error){throw new StorageException('Account budget clock unavailable.','account.budget_clock');}
        if($now<0||$now>PHP_INT_MAX-31536001||$now<$observed){throw new StorageException('Invalid account budget clock.','account.budget_clock');}$observed=$now;return $now;
    }
    private static function anchorFields($state):bool {if(!is_array($state)){return false;}$keys=array_keys($state);sort($keys);return $keys===['fingerprint','format','observed','until'];}
    /** Policy/key drift refuses while counters may be live; later stages never adopt a missing admission anchor. */
    private static function anchor(AtomicStore $store,string $namespace,string $fingerprint,int $horizon,int $now,bool $create):void
    {
        $store->transact(Guard::key('account-budget-config',$namespace,'configuration'),static function($state)use($fingerprint,$horizon,$now,$create):Change{
            if($state===null){if(!$create){throw new StorageException('Account budget admission state is missing.','account.budget_state');}}
            else{
                if(!self::anchorFields($state)||$state['format']!==1||!is_string($state['fingerprint'])||!preg_match('/\A[a-f0-9]{64}\z/D',$state['fingerprint'])||!is_int($state['observed'])||!is_int($state['until'])||$state['observed']<0||$state['observed']>$now||$state['until']<=$now||$state['until']<$state['observed']||$state['until']-$state['observed']>31536000){throw new StorageException('Invalid account budget admission state.','account.budget_state');}
                if(!hash_equals($state['fingerprint'],$fingerprint)){throw new StorageException('Account budget policy or pseudonym key changed while counters are live.','account.budget_configuration');}
            }
            $until=$now+$horizon;return new Change(['format'=>1,'fingerprint'=>$fingerprint,'observed'=>$now,'until'=>$until],$until,null);
        });
    }
    /** Structural checks only; no clock/backend call. Runtime durability of a custom store remains the host's contract. */
    public function validateConfiguration(string $site,?Clock $clock=null,bool $requireShared=true):void
    {
        self::label($site);list($expected,$store,$source)=($this->configuration)();
        if(!hash_equals($expected,$site)){throw new ConfigurationException('Account request budgets belong to another site.','configuration.account_budget_site');}
        if($clock!==null&&$source!==$clock&&!($source instanceof SystemClock&&$clock instanceof SystemClock)){throw new ConfigurationException('Account request budgets must use the lifecycle clock.','configuration.account_budget_clock');}
        if($requireShared){
            $depth=0;while($store instanceof \SoSecurity\Storage\NamespacedStore){if(++$depth>8){throw new ConfigurationException('Account budget storage nesting exceeds its bound.','configuration.account_budget_store');}$store=$store->underlying();}
            if($store instanceof \SoSecurity\Storage\MemoryStore||$store instanceof \SoSecurity\Storage\SessionStore){throw new ConfigurationException('Account request budgets require shared atomic storage.','configuration.account_budget_store');}
        }
    }
    /** Empty operation IDs permit public proposal charging only; stateful service calls supply a fresh internal ID. */
    public function __invoke(string $action,string $phase,string $scope,string $source,?Address $address=null,?string $subject=null,string $operation=''):bool {return ($this->invoke)($action,$phase,$scope,$source,$address,$subject,$operation);}
    public function __debugInfo():array {return ['account_request_budgets'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild account request budgets from private configuration.','configuration.account_budget_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Do not deserialize account budget admissions.','configuration.account_budget_serialization');}
    public function __clone() {throw new ConfigurationException('Do not clone in-flight account budget admissions.','configuration.account_budget_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account request budgets are immutable.','configuration.immutable');}
}
