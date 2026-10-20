<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\RateLimit\BudgetLimiter;
use SoSecurity\RateLimit\CompositeLimiter;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Shared send charges, separate from request admission. Retries retain spent quotas and the original notice lifetime. */
final class SendBudgets
{
    private $reserve;
    private $configuration;
    private $transition;
    public function __construct(AtomicStore $store,string $site,string $pseudonymKey,array $policies,?Clock $clock=null,int $maximumSends=3)
    {
        Guard::label($site);$names=array_keys($policies);sort($names);
        if(preg_match('//u',$site)!==1||$names!==['site','subject','target','transport']||strlen($pseudonymKey)<32||strlen($pseudonymKey)>128||$maximumSends<1||$maximumSends>30){throw new ConfigurationException('Configure four explicit send budgets, a dedicated stable key and bounded per-notice sends.','configuration.account_send_budget');}
        $clock=$clock ?? new SystemClock();$limits=[];$fingerprints=[];$horizon=1;
        foreach(['site','transport','target','subject'] as $name){$policy=$policies[$name];if(!$policy instanceof BudgetPolicy){throw new ConfigurationException('Use explicit send budget policies.','configuration.account_send_budget');}$limits[$name]=new BudgetLimiter($store,$policy,$clock);$fingerprints[$name]=$policy->fingerprint();$n=$policy->capacity()*$policy->window();$horizon=max($horizon,$policy->window(),intdiv($n,$policy->limit())+($n%$policy->limit()===0?0:1));}
        $namespace=hash('sha256',json_encode(['SoSecurity.Account.SendBudgets.1',$site]));$config=hash_hmac('sha256',json_encode([$namespace,$fingerprints,$maximumSends]),$pseudonymKey);$limiter=new CompositeLimiter($limits,$clock);$observed=0;
        $this->configuration=static function()use($site,$store,$clock):array{return [$site,$store,$clock];};
        $this->reserve=static function(DispatchNotice $delivery,MailMessage $message,string $transport,string $deliveryId,int $attempt)use($store,$clock,$namespace,$config,$limiter,$horizon,$pseudonymKey,$maximumSends,&$observed):?int{
            Guard::label($transport);if(preg_match('//u',$transport)!==1||!preg_match('/\A[a-f0-9]{64}\z/D',$deliveryId)||$attempt<1||$attempt>100){throw new ValidationException('Use the authenticated delivery and original attempt.','account.send_budget');}
            $notice=$delivery->notice();if(!$message->recipient()->equals($notice->recipient())){throw new ValidationException('Send recipient differs from its authenticated notice.','account.send_budget');}$now=self::now($clock,$observed);$until=$notice->expiresAt();if($notice->issuedAt()>$now||$until<=$now){return null;}
            // Fixed namespace prevents key/policy rotation from selecting fresh global counters while old ones may live.
            $store->transact(Guard::key('account-send-config',$namespace,'configuration'),static function($state)use($now,$horizon,$config):Change{
                if($state!==null){
                    if(!self::fields($state,['format','config','seen','until'])||$state['format']!==1||!is_string($state['config'])||!preg_match('/\A[a-f0-9]{64}\z/D',$state['config'])||!is_int($state['seen'])||!is_int($state['until'])||$state['seen']<0||$state['seen']>$now||$state['until']<=$now||$state['until']<$state['seen']||$state['until']-$state['seen']>31536000){throw new StorageException('Invalid send budget configuration state.','account.send_budget_state');}
                    if(!hash_equals($config,$state['config'])){throw new StorageException('Send budget configuration changed while counters may be live.','account.send_budget_configuration');}
                }
                return new Change(['format'=>1,'config'=>$config,'seen'=>$now,'until'=>$now+$horizon],$now+$horizon,null);
            });
            if(self::now($clock,$observed)>=$now+$horizon){return null;}
            $key=Guard::key('account-send-notice',$namespace,hash('sha256',json_encode([$notice->scope(),$notice->id()])));$binding=hash_hmac('sha256',json_encode([$config,$delivery->fingerprint(),$deliveryId,hash('sha256',$message->wire())]),$pseudonymKey);
            $ready=$store->transact($key,static function($state)use($now,$until,$attempt,$binding,$maximumSends,$pseudonymKey):Change{
                $secret=$pseudonymKey;
                if($state===null){if($attempt!==1){throw new StorageException('Prior send budget state is missing; no automatic retry reset.','account.send_budget_missing');}$state=self::seal(['format'=>1,'binding'=>$binding,'used'=>0,'attempt'=>0,'phase'=>'prepared','until'=>$until,'seen'=>$now],$secret);}
                else{self::state($state,$binding,$until,$now,$maximumSends,$secret);}
                $ready=self::available($state,$attempt,$maximumSends);$state['seen']=$now;return new Change(self::seal($state,$secret),$until,$ready);
            });
            if(!$ready||self::now($clock,$observed)>=$until){return null;}
            $tag=static function(string $purpose,array $values)use($pseudonymKey,$namespace):string{return hash_hmac('sha256',json_encode([$namespace,$purpose,$values],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$pseudonymKey);};
            $decision=$limiter->consume($namespace,['site'=>'all','transport'=>$tag('transport',[$transport]),'target'=>$tag('target',[$notice->recipient()->value()]),'subject'=>$tag('subject',[$notice->scope(),$delivery->subject()])]);
            if(!$decision->allowed()){return null;}$reserved=min($until,$decision->reservedUntil(),$now+$horizon);$current=self::now($clock,$observed);if($current>=$reserved){return null;}
            $admitted=$store->transact($key,static function($state)use($binding,$until,$current,$maximumSends,$attempt,$pseudonymKey):Change{
                if($state===null){throw new StorageException('Prepared send budget state disappeared.','account.send_budget_missing');}self::state($state,$binding,$until,$current,$maximumSends,$pseudonymKey);
                $allowed=self::available($state,$attempt,$maximumSends);if($allowed){++$state['used'];$state['attempt']=$attempt;$state['phase']='reserved';}$state['seen']=$current;return new Change(self::seal($state,$pseudonymKey),$until,$allowed);
            });
            return $admitted&&self::now($clock,$observed)<$reserved?$reserved:null;
        };
        $this->transition=static function(DispatchNotice $delivery,MailMessage $message,string $deliveryId,int $attempt,string $phase)use($store,$clock,$namespace,$config,$pseudonymKey,$maximumSends,&$observed):bool{
            if(!preg_match('/\A[a-f0-9]{64}\z/D',$deliveryId)||$attempt<1||$attempt>100||!in_array($phase,['started','accepted','rejected','unknown'],true)){throw new ValidationException('Use the original send attempt and a fixed outcome.','account.send_budget');}
            $notice=$delivery->notice();if(!$message->recipient()->equals($notice->recipient())){throw new ValidationException('Send recipient differs from its authenticated notice.','account.send_budget');}$now=self::now($clock,$observed);$until=$notice->expiresAt();if($now>=$until){return false;}
            $key=Guard::key('account-send-notice',$namespace,hash('sha256',json_encode([$notice->scope(),$notice->id()])));$binding=hash_hmac('sha256',json_encode([$config,$delivery->fingerprint(),$deliveryId,hash('sha256',$message->wire())]),$pseudonymKey);
            $result=$store->transact($key,static function($state)use($binding,$until,$now,$maximumSends,$attempt,$phase,$pseudonymKey):Change{
                if($state===null){throw new StorageException('Reserved send state is missing.','account.send_budget_missing');}self::state($state,$binding,$until,$now,$maximumSends,$pseudonymKey);
                $allowed=$state['attempt']===$attempt&&($phase==='started'?$state['phase']==='reserved':in_array($state['phase'],['reserved','started'],true))&&($phase!=='accepted'||$state['phase']==='started');
                if($allowed){$state['phase']=$phase;}$state['seen']=$now;return new Change(self::seal($state,$pseudonymKey),$until,$allowed);
            });
            return $result&&self::now($clock,$observed)<$until;
        };
    }
    private static function available(array $state,int $attempt,int $maximum):bool {return in_array($state['phase'],['prepared','reserved','rejected'],true)&&$state['attempt']<$attempt&&$state['used']<$maximum;}
    private static function seal(array $state,string $key):array {$fields=[];foreach(['format','binding','used','attempt','phase','until','seen'] as $field){$fields[$field]=$state[$field];}$state['seal']=hash_hmac('sha256',json_encode($fields),$key);return $state;}
    private static function fields($value,array $fields):bool {if(!is_array($value)){return false;}$keys=array_keys($value);sort($keys);sort($fields);return $keys===$fields;}
    private static function state(array $state,string $binding,int $until,int $now,int $maximum,string $secret):void
    {
        if(!self::fields($state,['format','binding','used','attempt','phase','until','seen','seal'])||$state['format']!==1||!is_string($state['binding'])||!hash_equals($binding,$state['binding'])||!is_int($state['used'])||$state['used']<0||$state['used']>$maximum||!is_int($state['attempt'])||$state['attempt']<0||$state['attempt']>100||$state['attempt']<$state['used']||($state['used']===0)!==($state['attempt']===0)||!is_string($state['phase'])||!in_array($state['phase'],['prepared','reserved','started','accepted','rejected','unknown'],true)||($state['phase']==='prepared')!==($state['used']===0)||!is_int($state['until'])||$state['until']!==$until||$until<=$now||!is_int($state['seen'])||$state['seen']<0||$state['seen']>$now||!is_string($state['seal'])||!hash_equals(self::seal($state,$secret)['seal'],$state['seal'])){throw new StorageException('Invalid or changed per-notice send budget.','account.send_budget_state');}
    }
    private static function now(Clock $clock,int &$observed):int
    {
        try{$now=$clock->now();}catch(\Throwable $error){throw new StorageException('Send budget clock unavailable.','account.send_budget_clock');}
        if($now<0||$now>PHP_INT_MAX-31536001||$now<$observed){throw new StorageException('Invalid send budget clock.','account.send_budget_clock');}$observed=$now;return $now;
    }
    public function reserve(DispatchNotice $notice,MailMessage $message,string $transport,string $deliveryId,int $attempt):?int {return ($this->reserve)($notice,$message,$transport,$deliveryId,$attempt);}
    public function started(DispatchNotice $notice,MailMessage $message,string $deliveryId,int $attempt):bool {return ($this->transition)($notice,$message,$deliveryId,$attempt,'started');}
    public function settle(DispatchNotice $notice,MailMessage $message,string $deliveryId,int $attempt,MailResult $result):bool {return ($this->transition)($notice,$message,$deliveryId,$attempt,$result->state());}
    public function validateConfiguration(string $site,?Clock $clock=null,bool $requireShared=true):void
    {
        list($expected,$store,$source)=($this->configuration)();if(!hash_equals($expected,$site)||($clock!==null&&$source!==$clock&&!($source instanceof SystemClock&&$clock instanceof SystemClock))){throw new ConfigurationException('Send budgets must match the dispatcher site and clock.','configuration.account_send_budget');}
        if($requireShared){$depth=0;while($store instanceof \SoSecurity\Storage\NamespacedStore){if(++$depth>8){throw new ConfigurationException('Send budget store nesting exceeds its bound.','configuration.account_send_budget');}$store=$store->underlying();}if($store instanceof \SoSecurity\Storage\MemoryStore||$store instanceof \SoSecurity\Storage\SessionStore){throw new ConfigurationException('Send budgets require shared atomic storage.','configuration.account_send_budget');}}
    }
    public function __debugInfo():array {return ['account_send_budgets'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild private send budget configuration.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Do not deserialize send budgets.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Send budgets are immutable.','configuration.immutable');}
}
