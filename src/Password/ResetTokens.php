<?php
declare(strict_types=1);
namespace SoSecurity\Password;
use SoSecurity\Account\AccountRecord;
use SoSecurity\Account\StateAccountPolicy;
use SoSecurity\Account\StateBoundary;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\FileStateBoundary;
use SoSecurity\Storage\ProofEpochStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;
/** One-time reset proof primitive. Mail, MFA recovery, password policy and delivery remain explicit host duties. */
final class ResetTokens
{
    private $tokens;private $store;private $clock;private $ttl;
    private $boundary;private $state;private $sessions;private $guard;private $site;private $address;private $addressVersion;private $policy;private $busy=false;private $admitted;
    /** Native guard(entry, scope, ?AccountRecord): strict true, read-only; no delivery or external effects. */
    public function __construct(AtomicStore $store,int $ttl=1800,?Clock $clock=null,?StateBoundary $boundary=null,?StateAccountPolicy $state=null,?SessionRegistry $sessions=null,?callable $requestGuard=null,string $site='',string $addressColumn='address',string $addressVersionColumn='address_version')
    {
        $clock=$clock??new SystemClock();Guard::duration($ttl);
        if($state!==null&&($boundary===null||$sessions===null||$requestGuard===null||$requestGuard instanceof \SoSecurity\Account\StateRequestGuard||!$state->resetContext($store,$sessions,$clock,$boundary,$site,$addressColumn,$addressVersionColumn))){throw new ConfigurationException('Use the exact native reset graph and explicit reset request authority.','configuration.state_permission');}
        if($state===null&&($sessions!==null||$requestGuard!==null)){throw new ConfigurationException('Supply native reset authority as one complete graph.','configuration.state_permission');}
        $this->boundary=$boundary;$this->state=$state;$this->sessions=$sessions;$this->guard=$requestGuard;$this->site=$site;$this->address=$addressColumn;$this->addressVersion=$addressVersionColumn;$this->clock=$clock;$this->ttl=$ttl;
        $this->policy=$state===null?null:hash('sha256','SoSecurity.Password.Reset.Native.Policy.1.'.self::json([$state->binding(),$ttl,$site,$addressColumn,$addressVersionColumn]));if($boundary!==null){$store=$boundary->protect($store);}$this->store=$store;$this->tokens=new CsrfTokens($store,$ttl,4,$clock);
    }
    /** Namespace-wide retirement of every version binding; it never changes passwords or ordinary CSRF. */
    public function stateRetirementEpoch(\SoSecurity\Storage\FileStore $store,Clock $clock,string $epoch):?array
    {
        if(($this->store!==$store&&(!$this->store instanceof \SoSecurity\Account\WitnessedStore||!$this->store->protects($store)))||$this->clock!==$clock){return null;}
        return ProofEpochStore::retirement($store,'password-reset','namespace',$epoch,hash('sha256','SoSecurity.Password.ResetTokens.Policy.1.'.$this->ttl));
    }
    private function legacy():void{if($this->state!==null){throw new ConfigurationException('Use current-account native reset For methods.','configuration.state_reset_entry');}FileStateBoundary::assertStoreActive($this->store);if($this->boundary!==null){$this->boundary->assertActive();}}
    public function issue(string $accountVersion):string{$this->legacy();return $this->tokens->issue('password-reset',$accountVersion);}
    public function consume(string $accountVersion,$token):bool{$this->legacy();return $this->tokens->verify('password-reset',$accountVersion,$token,true);}
    public function revoke(string $accountVersion):void{$this->legacy();$this->tokens->revoke('password-reset',$accountVersion);}
    /** Return only to trusted server delivery code; never expose this as an anonymous HTTP response. */
    public function issueFor(string $scope,string $subject):?string{return $this->native('issue',$scope,$subject,null);}
    public function consumeFor(string $scope,string $subject,$token):bool{return $this->native('consume',$scope,$subject,$token)===true;}
    public function revokeFor(string $scope,string $subject):void{$this->native('revoke',$scope,$subject,null);}
    /** work(PDO, AccountRecord) runs once in owned SQL; no output, external effects, DDL or transaction control. */
    public function withConsumption(string $scope,string $subject,\PDO $connection,array $tables,$token,callable $work)
    {
        if($this->state===null||!$this->state->credentialSqlContext($connection,$tables)){throw new ConfigurationException('Use the exact native reset PDO and complete declared effect tables.','configuration.state_business');}return $this->native('execute',$scope,$subject,$token,$connection,$tables,$work);
    }
    private static function json(array $value):string{return json_encode($value,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
    private function now():int{try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Reset proof clock unavailable.','reset.clock');}if($now<0||$now>PHP_INT_MAX-31536001){throw new StorageException('Invalid reset proof clock.','reset.clock');}return $now;}
    private function live():void
    {
        $at=$this->now();if($at<$this->admitted['seen']){throw new StorageException('Reset proof clock moved backwards.','reset.clock');}$this->admitted['seen']=$at;if($this->admitted['expires']!==null&&$this->admitted['expires']<=$at){throw new SecurityException('Reset proof expired during effects.','reset.expired');}
    }
    private function native(string $entry,string $scope,string $subject,$token,?\PDO $pdo=null,array $tables=[],?callable $work=null)
    {
        if($this->state===null){throw new ConfigurationException('Configure the native reset graph explicitly.','configuration.state_permission');}if($this->busy||$this->boundary->active()){throw new ConfigurationException('Enter native reset operations once.','configuration.state_request_nested');}$this->boundary->assertScope($scope);if(!$this->state->recoveryRegistry($this->sessions,$scope)){throw new ConfigurationException('Use the native reset policy scope.','configuration.state_scope');}Guard::label($subject);if(preg_match('//u',$subject)!==1){throw new ConfigurationException('Use a UTF-8 subject.','configuration.identity');}
        if(($entry==='consume'||$entry==='execute')&&(!is_string($token)||preg_match('/\A[a-f0-9]{64}\z/D',$token)!==1)){return null;}$names=array_keys($tables);sort($names);$deadline=new \SoSecurity\Support\Deadline(30000);$this->busy=true;
        try{$result=$this->boundary->run('password.reset.'.$entry,function()use($entry,$token,$pdo,$work,$deadline){
            $a=$this->admitted;$binding=$a['binding'];$this->live();if($entry==='issue'){$result=$this->tokens->issue('password-reset',$binding);$this->live();return $result;}if($entry==='revoke'){$this->tokens->revoke('password-reset',$binding);$this->live();return null;}
            if(!$this->tokens->verify('password-reset',$binding,$token,true)){throw new StorageException('Admitted reset proof changed during effects.','account.witness_changed');}$this->live();if($entry==='consume'){return true;}$unit=new SqlTransaction($pdo,$this->clock,30000);$live=function():void{$this->live();};return $unit->run(function()use($unit,$pdo,$work,$a){return $unit->invoke($work,[$pdo,$a['record']],'reset.business_unavailable');},null,$live,$live,$deadline);
        },function(string $expected)use($entry,$scope,$subject,$token,$names){return $this->admit($entry,$scope,$subject,$token,$names,$expected);},null,$deadline);
            if($this->admitted!==null){
                $this->boundary->run('password.reset.'.$entry.'_check',static function():void{throw new ConfigurationException('Reset proof completion is read only.','configuration.state_business');},function(string $expected)use($entry,$scope,$subject):bool{
                    $this->live();$view=$this->state->resetView($scope,$subject,$expected,$this->address,$this->addressVersion);
                    if($view===null){throw new SecurityException('Current reset identity required.','reset.request_denied');}
                    // A successful business transaction may deliberately change credential/address versions.
                    // Pure proof operations cannot silently adopt a changed binding.
                    if($entry!=='execute'){$binding=hash('sha256','SoSecurity.Password.Reset.Native.Binding.1.'.self::json([$this->site,$scope,$subject,$view['fingerprint']]));if(!hash_equals($this->admitted['binding'],$binding)){throw new SecurityException('Reset identity changed before return.','reset.request_denied');}}
                    $this->protect($entry,$scope,$view['record']);$this->live();return false;
                },null,$deadline);
                $deadline->check('account.operation_timeout');$this->live();
            }
            return $result;
        }
        finally{$this->admitted=null;$this->busy=false;}
    }
    private function protect(string $entry,string $scope,?AccountRecord $record):void
    {
        try{$allowed=($this->guard)($entry,$scope,$record);}catch(\Throwable $error){throw new DependencyException('Reset request authority unavailable.','reset.request_unavailable');}
        if($allowed!==true){throw new SecurityException('Reset request authority denied.','reset.request_denied');}
    }
    private function admit(string $entry,string $scope,string $subject,?string $token,array $tables,string $expected)
    {
        $started=$this->now();$view=$this->state->resetView($scope,$subject,$expected,$this->address,$this->addressVersion);$record=$view===null?null:$view['record'];$this->protect($entry,$scope,$record);if($view===null){return false;}
        $binding=hash('sha256','SoSecurity.Password.Reset.Native.Binding.1.'.self::json([$this->site,$scope,$subject,$view['fingerprint']]));$context=ProofEpochStore::context('password-reset','namespace');$marker=ProofEpochStore::markerBytes($this->state->credentialBytes(ProofEpochStore::key($context),$expected),$context);$raw=$this->state->credentialBytes(Guard::key('csrf','password-reset',$binding),$expected);$at=$this->now();$state=ProofEpochStore::payload($raw===null?null:Codec::decode($raw,$at),$marker,$context);$state=$state??[];if(count($state)>64){throw new StorageException('Corrupt reset proof capacity.','storage.corrupt');}
        foreach($state as $digest=>$expires){if(!is_string($digest)||preg_match('/\A[a-f0-9]{64}\z/D',$digest)!==1||!is_int($expires)||$expires<=0){throw new StorageException('Corrupt reset proof record.','storage.corrupt');}if($expires<=$at){unset($state[$digest]);}}
        if($entry==='issue'&&!$this->state->credentialCapacity(Guard::key('csrf','password-reset',$binding),$expected)){throw new SecurityException('Reset proof physical snapshot capacity reached.','reset.capacity');}
        $expires=$entry==='issue'?$at+$this->ttl:null;if($entry==='consume'||$entry==='execute'){$expires=$state[hash('sha256',$token)]??null;if($expires===null){return false;}}if($entry==='revoke'&&!$state){return false;}$end=$this->now();if($end<$started){throw new StorageException('Reset admission clock moved backwards.','reset.clock');}if($expires!==null&&$expires<=$end){return false;}
        $this->admitted=['binding'=>$binding,'record'=>$record,'seen'=>$end,'expires'=>$expires];$request=hash('sha256','SoSecurity.Password.Reset.Native.Request.1.'.self::json(['entry'=>$entry,'subject'=>$subject,'identity'=>$view['fingerprint'],'binding'=>$binding,'proof'=>$token===null?null:hash('sha256',$token),'tables'=>$tables,'observed'=>$expected,'policy'=>$this->policy]));return \SoSecurity\Account\StateOperation::reset('password.reset.'.$entry,$scope,$subject,$request,$this->policy,$end);
    }
    public function __debugInfo():array{return ['reset_tokens'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Rebuild reset services from trusted configuration.','configuration.reset_serialization');}
}
