<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Operation\Grants;
use SoSecurity\Operation\Confirmation;
use SoSecurity\Operation\Grant;
use SoSecurity\Operation\Permit;
use SoSecurity\Support\Clock;

/** Concrete independent password/MFA/session and exact one-use Grants control. No boolean approval adapter. */
final class StateRetirementControl
{
    private $dependencies;
    private $observed;
    public function __construct(StateBoundary $boundary,StateAccountPolicy $policy,SessionRegistry $sessions,Grants $grants,string $scope,Clock $clock)
    {
        if(!$boundary->semanticAuthority()||!$boundary->acceptsPolicy($policy)||!$policy->recoveryRegistry($sessions,$scope)||!$policy->recoveryClock($clock)||!$grants->recoveryContext($sessions,$boundary,$policy)){throw new ConfigurationException('Bind independent retirement approval to the actual protected strong authentication services.','configuration.state_retirement');}
        $this->dependencies=static function()use($boundary,$policy,$sessions,$grants,$scope,$clock):array{return [$boundary,$policy,$sessions,$grants,$scope,$clock];};
    }
    private function d():array{return ($this->dependencies)();}
    public function binding():string{$d=$this->d();return hash('sha256','SoSecurity.Account.StateRetirementControl.1.'.$d[0]->binding().$d[1]->binding().$d[3]->policy()->fingerprint());}
    public function independentOf(LocalStateWitness $witness):bool{return $this->d()[0]->independentOf($witness);}
    public function now():int{$now=$this->d()[5]->now();if($now<1||$now>PHP_INT_MAX-31536001||($this->observed!==null&&$now<$this->observed)){throw new SecurityException('Invalid independent approval clock.','account.retirement_clock');}$this->observed=$now;return $now;}
    private function action($review):string
    {
        if($review instanceof StateRetirementReview){return $review->metadata()['purpose']==='retire_stale'?'state.retire_stale':'state.retire_unknown';}if($review instanceof StateSuccessorReview){return 'state.successor.stage';}if($review instanceof StateContainmentReview){return 'state.accounts.contain';}if($review instanceof StateFactorContainmentReview){return 'state.factors.contain';}if($review instanceof StateFactorResolutionReview){return 'state.factors.resolve';}if($review instanceof StateAccountResolutionReview){return 'state.accounts.resolve';}if($review instanceof StateWorkerReview){return $review->metadata()['purpose']==='handoff_workers'?'state.workers.handoff':'state.workers.resolve';}if($review instanceof StateProofReview){return $review->metadata()['purpose']==='retire_proofs'?'state.proofs.retire':'state.proofs.resolve';}if($review instanceof StateApiKeyReview){return $review->metadata()['purpose']==='retire_api_keys'?'state.api_keys.retire':'state.api_keys.resolve';}if($review instanceof StateCredentialInstallReview){return $review->metadata()['purpose']==='install_credentials'?'state.credentials.install':'state.credentials.resolve';}throw new ConfigurationException('Use one exact supported sealed selection.','configuration.state_retirement');
    }
    private function permission($review,string $actor,string $token):StatePermission{return new StatePermission($this->action($review),$this->d()[4],$actor,$review->fingerprint(),$token,['state_recovery_operator'],2,$this->d()[3]->policy()->maximumAge(),true,false,$this->d()[3]->policy()->methods());}
    private function run($review,string $actor,string $token,callable $work)
    {
        $d=$this->d();$v=$review->metadata();$now=$this->now();if($v['control']!==$this->binding()||$now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Independent retirement selection is stale.','account.retirement_expired');}
        $r=$this->permission($review,$actor,$token);return $d[0]->authorized($this->action($review),$d[4],$review->fingerprint(),$d[1],$r,$work);
    }
    public function review(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.retirement.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$this->d()[3]->policy()->maximumAge(),true,false,$this->d()[3]->policy()->methods());$d[0]->authorized('state.retirement.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function begin(StateRetirementReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirm(StateRetirementReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consume(StateRetirementReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact current independent one-use approval required.','account.retirement_denied');}return $permit;
    }
    public function current(StateRetirementReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewSuccessor(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.successor.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.successor.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginSuccessor(StateSuccessorReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmSuccessor(StateSuccessorReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeSuccessor(StateSuccessorReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact current independent successor approval required.','account.successor_denied');}return $permit;
    }
    public function currentSuccessor(StateSuccessorReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewContainment(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.accounts.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.accounts.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginContainment(StateContainmentReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmContainment(StateContainmentReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeContainment(StateContainmentReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact independent account containment approval required.','account.containment_denied');}return $permit;
    }
    public function currentContainment(StateContainmentReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewFactors(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.factors.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.factors.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginFactors(StateFactorContainmentReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmFactors(StateFactorContainmentReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeFactors(StateFactorContainmentReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact independent factor containment approval required.','account.containment_denied');}return $permit;
    }
    public function currentFactors(StateFactorContainmentReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewResolution(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.factors.resolution.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.factors.resolution.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginResolution(StateFactorResolutionReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmResolution(StateFactorResolutionReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeResolution(StateFactorResolutionReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact independent factor containment approval required.','account.containment_denied');}return $permit;
    }
    public function currentResolution(StateFactorResolutionReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewAccountResolution(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.accounts.resolution.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.accounts.resolution.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginAccountResolution(StateAccountResolutionReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmAccountResolution(StateAccountResolutionReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeAccountResolution(StateAccountResolutionReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact independent account containment approval required.','account.containment_denied');}return $permit;
    }
    public function currentAccountResolution(StateAccountResolutionReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewInstallation(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.credentials.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.credentials.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginInstallation(StateCredentialInstallReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmInstallation(StateCredentialInstallReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeInstallation(StateCredentialInstallReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact independent account containment approval required.','account.containment_denied');}return $permit;
    }
    public function currentInstallation(StateCredentialInstallReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewApiKeys(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.api_keys.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.api_keys.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginApiKeys(StateApiKeyReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmApiKeys(StateApiKeyReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeApiKeys(StateApiKeyReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact independent account containment approval required.','account.containment_denied');}return $permit;
    }
    public function currentApiKeys(StateApiKeyReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewProofs(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.proofs.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.proofs.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginProofs(StateProofReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmProofs(StateProofReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeProofs(StateProofReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact independent account containment approval required.','account.containment_denied');}return $permit;
    }
    public function currentProofs(StateProofReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function reviewWorkers(string $target,string $actor,string $token):void
    {
        $d=$this->d();$r=new StatePermission('state.workers.review',$d[4],$actor,$target,$token,['state_recovery_operator'],2,$d[3]->policy()->maximumAge(),true,false,$d[3]->policy()->methods());$d[0]->authorized('state.workers.review',$d[4],$target,$d[1],$r,static function():void{});
    }
    public function beginWorkers(StateWorkerReview $review,string $actor,string $token):Confirmation{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token){return $d[3]->begin($d[4],$actor,$token,$review->intent($d[4]));});}
    public function confirmWorkers(StateWorkerReview $review,string $actor,string $token,string $confirmation):?Grant{$d=$this->d();return $this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$confirmation){return $d[3]->confirm($d[4],$actor,$token,$review->intent($d[4]),$confirmation);});}
    public function consumeWorkers(StateWorkerReview $review,string $actor,string $token,string $grant):Permit
    {
        $d=$this->d();$permit=$this->run($review,$actor,$token,static function()use($d,$review,$actor,$token,$grant){return $d[3]->consume($d[4],$actor,$token,$review->intent($d[4]),$grant);});
        if(!$permit instanceof Permit||!in_array($permit->method(),['totp','webauthn'],true)||!in_array('state_recovery_operator',$permit->account()->roles(),true)||$permit->intent()->fingerprint()!==$review->intent($d[4])->fingerprint()||$this->now()>=$permit->expiresAt()){throw new SecurityException('Exact independent account containment approval required.','account.containment_denied');}return $permit;
    }
    public function currentWorkers(StateWorkerReview $review,string $actor,string $token):void{$this->run($review,$actor,$token,static function():void{});}
    public function actorDigest(string $actor):string{return hash('sha256',json_encode(['SoSecurity.Account.StateRetirementOperator.1',$this->d()[4],$actor]));}
    public function __debugInfo():array{return ['state_retirement_control'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload independent approval services.','configuration.state_retirement');}
    public function __wakeup():void{throw new ConfigurationException('Reload independent approval services.','configuration.state_retirement');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Approval services are immutable.','configuration.immutable');}
}
