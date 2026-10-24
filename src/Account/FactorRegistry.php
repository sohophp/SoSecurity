<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Explicit per-account signed factor directory. Active pointers have no automatic expiry or raw-state fallback. */
final class FactorRegistry
{
    private $dependencies;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $keys,FactorRepository $accounts,TotpFactors $factors,callable $readGuard,callable $managementGuard,?Policy $policy=null,?Clock $clock=null,?LocalEpochFence $fence=null)
    {
        foreach([$site,$scope] as $label){self::label($label);}if(!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)||$accounts->connection()!==$connection){throw new ConfigurationException('Use an external factor epoch and the exact host connection.','configuration.account_factor');}
        if(($fence!==null&&!$fence->matches($site,$scope,$epoch))||($factors->isManaged()&&($fence===null||!$factors->boundTo($fence)))){throw new ConfigurationException('Managed directories require their exact worker authority.','configuration.account_factor');}
        $clock=$clock??new SystemClock();$policy=$policy??new Policy();new SqlTransaction($connection,$clock,$policy->ioMilliseconds());$factors->validateConfiguration($clock,true);
        $this->dependencies=static function()use($connection,$site,$scope,$epoch,$keys,$accounts,$factors,$readGuard,$managementGuard,$policy,$clock,$fence):array{return [$connection,$site,$scope,$epoch,$keys,$accounts,$factors,$readGuard,$managementGuard,$policy,$clock,$fence];};
    }
    private function work(callable $operation) {$d=($this->dependencies)();return $d[11]===null?$operation():$d[11]->work($operation);}
    public function current(string $subject):FactorSlot
    {
        return $this->work(function()use($subject):FactorSlot{return $this->currentUnfenced($subject);});
    }
    public function initialize(string $subject):bool
    {
        return $this->work(function()use($subject):bool{return $this->initializeUnfenced($subject);});
    }
    public function adopt(string $subject):bool
    {
        return $this->work(function()use($subject):bool{return $this->adoptUnfenced($subject);});
    }
    public function binding(string $scope,string $subject):?string
    {
        return $this->work(function()use($scope,$subject):?string{return $this->bindingUnfenced($scope,$subject);});
    }
    public function verify(string $scope,string $subject,string $expectedBinding,$proof):?string
    {
        return $this->work(function()use($scope,$subject,$expectedBinding,$proof):?string{return $this->verifyUnfenced($scope,$subject,$expectedBinding,$proof);});
    }
    public function retire(string $subject,callable $audit):array
    {
        return $this->work(function()use($subject,$audit):array{return $this->retireUnfenced($subject,$audit);});
    }
    public function ledgerPolicy(HmacKeys $keys):?Policy{$d=($this->dependencies)();return $d[4]===$keys?$d[9]:null;}
    public function matchesStatePolicy(\SoSecurity\Mfa\TotpFactors $factors,\PDO $pdo,string $site,string $scope,string $epoch,\SoSecurity\Support\Clock $clock):bool{$d=($this->dependencies)();return $d[0]===$pdo&&$d[1]===$site&&$d[2]===$scope&&$d[3]===$epoch&&$d[6]===$factors&&($d[10]===$clock||($d[10] instanceof \SoSecurity\Support\SystemClock&&$clock instanceof \SoSecurity\Support\SystemClock));}
    private static function label(string $value):void {Guard::label($value);if(preg_match('//u',$value)!==1){throw new ConfigurationException('Use UTF-8 managed factor labels.','configuration.account_factor');}}
    private function unit():SqlTransaction {$d=($this->dependencies)();return new SqlTransaction($d[0],$d[10],$d[9]->ioMilliseconds());}
    private function ledger(SqlTransaction $unit,string $subject):Ledger {$d=($this->dependencies)();return new Ledger($unit,'account-factor-directory:'.hash('sha256',json_encode([$d[1],$subject])),$d[2],$d[3],$d[4],$d[9]);}
    private function id(string $subject):string {return hash('sha256','SoSecurity.Account.FactorRegistry.Pointer.1.'.$subject);}
    private function guard(SqlTransaction $u,string $action,string $phase,?AccountRecord $record=null,?string $subject=null,?FactorInspection $inspection=null,bool $currentRead=false):void {$d=($this->dependencies)();$d[6]->enlistWorkers($d[0],$currentRead?$u:null);$callback=$action==='read'?$d[7]:$d[8];if($u->invoke($callback,[$action,$phase,$d[2],$record,$subject,$inspection],'account.factor_authority')!==true){throw new SecurityException('Current managed factor authority required.','account.factor_denied');}$d[6]->enlistWorkers($d[0],$currentRead?$u:null);}
    private function account(SqlTransaction $u,string $subject):AccountRecord {
        $d=($this->dependencies)();$record=$u->invoke([$d[5],'find'],[$d[2],$subject],'account.repository');
        if(!$record instanceof AccountRecord||$record->account()->scope()!==$d[2]||$record->account()->subject()!==$subject||$record->status()!=='active'||!$record->verified()||!$record->account()->enabled()){throw new SecurityException('Current active verified account required.','account.factor_account');}return $record;
    }
    private function data(array $row,string $subject):array {$d=($this->dependencies)();return FactorDirectoryState::read($d[1],$d[2],$d[3],$row,$subject);}
    /** @return never */
    private static function corrupt():void {throw new StorageException('Managed factor pointer cannot be authenticated.','account.factor_corrupt');}
    private function bindingOf(array $data):string {$d=($this->dependencies)();return FactorDirectoryState::binding($d[1],$d[2],$d[3],$data);}
    private function slotFrom(array $data):FactorSlot {return new FactorSlot($data['subject'],$this->bindingOf($data),$data['slot_scope'],$data['slot_subject'],$data['factor_id']);}
    /** Read joining is explicit and provisional inside a host transaction, including old PDO's hidden transactions. */
    private function readUnit(callable $body,callable $finish):array {
        $d=($this->dependencies)();$u=$this->unit();$deadline=new Deadline($d[9]->ioMilliseconds());
        return $u->inContext(function()use($u,$body):array{return $body($u);},function(array $state)use($u,$finish):void{$finish($u,$state);},$deadline);
    }
    private function snapshot(string $subject):array {
        self::label($subject);return $this->readUnit(function(SqlTransaction $u)use($subject):array{$this->guard($u,'read','before',null,null,null,true);$ledger=$this->ledger($u,$subject);$initial=$ledger->readCheckpoint($this->id($subject),function()use($u,$subject):AccountRecord{return $this->account($u,$subject);});$checkpoint=$initial['checkpoint'];$record=$initial['context'];$row=$initial['row'];if($row===null||$checkpoint['entries']!==1){self::corrupt();}$data=$this->data($row,$subject);if($data['origin']==='migrating'){throw new SecurityException('Migration preparation cannot authenticate.','account.factor_migrating');}if(in_array($data['origin'],['retired','revoked'],true)){throw new SecurityException('Retired factor directories cannot authenticate.','account.factor_retired');}if($data['factor_id']!==''&&!$record->account()->mfaRequired()){self::corrupt();}$this->guard($u,'read','current',$record,null,null,true);return ['row'=>$row,'data'=>$data,'record'=>$record,'checkpoint'=>$checkpoint];},function(SqlTransaction $u,array $state)use($subject):void{$this->guard($u,'read','return',$state['record'],null,null,true);$ledger=$this->ledger($u,$subject);if($ledger->readIfCheckpoint($this->id($subject),$state['checkpoint'])!==$state['row']||$this->account($u,$subject)->fingerprint()!==$state['record']->fingerprint()){self::corrupt();}});
    }
    private function currentUnfenced(string $subject):FactorSlot {return $this->slotFrom($this->snapshot($subject)['data']);}
    /** Provision explicitly for every account. Never invoke this as a login-error fallback. */
    private function initializeUnfenced(string $subject):bool {
        self::label($subject);$d=($this->dependencies)();$u=$this->unit();$generation=bin2hex(random_bytes(16));
        $state=$u->run(function()use($u,$subject,$d,$generation):array{$this->guard($u,'initialize','before');$ledger=$this->ledger($u,$subject);$created=$ledger->initialize();if(!$created){$row=$ledger->read($this->id($subject));if($row===null){self::corrupt();}$existing=$this->data($row,$subject);if($existing['origin']==='migrating'){throw new SecurityException('An existing migration must be resolved explicitly.','account.factor_migrating');}if(in_array($existing['origin'],['retired','revoked'],true)){throw new SecurityException('Retired factor directories require explicit restoration.','account.factor_retired');}return ['created'=>false,'record'=>$this->account($u,$subject),'row'=>$row,'checkpoint'=>$ledger->checkpoint()];}
            $record=$this->account($u,$subject);$status=$u->invoke([$d[6],'status'],[$d[2],$subject],'account.factor_store');if($status['pending']||($record->account()->mfaRequired()&&!$status['enabled'])){throw new ConfigurationException('Resolve incomplete legacy MFA before managed adoption.','configuration.account_factor');}
            if($status['enabled']){$record=$this->requireMfa($u,$record);}
            $data=['format'=>1,'purpose'=>'managed_factor','subject'=>$subject,'origin'=>$status['enabled']?'legacy':'none','slot_scope'=>$status['enabled']?$d[2]:'','slot_subject'=>$status['enabled']?$subject:'','factor_id'=>$status['factor_id']??'','generation'=>$generation];
            $row=$ledger->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$u->now()+1209600);
            return ['created'=>true,'record'=>$record,'row'=>$row,'checkpoint'=>$ledger->checkpoint()];
        },null,function(array $state)use($u,$subject):void{$this->finishWrite($u,$subject,'initialize',$state);});return $state['created'];
    }
    /** First enrollment only. An existing enabled mapping can be replaced solely by the recovery orchestrator. */
    private function adoptUnfenced(string $subject):bool {
        self::label($subject);$d=($this->dependencies)();$u=$this->unit();$generation=bin2hex(random_bytes(16));$state=$u->run(function()use($u,$subject,$d,$generation):array{
            $this->guard($u,'adopt','before');$ledger=$this->ledger($u,$subject);$ledger->checkpoint();$record=$this->account($u,$subject);$row=$ledger->read($this->id($subject));if($row===null){self::corrupt();}$old=$this->data($row,$subject);if(in_array($old['origin'],['retired','revoked'],true)){throw new SecurityException('Retired factors require explicit independent restoration.','account.factor_retired');}if($old['origin']!=='none'){throw new SecurityException('Use explicit strong factor recovery for replacement.','account.factor_already_enabled');}
            $status=$u->invoke([$d[6],'status'],[$d[2],$subject],'account.factor_store');if(!$status['enabled']||$status['pending']){throw new SecurityException('A completed factor possession proof is required.','account.factor_unproven');}$record=$this->requireMfa($u,$record);
            $data=['format'=>1,'purpose'=>'managed_factor','subject'=>$subject,'origin'=>'legacy','slot_scope'=>$d[2],'slot_subject'=>$subject,'factor_id'=>$status['factor_id'],'generation'=>$generation];$saved=$ledger->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$u->now()+1209600,$row['revision']);return ['record'=>$record,'row'=>$saved,'checkpoint'=>$ledger->checkpoint()];
        },null,function(array $state)use($u,$subject):void{$this->finishWrite($u,$subject,'adopt',$state);});return true;
    }
    private function requireMfa(SqlTransaction $u,AccountRecord $record):AccountRecord {
        $d=($this->dependencies)();$result=$u->invoke([$d[5],'requireMfa'],[$record],'account.repository');
        if(!$result instanceof AccountRecord||$result->account()->scope()!==$record->account()->scope()||$result->account()->subject()!==$record->account()->subject()||!$result->account()->mfaRequired()||$result->account()->version()===$record->account()->version()||!$result->address()->equals($record->address())||$result->addressVersion()!==$record->addressVersion()||$result->status()!==$record->status()||$result->verified()!==$record->verified()||$result->account()->roles()!==$record->account()->roles()){self::corrupt();}return $result;
    }
    private function finishWrite(SqlTransaction $u,string $subject,string $action,array $state):void {
        $this->guard($u,$action,'commit',$state['record']);$ledger=$this->ledger($u,$subject);if($ledger->checkpoint()!==$state['checkpoint']||$ledger->read($this->id($subject))!==$state['row']||$this->account($u,$subject)->fingerprint()!==$state['record']->fingerprint()){self::corrupt();}
        $d=($this->dependencies)();$data=$this->data($state['row'],$subject);if($data['factor_id']!==''){$status=$u->invoke([$d[6],'status'],[$data['slot_scope'],$data['slot_subject']],'account.factor_store');if($status['factor_id']!==$data['factor_id']){throw new SecurityException('Factor changed before pointer adoption.','account.factor_changed');}}
    }
    /** Private activation capability is handed only to the strong-approval orchestrator. */
    public function recovery(callable $authority,callable $budgets,callable $approval,callable $events,?LocalEpochFence $fence=null):FactorRecovery
    {
        $d=($this->dependencies)();if($d[11]!==null){if($fence!==null&&$fence->binding()!==$d[11]->binding()){throw new ConfigurationException('Recovery must use the configured managed worker authority.','configuration.account_factor');}$fence=$d[11];}
        $facts=function(SqlTransaction $u,string $subject):array{return $this->recoveryFacts($u,$subject);};
        $activate=function(SqlTransaction $u,array $expected,string $slotScope,string $slotSubject,string $factorId):array{
            $subject=$expected['record']->account()->subject();$current=$this->recoveryFacts($u,$subject);
            if($current['record']->fingerprint()!==$expected['record']->fingerprint()||$current['identity']->fingerprint()!==$expected['identity']->fingerprint()||$current['slot']->binding()!==$expected['slot']->binding()){self::corrupt();}
            $d=($this->dependencies)();$status=$u->invoke([$d[6],'status'],[$slotScope,$slotSubject],'account.factor_store');
            if(!$status['enabled']||$status['pending']||$status['factor_id']!==$factorId){throw new SecurityException('The prepared factor is no longer current.','account.factor_changed');}
            $record=$this->requireMfa($u,$current['record']);$ledger=$this->ledger($u,$subject);
            $data=['format'=>1,'purpose'=>'managed_factor','subject'=>$subject,'origin'=>'recovery','slot_scope'=>$slotScope,'slot_subject'=>$slotSubject,'factor_id'=>$factorId,'generation'=>bin2hex(random_bytes(16))];
            $saved=$ledger->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$u->now()+1209600,$current['row']['revision']);
            $this->finishWrite($u,$subject,'replace',['record'=>$record,'row'=>$saved,'checkpoint'=>$ledger->checkpoint()]);
            $result=$this->recoveryFacts($u,$subject);
            if($result['identity']->fingerprint()===$expected['identity']->fingerprint()){self::corrupt();}return $result;
        };
        $management=function(SqlTransaction $u,string $subject):array{return $this->managementState($u,$subject);};
        return new FactorRecovery($d[0],$d[1],$d[2],$d[3],$d[4],$d[6],$facts,$activate,$authority,$budgets,$approval,$events,$d[9],$d[10],$management,$fence);
    }
    private function recoveryFacts(SqlTransaction $u,string $subject):array
    {
        self::label($subject);$this->guard($u,'read','before');$ledger=$this->ledger($u,$subject);$root=$ledger->checkpoint();$record=$this->account($u,$subject);$row=$ledger->read($this->id($subject));
        if($row===null||$root['entries']!==1){self::corrupt();}$pointer=$this->data($row,$subject);if($pointer['origin']==='migrating'){throw new SecurityException('Resolve the current migration first.','account.factor_migrating');}if(in_array($pointer['origin'],['retired','revoked'],true)){throw new SecurityException('Retired factors require explicit independent restoration.','account.factor_retired');}$slot=$this->slotFrom($pointer);$d=($this->dependencies)();
        if(!$slot->enabled()||!$record->account()->mfaRequired()){throw new SecurityException('Replacement requires an existing managed factor.','account.factor_unproven');}
        $identity=$u->invoke([$d[5],'identity'],[$record],'account.repository');
        if(!$identity instanceof \SoSecurity\Auth\Account||$identity->scope()!==$record->account()->scope()||$identity->subject()!==$subject||$identity->enabled()!==$record->account()->enabled()||$identity->roles()!==$record->account()->roles()||$identity->mfaRequired()!==$record->account()->mfaRequired()){self::corrupt();}
        $status=$u->invoke([$d[6],'status'],[$slot->slotScope(),$slot->slotSubject()],'account.factor_store');
        if($status['factor_id']!==$slot->factorId()){throw new SecurityException('Current managed factor changed.','account.factor_changed');}
        $this->guard($u,'read','current',$record);
        // Authority callbacks can change password material without advancing the raw version.
        // Re-read effective identity and external factor state after the last callback.
        $freshIdentity=$u->invoke([$d[5],'identity'],[$record],'account.repository');
        $freshStatus=$u->invoke([$d[6],'status'],[$slot->slotScope(),$slot->slotSubject()],'account.factor_store');
        if(!$freshIdentity instanceof \SoSecurity\Auth\Account||$freshIdentity->fingerprint()!==$identity->fingerprint()||$freshStatus['factor_id']!==$slot->factorId()||$ledger->checkpoint()!==$root||$ledger->read($this->id($subject))!==$row||$this->account($u,$subject)->fingerprint()!==$record->fingerprint()){self::corrupt();}
        return ['record'=>$record,'identity'=>$identity,'slot'=>$slot,'row'=>$row];
    }
    public function secondFactor():ManagedSecondFactor {return new ManagedSecondFactor($this);}
    private function bindingUnfenced(string $scope,string $subject):?string {
        $d=($this->dependencies)();if($scope!==$d[2]){return null;}$before=$this->snapshot($subject);$slot=$this->slotFrom($before['data']);if(!$slot->enabled()){if($before['record']->account()->mfaRequired()){self::corrupt();}return null;}
        $status=$d[6]->status($slot->slotScope(),$slot->slotSubject());$fresh=$this->snapshot($subject);if($status['factor_id']!==$slot->factorId()||$this->bindingOf($fresh['data'])!==$slot->binding()||$fresh['record']->fingerprint()!==$before['record']->fingerprint()){throw new SecurityException('Current managed factor changed.','account.factor_changed');}return $slot->binding();
    }
    private function verifyUnfenced(string $scope,string $subject,string $expectedBinding,$proof):?string {
        $d=($this->dependencies)();if($scope!==$d[2]||!preg_match('/\A[a-f0-9]{64}\z/D',$expectedBinding)||!is_array($proof)||count($proof)!==2||!isset($proof['type'],$proof['code'])||!in_array($proof['type'],['totp','recovery'],true)){return null;}
        $before=$this->snapshot($subject);$slot=$this->slotFrom($before['data']);if(!$slot->enabled()||!hash_equals($expectedBinding,$slot->binding())){return null;}
        if(!$d[6]->verifyBound($slot->slotScope(),$slot->slotSubject(),$slot->factorId(),$proof['code'],$proof['type']==='recovery')){return null;}$fresh=$this->snapshot($subject);
        return $this->bindingOf($fresh['data'])===$slot->binding()&&$fresh['record']->fingerprint()===$before['record']->fingerprint()?$proof['type']:null;
    }
    private function managementRecord(SqlTransaction $u,string $subject):?AccountRecord
    {
        $d=($this->dependencies)();$r=$u->invoke([$d[5],'find'],[$d[2],$subject],'account.repository');
        if($r!==null&&(!$r instanceof AccountRecord||$r->account()->scope()!==$d[2]||$r->account()->subject()!==$subject)){self::corrupt();}return $r;
    }
    private function managementIdentity(SqlTransaction $u,?AccountRecord $r):?\SoSecurity\Auth\Account
    {
        if($r===null||$r->status()!=='active'||!$r->verified()){return null;}$d=($this->dependencies)();$id=$u->invoke([$d[5],'identity'],[$r],'account.repository');
        if(!$id instanceof \SoSecurity\Auth\Account||$id->scope()!==$r->account()->scope()||$id->subject()!==$r->account()->subject()||$id->enabled()!==$r->account()->enabled()||$id->roles()!==$r->account()->roles()||$id->mfaRequired()!==$r->account()->mfaRequired()){self::corrupt();}return $id;
    }
    private function managementCredential(SqlTransaction $u,?AccountRecord $record):?string
    {
        if($record===null){return null;}$d=($this->dependencies)();$binding=$u->invoke([$d[5],'credentialBinding'],[$record],'account.repository');if(!is_string($binding)||!preg_match('/\A[a-f0-9]{64}\z/D',$binding)){self::corrupt();}return $binding;
    }
    private function managementStamp(array $data,?AccountRecord $record,?\SoSecurity\Auth\Account $identity,?string $credential):string
    {
        return hash('sha256',json_encode(['SoSecurity.Account.FactorInspection.2',$this->bindingOf($data),$record===null?null:$record->fingerprint(),$identity===null?null:$identity->fingerprint(),$credential]));
    }
    /** Metadata-only management capability. It never validates a login or adopts a missing/raw generation. */
    private function managementState(SqlTransaction $u,string $subject):array
    {
        self::label($subject);$this->guard($u,'inspect','before',null,$subject);$l=$this->ledger($u,$subject);$checkpoint=$l->checkpoint();$row=$l->read($this->id($subject));if($row===null||$checkpoint['entries']!==1){self::corrupt();}
        $data=$this->data($row,$subject);if($data['origin']==='migrating'){throw new SecurityException('Use migration-specific management.','account.factor_migrating');}$record=$this->managementRecord($u,$subject);$identity=$this->managementIdentity($u,$record);$credential=$this->managementCredential($u,$record);$stamp=$this->managementStamp($data,$record,$identity,$credential);
        $this->guard($u,'inspect','current',$record,$subject);$fresh=$this->managementRecord($u,$subject);$freshIdentity=$this->managementIdentity($u,$fresh);$freshCredential=$this->managementCredential($u,$fresh);
        if($this->managementStamp($data,$fresh,$freshIdentity,$freshCredential)!==$stamp||$l->checkpoint()!==$checkpoint||$l->read($this->id($subject))!==$row){self::corrupt();}
        return ['record'=>$record,'identity'=>$identity,'slot'=>$this->slotFrom($data),'row'=>$row,'data'=>$data,'retired'=>in_array($data['origin'],['retired','revoked'],true),'credential_binding'=>$credential,'stamp'=>$stamp,'checkpoint'=>$checkpoint];
    }
    private function managementCurrent(SqlTransaction $u,string $subject,array $expected):array
    {
        $fresh=$this->managementState($u,$subject);if($fresh['stamp']!==$expected['stamp']||$fresh['row']!==$expected['row']||$fresh['checkpoint']!==$expected['checkpoint']){self::corrupt();}return $fresh;
    }
    private function inspectionValue(array $s):FactorInspection {$d=($this->dependencies)();return new FactorInspection($d[2],$s['slot'],$s['record'],$s['retired'],$s['stamp']);}
    public function inspect(string $subject):FactorInspection
    {
        self::label($subject);$u=$this->unit();$s=$u->run(function()use($u,$subject):array{return $this->managementState($u,$subject);},null,function(array $s)use($u,$subject):void{$this->guard($u,'inspect','return',$s['record'],$subject);$this->managementCurrent($u,$subject,$s);});return $this->inspectionValue($s);
    }
    private function requireInactive(array $state):void
    {
        if($state['record']!==null&&$state['record']->status()==='active'){throw new SecurityException('Disable or delete the account before factor destruction.','account.factor_active');}
    }
    /** Commit an irreversible directory tombstone first, then retire its exact physical generation. Audit joins the same PDO. */
    private function retireUnfenced(string $subject,callable $audit):array
    {
        self::label($subject);$d=($this->dependencies)();$u=$this->unit();$ready=false;$committed=false;$operation=bin2hex(random_bytes(16));
        try{$result=$u->run(function()use($u,$subject,$audit,$d,$operation):array{
            $this->guard($u,'retire','before',null,$subject);$state=$this->managementState($u,$subject);$this->requireInactive($state);$review=$this->inspectionValue($state);$this->guard($u,'retire','current',$state['record'],$subject,$review);$this->managementCurrent($u,$subject,$state);
            if($state['retired']){return ['state'=>$state,'changed'=>false,'review'=>$review];}$data=$state['data'];unset($data['migration'],$data['revocation'],$data['restoration']);$data['format']=2;$data['origin']='retired';$data['generation']=bin2hex(random_bytes(16));$l=$this->ledger($u,$subject);
            $l->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$u->now()+1209600,$state['row']['revision']);$saved=$this->managementState($u,$subject);
            if($u->invoke($audit,[$d[2],$subject,$state['record'],$state['slot'],$operation,$saved['slot']->binding(),$review],'account.factor_audit')!==true){throw new StorageException('Durable factor retirement audit required.','account.factor_audit');}
            $this->managementCurrent($u,$subject,$saved);return ['state'=>$saved,'changed'=>true,'review'=>$review];
        },null,function(array $result)use($u,$subject,&$ready):void{$state=$result['state'];$this->guard($u,'retire','commit',$state['record'],$subject,$result['review']);$this->requireInactive($this->managementCurrent($u,$subject,$state));$ready=true;});$committed=true;
            $u=$this->unit();$state=$result['state'];$review=$result['review'];$clean=$u->run(function()use($u,$subject,$state,$d,$review):array{
                $fresh=$this->managementCurrent($u,$subject,$state);$this->requireInactive($fresh);$this->guard($u,'retire','delete',$fresh['record'],$subject,$review);$this->requireInactive($this->managementCurrent($u,$subject,$state));$slot=$fresh['slot'];if(!$slot->enabled()){return ['absent'=>1,'conflicts'=>0];}
                $removed=$u->invoke([$d[6],'revokeGeneration'],[$slot->slotScope(),$slot->slotSubject(),$slot->factorId()],'account.factor_store');return ['absent'=>$removed===true?1:0,'conflicts'=>$removed===true?0:1];
            },null,function()use($u,$subject,$state,$review):void{$this->guard($u,'retire','complete',$state['record'],$subject,$review);$this->requireInactive($this->managementCurrent($u,$subject,$state));});
            return ['retired'=>true,'changed'=>$result['changed']]+$clean;
        }catch(\Throwable $error){if($ready||$committed||$u->committed()){throw new StorageException('Factor retirement completion is unknown; retain the signed tombstone.','account.completion_unknown');}throw $error;}
    }
    private function factorService():TotpFactors {return ($this->dependencies)()[6];}
    /** Current normal operations use the signed pointer and a mandatory active worker fence. */
    public function operations(LocalEpochFence $fence,callable $authority,callable $budgets,callable $approval,callable $events):FactorOperations
    {
        $d=($this->dependencies)();if($d[11]!==null&&$fence->binding()!==$d[11]->binding()){throw new ConfigurationException('Operations must use the configured managed worker authority.','configuration.account_factor');}if(!$d[5] instanceof FactorManagementRepository||!$fence->matches($d[1],$d[2],$d[3])){throw new ConfigurationException('Normal factor operations require the host MFA CAS capability and a matching fence.','configuration.factor_operations');}
        $facts=function(SqlTransaction $u,string $subject,bool $active=true):array{
            $state=$this->managementState($u,$subject);$r=$state['record'];$slot=$state['slot'];
            if($active&&($state['retired']||$r===null||$r->status()!=='active'||!$r->verified()||!$r->account()->enabled()||$state['identity']===null||$slot->enabled()!==$r->account()->mfaRequired())){throw new SecurityException('Current active managed account required.','account.factor_account');}
            if($active&&$slot->enabled()){$status=$u->invoke([$this->factorService(),'status'],[$slot->slotScope(),$slot->slotSubject()],'account.factor_store');if($status['factor_id']!==$slot->factorId()||$status['pending']){throw new SecurityException('The exact current managed factor is required.','account.factor_changed');}}
            return $state;
        };
        $mutate=function(SqlTransaction $u,array $expected,bool $required,?array $prepared=null)use($facts,$d):array{
            $subject=$expected['slot']->subject();$current=$facts($u,$subject);if($current['stamp']!==$expected['stamp']){self::corrupt();}
            if($prepared!==null){
                if(!$required||$current['slot']->enabled()||array_keys($prepared)!==['binding','scope','subject','factor']){throw new SecurityException('Only an empty managed directory can enroll.','account.factor_denied');}
                $slot=new FactorSlot($subject,$prepared['binding'],$prepared['scope'],$prepared['subject'],$prepared['factor']);$status=$u->invoke([$d[6],'status'],[$slot->slotScope(),$slot->slotSubject()],'account.factor_store');if(!$status['enabled']||$status['pending']||$status['factor_id']!==$slot->factorId()){throw new SecurityException('The reserved enrollment is no longer proven.','account.factor_unproven');}
            }
            $before=$current['record'];$after=$u->invoke([$d[5],'setMfa'],[$before,$required],'account.repository');
            if(!$after instanceof AccountRecord||$after->account()->scope()!==$before->account()->scope()||$after->account()->subject()!==$subject||$after->account()->mfaRequired()!==$required||$after->account()->version()===$before->account()->version()||!$after->address()->equals($before->address())||$after->addressVersion()!==$before->addressVersion()||$after->account()->roles()!==$before->account()->roles()||$after->status()!==$before->status()||$after->verified()!==$before->verified()){self::corrupt();}
            $data=$current['data'];$data['generation']=bin2hex(random_bytes(16));if(!$required){unset($data['migration'],$data['revocation'],$data['restoration']);$data['format']=3;$data['origin']='disabled';$data['slot_scope']='';$data['slot_subject']='';$data['factor_id']='';}
            if($prepared!==null){unset($data['migration'],$data['revocation'],$data['restoration']);$data['format']=3;$data['origin']='enrolled';$data['slot_scope']=$prepared['scope'];$data['slot_subject']=$prepared['subject'];$data['factor_id']=$prepared['factor'];}
            $l=$this->ledger($u,$subject);$l->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$u->now()+1209600,$current['row']['revision']);
            $result=$facts($u,$subject);if($result['record']->fingerprint()!==$after->fingerprint()){self::corrupt();}return $result;
        };
        return new FactorOperations($d[0],$d[1],$d[2],$d[3],$d[4],$d[6],$fence,$facts,$mutate,$authority,$budgets,$approval,$events,$d[9],$d[10]);
    }
    /** Independent abandonment of an unknown normal operation; no physical effect is replayed. */
    public function operationResolution(LocalEpochFence $fence,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events):FactorOperationResolution
    {
        $d=($this->dependencies)();if(!$d[5] instanceof FactorMigrationRepository){throw new ConfigurationException('Resolution requires exact host credential-material CAS validation.','configuration.factor_resolution');}
        $operations=$this->operations($fence,$authority,$budgets,$approval,$events);
        $advance=function(SqlTransaction $u,array $expected)use($d):array{
            $subject=$expected['slot']->subject();$current=$this->managementCurrent($u,$subject,$expected);$before=$current['record'];
            // Missing/disabled/unverified identities cannot authenticate; preserve those states.
            if($before===null||$before->status()!=='active'||!$before->verified()){return $current;}
            if($current['slot']->enabled()!==$before->account()->mfaRequired()){self::corrupt();}
            $material=$this->migrationMaterial($u,$before);$after=$u->invoke([$d[5],'setMfa'],[$before,$before->account()->mfaRequired()],'account.repository');
            if(!$after instanceof AccountRecord||$after->account()->scope()!==$before->account()->scope()||$after->account()->subject()!==$subject||$after->account()->mfaRequired()!==$before->account()->mfaRequired()||$after->account()->version()===$before->account()->version()||!$after->address()->equals($before->address())||$after->addressVersion()!==$before->addressVersion()||$after->account()->roles()!==$before->account()->roles()||$after->status()!==$before->status()||$after->verified()!==$before->verified()||$this->migrationMaterial($u,$after)!==$material){self::corrupt();}
            $saved=$this->managementState($u,$subject);if($saved['record']->fingerprint()!==$after->fingerprint()||$saved['row']!==$current['row']||$saved['slot']->binding()!==$current['slot']->binding()){self::corrupt();}return $saved;
        };
        return $operations->resolution($advance,$authority,$budgets,$approval,$audit,$events);
    }
    /** Independently approved revocation blocks MFA login; it never removes the account MFA requirement. */
    public function privilegedRevocation(LocalEpochFence $fence,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events):FactorRevocation
    {
        $d=($this->dependencies)();
        if(!$d[5] instanceof FactorMigrationRepository||!$d[6]->registeredWith($d[0])||!$d[6]->boundTo($fence)||($d[11]!==null&&$d[11]->binding()!==$fence->binding())){throw new ConfigurationException('Revocation requires exact registered workers and host credential-material CAS.','configuration.factor_revocation');}
        $facts=function(SqlTransaction $u,string $subject):array{return $this->managementState($u,$subject);};
        $mutate=function(SqlTransaction $u,array $expected,array $context)use($d):array{
            $subject=$expected['slot']->subject();$current=$this->managementCurrent($u,$subject,$expected);$before=$current['record'];
            if($current['retired']||$before===null||$before->status()!=='active'||!$before->verified()||!$before->account()->enabled()||!$before->account()->mfaRequired()||!$current['slot']->enabled()){throw new SecurityException('Only a current active MFA account can be independently revoked.','account.revocation_changed');}
            $material=$this->migrationMaterial($u,$before);$after=$u->invoke([$d[5],'setMfa'],[$before,true],'account.repository');
            if(!$after instanceof AccountRecord||$after->account()->scope()!==$before->account()->scope()||$after->account()->subject()!==$subject||!$after->account()->mfaRequired()||$after->account()->version()===$before->account()->version()||!$after->address()->equals($before->address())||$after->addressVersion()!==$before->addressVersion()||$after->account()->roles()!==$before->account()->roles()||$after->status()!==$before->status()||$after->verified()!==$before->verified()||$this->migrationMaterial($u,$after)!==$material){self::corrupt();}
            $l=$this->ledger($u,$subject);if($l->checkpoint()!==$current['checkpoint']||$l->read($this->id($subject))!==$current['row']){self::corrupt();}
            $data=$current['data'];unset($data['migration'],$data['revocation'],$data['restoration']);$data['format']=6;$data['origin']='revoked';$data['generation']=bin2hex(random_bytes(16));$data['revocation']=['operation'=>$context['operation'],'context'=>hash('sha256',json_encode($context,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)),'revoked_at'=>$u->now()];
            $l->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$current['row']['retire_at'],$current['row']['revision']);
            $saved=$this->managementState($u,$subject);if($saved['record']->fingerprint()!==$after->fingerprint()){self::corrupt();}return $saved;
        };
        return new FactorRevocation($d[0],$d[1],$d[2],$d[3],$d[4],$d[6],$fence,$facts,$mutate,$authority,$budgets,$approval,$audit,$events,$d[9],$d[10]);
    }
    /** Independent restoration accepts only retired/revoked directories and a proven different slot. */
    public function restoration(LocalEpochFence $fence,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events):FactorRestoration
    {
        $d=($this->dependencies)();if(!$d[5] instanceof FactorMigrationRepository||!$d[6]->registeredWith($d[0])||!$d[6]->boundTo($fence)||($d[11]!==null&&$d[11]->binding()!==$fence->binding())){throw new ConfigurationException('Restoration requires the exact registered workers and host material-preserving CAS.','configuration.factor_restoration');}
        $facts=function(SqlTransaction $u,string $subject):array{return $this->managementState($u,$subject);};
        $activate=function(SqlTransaction $u,array $expected,array $context)use($d,$fence):array{
            $subject=$expected['slot']->subject();$current=$this->managementCurrent($u,$subject,$expected);$before=$current['record'];
            if(!$current['retired']||$before===null||$before->status()!=='active'||!$before->verified()||!$before->account()->enabled()){throw new SecurityException('Restore only a current active verified account with a retained retirement marker.','account.restoration_changed');}
            $physical=$u->invoke([$d[6],'migrationSnapshotClosed'],[$fence,$context['slot_scope'],$context['slot_subject']],'account.factor_store');if($physical['factor_id']!==$context['slot_factor']||$physical['digest']!==$context['physical']){self::corrupt();}
            $material=$this->migrationMaterial($u,$before);$after=$u->invoke([$d[5],'setMfa'],[$before,true],'account.repository');
            if(!$after instanceof AccountRecord||$after->account()->scope()!==$before->account()->scope()||$after->account()->subject()!==$subject||!$after->account()->mfaRequired()||$after->account()->version()===$before->account()->version()||!$after->address()->equals($before->address())||$after->addressVersion()!==$before->addressVersion()||$after->account()->roles()!==$before->account()->roles()||$after->status()!==$before->status()||$after->verified()!==$before->verified()||$this->migrationMaterial($u,$after)!==$material){self::corrupt();}
            $l=$this->ledger($u,$subject);if($l->checkpoint()!==$current['checkpoint']||$l->read($this->id($subject))!==$current['row']){self::corrupt();}
            $data=['format'=>7,'purpose'=>'managed_factor','subject'=>$subject,'origin'=>'restored','slot_scope'=>$context['slot_scope'],'slot_subject'=>$context['slot_subject'],'factor_id'=>$context['slot_factor'],'generation'=>bin2hex(random_bytes(16)),'restoration'=>['operation'=>$context['operation'],'context'=>hash('sha256',json_encode($context,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)),'restored_at'=>$u->now()]];
            $l->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$current['row']['retire_at'],$current['row']['revision']);$saved=$this->managementState($u,$subject);if($saved['record']->fingerprint()!==$after->fingerprint()){self::corrupt();}return $saved;
        };
        return new FactorRestoration($d[0],$d[1],$d[2],$d[3],$d[4],$d[6],$fence,$facts,$activate,$authority,$budgets,$approval,$audit,$events,$d[9],$d[10]);
    }
    private function migrationMaterial(SqlTransaction $u,AccountRecord $record):string
    {
        $d=($this->dependencies)();$value=$u->invoke([$d[5],'migrationMaterialBinding'],[$record],'account.repository');if(!is_string($value)||!preg_match('/\A[a-f0-9]{64}\z/D',$value)){self::corrupt();}return $value;
    }
    /** SQL-only migration facts. Normal login and management reject the migrating marker. */
    private function migrationFacts(SqlTransaction $u,string $subject,?string $operation):array
    {
        self::label($subject);$this->guard($u,'migrate','before',null,$subject);$l=$this->ledger($u,$subject);$root=$l->checkpointIfInitialized();$row=$root===null?null:$l->read($this->id($subject));
        if(($root!==null&&$root['entries']!==($row===null?0:1))){self::corrupt();}$data=$row===null?null:$this->data($row,$subject);
        if($data!==null){
            if(in_array($data['origin'],['migrating','migrated'],true)){if($operation===null||$data['migration']!==$operation){throw new SecurityException('Resolve the exact registered migration first.','account.migration_busy');}}
            elseif(!in_array($data['origin'],['none','legacy','disabled'],true)){throw new SecurityException('Use independent recovery for non-legacy factor pointers.','account.migration_ineligible');}
            if($data['factor_id']!==''&&($data['slot_scope']!==($this->dependencies)()[2]||$data['slot_subject']!==$subject)){throw new SecurityException('Migrate only the exact original legacy slot.','account.migration_ineligible');}
        }
        $record=$this->account($u,$subject);$identity=$this->managementIdentity($u,$record);$credential=$this->managementCredential($u,$record);$material=$this->migrationMaterial($u,$record);if($identity===null){self::corrupt();}
        $account=hash('sha256',json_encode(['SoSecurity.Account.MigrationAccount.1',$record->fingerprint(),$identity->fingerprint(),$credential,$material]));$stamp=hash('sha256',json_encode(['SoSecurity.Account.MigrationFacts.1',$account,$row,$root]));
        $this->guard($u,'migrate','current',$record,$subject);$fresh=$this->account($u,$subject);$id=$this->managementIdentity($u,$fresh);$cred=$this->managementCredential($u,$fresh);$mat=$this->migrationMaterial($u,$fresh);
        if($id===null||$record->fingerprint()!==$fresh->fingerprint()||$identity->fingerprint()!==$id->fingerprint()||$credential!==$cred||$material!==$mat||$l->checkpointIfInitialized()!==$root||($root!==null&&$l->read($this->id($subject))!==$row)){self::corrupt();}
        return ['record'=>$record,'identity'=>$identity,'material'=>$material,'account_stamp'=>$account,'stamp'=>$stamp,'row'=>$row,'checkpoint'=>$root,'data'=>$data];
    }
    /** Formal migration is a distinct strongly approved workflow, never a login fallback. */
    public function migration(TotpFactors $legacy,LocalEpochFence $fence,callable $authority,callable $budgets,callable $approval,callable $stopped,callable $audit,callable $events):FactorMigration
    {
        $d=($this->dependencies)();if(!$d[5] instanceof FactorMigrationRepository||!$d[6]->migratesFrom($legacy)||!$d[6]->boundTo($fence)||$d[11]===null||$d[11]->binding()!==$fence->binding()){throw new ConfigurationException('Migration requires the exact managed source, repository and registered worker authority.','configuration.factor_migration');}
        $facts=function(SqlTransaction $u,string $subject,?string $operation=null):array{return $this->migrationFacts($u,$subject,$operation);};
        $write=function(SqlTransaction $u,array $before,array $review,string $action,?array $old=null)use($facts,$d):array{
            $written=null;$subject=$review['subject'];$current=$facts($u,$subject,$action==='reserve'?null:$review['operation']);if($current['stamp']!==$before['stamp']){self::corrupt();}$l=$this->ledger($u,$subject);
            if($action==='reserve'){
                if($current['data']!==null&&in_array($current['data']['origin'],['migrating','migrated'],true)){throw new SecurityException('Do not reserve an existing migration again.','account.migration_busy');}
                if($current['checkpoint']===null){$l->initialize();}
                $enabled=$review['factor_id']!==null;$data=['format'=>4,'purpose'=>'managed_factor','subject'=>$subject,'origin'=>'migrating','slot_scope'=>$enabled?$d[2]:'','slot_subject'=>$enabled?$subject:'','factor_id'=>$review['factor_id']??'','generation'=>$review['generation'],'migration'=>$review['operation']];
                $l->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$u->now()+1209600,$current['row']['revision']??null);
            }elseif($action==='finish'){
                if($current['data']===null||$current['data']['format']!==4||$current['data']['generation']!==$review['generation']){self::corrupt();}
                $prior=$current['record'];$required=$review['factor_id']!==null;if(!$required&&$prior->account()->mfaRequired()){throw new SecurityException('Migration never clears an existing MFA requirement.','account.migration_ineligible');}
                $after=$u->invoke([$d[5],'setMfa'],[$prior,$required],'account.repository');
                if(!$after instanceof AccountRecord||$after->account()->scope()!==$prior->account()->scope()||$after->account()->subject()!==$subject||$after->account()->version()===$prior->account()->version()||$after->account()->mfaRequired()!==$required||$after->address()->value()!==$prior->address()->value()||$after->addressVersion()!==$prior->addressVersion()||$after->status()!==$prior->status()||$after->verified()!==$prior->verified()||$after->account()->roles()!==$prior->account()->roles()||$this->migrationMaterial($u,$after)!==$before['material']){self::corrupt();}
                $written=$after;$data=$current['data'];$data['format']=5;$data['origin']='migrated';$l->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$current['row']['retire_at'],$current['row']['revision']);
            }elseif($action==='cancel'){
                if($current['data']===null||$current['data']['format']!==4){self::corrupt();}
                if($old===null){$l->remove([$current['row']['record_id']=>$current['row']['revision']]);}
                else{$l->put($this->id($subject),hash('sha256',$subject),'budget',json_encode($old,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$current['row']['retire_at'],$current['row']['revision']);}
                return $facts($u,$subject,null);
            }else{throw new ConfigurationException('Use an explicit migration directory transition.','configuration.factor_migration');}
            $result=$facts($u,$subject,$review['operation']);if($written!==null&&$result['record']->fingerprint()!==$written->fingerprint()){self::corrupt();}return $result;
        };
        return new FactorMigration($d[0],$d[1],$d[2],$d[3],$d[4],$legacy,$d[6],$fence,$facts,$write,$authority,$budgets,$approval,$stopped,$audit,$events,$d[9],$d[10]);
    }
    public function __debugInfo():array {return ['factor_registry'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current managed factor configuration.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current managed factor configuration.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Factor registries are immutable.','configuration.immutable');}
}
