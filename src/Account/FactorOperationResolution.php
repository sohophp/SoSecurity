<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;

/** Resolve an unknown normal operation, never replay its effect or recovery-code output. */
final class FactorOperationResolution
{
    private $dependencies;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $keys,TotpFactors $managed,LocalEpochFence $fence,callable $decode,callable $facts,callable $advance,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events,Policy $policy,Clock $clock)
    {
        self::label($site);self::label($scope);self::id($epoch);
        if(!$managed->registeredWith($connection)||!$managed->boundTo($fence)||!$fence->matches($site,$scope,$epoch)){throw new ConfigurationException('Use the exact registered factor context.','configuration.factor_resolution');}
        new SqlTransaction($connection,$clock,$policy->ioMilliseconds());
        $this->dependencies=static function()use($connection,$site,$scope,$epoch,$keys,$managed,$fence,$decode,$facts,$advance,$authority,$budgets,$approval,$audit,$events,$policy,$clock):array{return [$connection,$site,$scope,$epoch,$keys,$managed,$fence,$decode,$facts,$advance,$authority,$budgets,$approval,$audit,$events,$policy,$clock];};
    }
    private function d():array{return ($this->dependencies)();}
    private function unit():SqlTransaction{$d=$this->d();return new SqlTransaction($d[0],$d[16],$d[15]->ioMilliseconds());}
    private function ledger(SqlTransaction $u):Ledger{$d=$this->d();return new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[15],2,$d[6]->binding());}
    private static function json(array $value):string{return json_encode($value,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    private static function label(string $value):void{Guard::label($value);if(preg_match('//u',$value)!==1){throw new ValidationException('Use bounded UTF-8 resolution labels.','account.resolution_input');}}
    private static function id(string $value):void{if(preg_match('/\A[a-f0-9]{64}\z/D',$value)!==1){throw new ValidationException('Use an exact operation identifier.','account.resolution_input');}}
    private function budget(SqlTransaction $u,string $phase,string $source,string $operation):void{$d=$this->d();if($u->invoke($d[11],['factor_operation_abandon',$phase,$source,$operation],'account.resolution_budget')!==true){throw new SecurityException('Resolution budget denied.','account.resolution_budget');}}
    private function guard(SqlTransaction $u,string $phase,?array $context):void
    {
        $d=$this->d();$d[5]->enlistWorkers($d[0]);$l=$this->ledger($u);$before=$l->checkpoint();
        if($u->invoke($d[10],['factor_operation_abandon',$phase,$d[2],$context],'account.resolution_authority')!==true){throw new SecurityException('Current resolution authority required.','account.resolution_denied');}
        if($l->checkpoint()!==$before){throw new StorageException('Resolution authority changed the history.','account.resolution_changed');}
    }
    private function approval(SqlTransaction $u,string $phase,array $context,array $proof):void{$d=$this->d();if($u->invoke($d[12],[$phase,$context,$proof],'account.resolution_approval')!==true){throw new SecurityException('Independent exact resolution approval required.','account.resolution_denied');}}
    private function requested(SqlTransaction $u,callable $body,string $phase,string $source,string $operation,?array $context=null,?callable $finish=null)
    {
        $rejected=null;$result=$u->run($body,function()use($u,$phase,$source,$operation,$context,&$rejected):bool{try{$this->budget($u,'public',$source,$operation);$this->guard($u,$phase,$context);return true;}catch(\Throwable $error){$rejected=$error;return false;}},$finish);if($rejected!==null){throw $rejected;}return $result;
    }
    private function validFacts($facts,string $subject):void
    {
        $d=$this->d();if(!is_array($facts)||!isset($facts['slot'],$facts['stamp'],$facts['row'],$facts['checkpoint'])||!array_key_exists('record',$facts)||!$facts['slot'] instanceof FactorSlot||$facts['slot']->subject()!==$subject||!is_string($facts['stamp'])||!preg_match('/\A[a-f0-9]{64}\z/D',$facts['stamp'])||!is_array($facts['row'])||!is_array($facts['checkpoint'])||($facts['record']!==null&&(!$facts['record'] instanceof AccountRecord||$facts['record']->account()->scope()!==$d[2]||$facts['record']->account()->subject()!==$subject))){throw new StorageException('Invalid current resolution account snapshot.','account.resolution_changed');}
    }
    private function advanced(array $before,$after,string $subject):void
    {
        $this->validFacts($after,$subject);$a=$before['record'];$b=$after['record'];
        if($after['row']!==$before['row']||$after['checkpoint']!==$before['checkpoint']||$after['slot']->binding()!==$before['slot']->binding()){throw new StorageException('Resolution CAS changed the factor directory.','account.resolution_changed');}
        if($a===null||$a->status()!=='active'||!$a->verified()){
            if($after['stamp']!==$before['stamp']||($a===null?$b!==null:($b===null||$b->fingerprint()!==$a->fingerprint()))){throw new StorageException('Resolution changed an inactive identity.','account.resolution_changed');}return;
        }
        if($b===null||$b->account()->version()===$a->account()->version()||$after['stamp']===$before['stamp']||$b->account()->mfaRequired()!==$a->account()->mfaRequired()||$b->account()->roles()!==$a->account()->roles()||!$b->address()->equals($a->address())||$b->addressVersion()!==$a->addressVersion()||$b->status()!==$a->status()||$b->verified()!==$a->verified()){throw new StorageException('Resolution must revoke active credentials and preserve account data.','account.resolution_changed');}
    }
    private function frame(SqlTransaction $u,string $operation,bool $prepared=true):array
    {
        $d=$this->d();$l=$this->ledger($u);$root=$l->checkpoint();$row=$l->read($operation);
        if($row===null){throw new SecurityException('A retained normal operation is required.','account.resolution_changed');}
        $body=$u->invoke($d[7],[$row],'account.resolution_corrupt');
        if($body['purpose']!=='factor_operation'||($prepared&&$body['state']!=='prepared')){throw new SecurityException('Only an unresolved normal operation may be abandoned.','account.resolution_changed');}
        $facts=$u->invoke($d[8],[$u,$body['review']['subject'],false],'account.resolution_directory');$this->validFacts($facts,$body['review']['subject']);
        if($l->checkpoint()!==$root||$l->read($operation)!==$row){throw new StorageException('Resolution inspection changed.','account.resolution_changed');}
        $stamp=hash('sha256',self::json([Ledger::digest($root),$row,$facts['stamp']]));return ['root'=>$root,'row'=>$row,'body'=>$body,'facts'=>$facts,'stamp'=>$stamp];
    }
    private function same(SqlTransaction $u,array $context):array
    {
        $f=$this->frame($u,$context['operation']);if($f['stamp']!==$context['state']||$f['body']['review']['subject']!==$context['subject']||$f['body']['review']['action']!==$context['action']){throw new StorageException('Resolution review is stale.','account.resolution_changed');}return $f;
    }
    private function deadline(SqlTransaction $u,array $v):void{if($u->now()<$v['issued']||$u->now()>=$v['expires']){throw new SecurityException('Resolution review expired.','account.resolution_expired');}}
    private function context(SqlTransaction $u,array $f,string $nonce):array
    {
        $d=$this->d();$v=['format'=>1,'purpose'=>'factor_operation_abandon','site'=>$d[1],'scope'=>$d[2],'epoch'=>$d[3],'authority'=>$d[6]->binding(),'operation'=>$f['row']['record_id'],'subject'=>$f['body']['review']['subject'],'action'=>$f['body']['review']['action'],'state'=>$f['stamp'],'issued'=>$u->now(),'expires'=>$u->now()+min(300,$d[15]->lifetime('recover_account')),'nonce'=>$nonce,'key'=>$d[4]->currentId()];$v['seal']=bin2hex($d[4]->sign('SoSecurity.Account.OperationResolution.Review.1.'.self::json($v)));return $v;
    }
    private function input(array $v):array
    {
        $fields=['format','purpose','site','scope','epoch','authority','operation','subject','action','state','issued','expires','nonce','key','seal'];$keys=array_keys($v);sort($keys);$wanted=$fields;sort($wanted);
        if($keys!==$wanted||$v['format']!==1||$v['purpose']!=='factor_operation_abandon'||!is_int($v['issued'])||!is_int($v['expires'])||$v['issued']<0||$v['expires']<=$v['issued']||$v['expires']-$v['issued']>300||!in_array($v['action'],['disable','regenerate','reencrypt'],true)){throw new ValidationException('Use an exact signed abandonment review.','account.resolution_input');}
        foreach(['site','scope','subject'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid resolution labels.','account.resolution_input');}self::label($v[$key]);}
        foreach(['epoch','authority','operation','state','nonce','seal'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid resolution identifier.','account.resolution_input');}self::id($v[$key]);}
        if(!is_string($v['key'])||preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v['key'])!==1){throw new ValidationException('Invalid resolution key.','account.resolution_input');}
        $ordered=[];foreach($fields as $key){$ordered[$key]=$v[$key];}$v=$ordered;$seal=$v['seal'];unset($v['seal']);$d=$this->d();
        if($v['site']!==$d[1]||$v['scope']!==$d[2]||$v['epoch']!==$d[3]||$v['authority']!==$d[6]->binding()||!$d[4]->verify($v['key'],'SoSecurity.Account.OperationResolution.Review.1.'.self::json($v),hex2bin($seal))){throw new SecurityException('Resolution review cannot be authenticated.','account.resolution_denied');}return $v+['seal'=>$seal];
    }
    private static function proof(array $proof):void{$keys=array_keys($proof);sort($keys);if($keys!==['code','type']||$proof['type']!=='approved'||!is_string($proof['code'])||$proof['code']===''||strlen($proof['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$proof['code'])){throw new ValidationException('Use bounded independent resolution approval.','account.resolution_input');}}
    public function review(string $operation,string $source):array{return $this->reviewUsing($operation,$source,false);}
    public function reviewClosed(string $operation,string $source):array{return $this->reviewUsing($operation,$source,true);}
    private function reviewUsing(string $operation,string $source,bool $closed):array
    {
        self::id($operation);self::label($source);$nonce=bin2hex(random_bytes(32));$retention=$this->d()[15]->lifetime('account_activated');$d=$this->d();$method=$closed?'closedWork':'work';
        return $d[6]->$method(function()use($operation,$source,$nonce,$retention):array{$u=$this->unit();return $this->requested($u,function()use($u,$operation,$nonce,$retention):array{$f=$this->frame($u,$operation);$v=$this->context($u,$f,$nonce);return ['context'=>$v,'original_state'=>$f['body']['state'],'retire_at'=>$f['row']['retire_at'],'decision_retention_seconds'=>$retention,'revokes_active_credentials'=>true,'closes_worker_authority'=>true];},'review',$source,$operation,null,function(array $result)use($u,$source):void{$v=$result['context'];$this->budget($u,'final',$source,$v['operation']);$this->guard($u,'review_return',$v);$this->deadline($u,$v);$this->same($u,$v);});});
    }
    private function check(SqlTransaction $u,array $v,string $source,array $proof,string $phase):array
    {
        $this->budget($u,'final',$source,$v['operation']);$this->approval($u,$phase,$v,$proof);$this->guard($u,$phase,$v);$this->deadline($u,$v);return $this->same($u,$v);
    }
    private function verify(array $v,string $source,array $proof):void
    {
        $u=$this->unit();$this->requested($u,function()use($u,$v,$source,$proof):void{$this->check($u,$v,$source,$proof,'inspect');},'inspect',$source,$v['operation'],$v);
        $d=$this->d();$deadline=new Deadline($d[15]->ioMilliseconds());$before=$d[16]->now();try{$ok=call_user_func($d[12],'verify',$v,$proof);}catch(\Throwable $error){throw new DependencyException('Independent resolution approval unavailable.','account.resolution_approval');}$deadline->check('account.resolution_expired');$now=$d[16]->now();if($now<$before||$now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Resolution approval expired.','account.resolution_expired');}if($ok!==true){throw new SecurityException('Independent exact resolution approval required.','account.resolution_denied');}
    }
    public function abandon(array $context,string $source,array $proof):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);$d=$this->d();$d[6]->work(function()use($v,$source,$proof):void{$this->verify($v,$source,$proof);});$closing=false;
        try{return $d[6]->drain(function()use($v,$source,$proof):array{return $this->apply($v,$source,$proof);},function()use($v,$source,$proof,&$closing):bool{$u=$this->unit();$u->run(function()use($u,$v,$source,$proof):void{$this->check($u,$v,$source,$proof,'authorize');});$closing=true;return true;});}
        catch(\Throwable $error){if($closing){throw new StorageException('Resolution completion is unknown; inspect SQL and the independent closed authority.','account.completion_unknown',$error);}throw $error;}
    }
    public function abandonClosed(array $context,string $source,array $proof):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);$d=$this->d();$attempt=false;
        try{return $d[6]->closedWork(function()use($v,$source,$proof,&$attempt):array{$this->verify($v,$source,$proof);$attempt=true;return $this->apply($v,$source,$proof);});}
        catch(\Throwable $error){if($attempt){throw new StorageException('Resolution completion is unknown; inspect the retained decision and closed authority.','account.completion_unknown',$error);}throw $error;}
    }
    private function verifyResult(SqlTransaction $u,array $v,string $source,array $proof,array $result,string $phase):void
    {
        $this->budget($u,'final',$source,$v['operation']);$this->approval($u,$phase,$v,$proof);$this->guard($u,$phase,$v);$this->deadline($u,$v);$l=$this->ledger($u);$d=$this->d();$facts=$u->invoke($d[8],[$u,$v['subject'],false],'account.resolution_directory');
        if($l->checkpoint()!==$result['root']||$l->read($v['operation'])!==$result['row']||$facts['stamp']!==$result['facts']['stamp']){throw new StorageException('Resolution changed after its decision.','account.resolution_changed');}
    }
    private function apply(array $v,string $source,array $proof):array
    {
        $d=$this->d();$d[6]->closedWork(static function():void{});$u=$this->unit();$result=$this->requested($u,function()use($d,$u,$v,$source,$proof):array{
            $f=$this->check($u,$v,$source,$proof,'current');$after=$u->invoke($d[9],[$u,$f['facts']],'account.resolution_directory');$this->advanced($f['facts'],$after,$v['subject']);$l=$this->ledger($u);if($l->checkpoint()!==$f['root']||$l->read($v['operation'])!==$f['row']){throw new StorageException('Account CAS changed the reviewed operation history.','account.resolution_changed');}$resolvedAt=$u->now();$body=$f['body'];$body['format']=2;$body['state']='abandoned';$body['after']=$after['stamp'];$body['resolution']=['purpose'=>'factor_operation_abandonment','decision'=>$v['nonce'],'context'=>hash('sha256',self::json($v)),'resolved_at'=>$resolvedAt,'retain_until'=>$resolvedAt+$d[15]->lifetime('account_activated')];$l=$this->ledger($u);$row=$l->put($v['operation'],$f['row']['owner'],'recover',self::json($body),$f['row']['retire_at'],$f['row']['revision']);$root=$l->checkpoint();
            if($u->invoke($d[13],[$v,$f['facts'],$after],'account.resolution_audit')!==true||$u->invoke($d[14],['factor_management_abandoned',$v,$f['facts'],$after],'account.resolution_event')!==true){throw new StorageException('Same-PDO resolution audit and notification required.','account.resolution_audit');}
            return ['row'=>$row,'root'=>$root,'facts'=>$after,'result'=>['operation'=>$v['operation'],'decision'=>$v['nonce'],'abandoned'=>true,'original_outcome'=>'unknown','retain_until'=>$body['resolution']['retain_until']]];
        },'current',$source,$v['operation'],$v,function(array $r)use($u,$v,$source,$proof):void{$this->verifyResult($u,$v,$source,$proof,$r,'commit');});
        $finish=$this->unit();$finish->run(function()use($finish,$v,$source,$proof,$result):void{$this->verifyResult($finish,$v,$source,$proof,$result,'return');});return $result['result'];
    }
    /** Borrow an already-held exact closed EX context; return retained metadata, never codes. */
    public function inspectClosed(string $operation,string $source):array
    {
        self::id($operation);self::label($source);$d=$this->d();return $d[6]->closedWork(function()use($operation,$source):array{$u=$this->unit();$f=$this->requested($u,function()use($u,$operation):array{return $this->frame($u,$operation,false);},'inspect',$source,$operation,null,function(array $f)use($u,$source):void{$preview=['operation'=>$f['row']['record_id'],'subject'=>$f['body']['review']['subject'],'action'=>$f['body']['review']['action']];$this->budget($u,'final',$source,$preview['operation']);$this->guard($u,'inspect_return',$preview);$fresh=$this->frame($u,$preview['operation'],false);if($fresh['stamp']!==$f['stamp']){throw new StorageException('Resolution inspection changed.','account.resolution_changed');}});return ['operation'=>$operation,'state'=>$f['body']['state'],'resolution'=>$f['body']['resolution']??null];});
    }
    public function __debugInfo():array{return ['factor_operation_resolution'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload current resolution dependencies.','configuration.factor_resolution');}
    public function __wakeup():void{throw new ConfigurationException('Reload current resolution dependencies.','configuration.factor_resolution');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Resolution services are immutable.','configuration.immutable');}
}
