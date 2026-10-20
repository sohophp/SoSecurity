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

/** Independently approved loss response. Keep MFA required and block login until independent restoration. */
final class FactorRevocation
{
    private $dependencies;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $keys,TotpFactors $factors,LocalEpochFence $fence,callable $facts,callable $mutate,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events,Policy $policy,Clock $clock)
    {
        self::label($site);self::label($scope);self::id($epoch);
        if(!$factors->registeredWith($connection)||!$factors->boundTo($fence)||!$fence->matches($site,$scope,$epoch)){throw new ConfigurationException('Use the exact registered revocation context.','configuration.factor_revocation');}
        new SqlTransaction($connection,$clock,$policy->ioMilliseconds());
        $this->dependencies=static function()use($connection,$site,$scope,$epoch,$keys,$factors,$fence,$facts,$mutate,$authority,$budgets,$approval,$audit,$events,$policy,$clock):array{return [$connection,$site,$scope,$epoch,$keys,$factors,$fence,$facts,$mutate,$authority,$budgets,$approval,$audit,$events,$policy,$clock];};
    }
    private function d():array{return ($this->dependencies)();}
    private function unit():SqlTransaction{$d=$this->d();return new SqlTransaction($d[0],$d[15],$d[14]->ioMilliseconds());}
    private function workers(SqlTransaction $u):Ledger{$d=$this->d();return new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[14],2,$d[6]->binding());}
    private static function json(array $v):string{return json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    private static function label(string $v):void{try{Guard::label($v);}catch(ConfigurationException $error){throw new ValidationException('Use bounded revocation labels.','account.revocation_input',$error);}if(preg_match('//u',$v)!==1){throw new ValidationException('Use bounded UTF-8 revocation labels.','account.revocation_input');}}
    private static function id(string $v):void{if(preg_match('/\A[a-f0-9]{64}\z/D',$v)!==1){throw new ValidationException('Use exact revocation identifiers.','account.revocation_input');}}
    private function budget(SqlTransaction $u,string $phase,string $source,string $operation,string $purpose):void{$d=$this->d();if($u->invoke($d[10],[$purpose,$phase,$source,$operation],'account.revocation_budget')!==true){throw new SecurityException('Revocation budget denied.','account.revocation_budget');}}
    private function guard(SqlTransaction $u,string $phase,?array $v):void
    {
        $d=$this->d();$d[5]->enlistWorkers($d[0]);$l=$this->workers($u);$root=$l->checkpoint();
        if($u->invoke($d[9],[$v['purpose']??'factor_privileged_revoke',$phase,$d[2],$v],'account.revocation_authority')!==true){throw new SecurityException('Current independent revocation authority required.','account.revocation_denied');}
        if($l->checkpoint()!==$root){throw new StorageException('Revocation authority changed registered history.','account.revocation_changed');}
    }
    private function requested(SqlTransaction $u,callable $body,string $phase,string $source,string $operation,string $purpose,?array $v=null,?callable $finish=null)
    {
        $rejected=null;$result=$u->run($body,function()use($u,$phase,$source,$operation,$purpose,$v,&$rejected):bool{try{$this->budget($u,'public',$source,$operation,$purpose);$this->guard($u,$phase,$v);return true;}catch(\Throwable $error){$rejected=$error;return false;}},$finish);if($rejected!==null){throw $rejected;}return $result;
    }
    private function frame(SqlTransaction $u,string $subject):array
    {
        $d=$this->d();$l=$this->workers($u);$root=$l->checkpoint();$f=$u->invoke($d[7],[$u,$subject],'account.revocation_directory');
        if(!is_array($f)||!isset($f['slot'],$f['stamp'],$f['row'],$f['checkpoint'],$f['data'])||!$f['slot'] instanceof FactorSlot||$f['slot']->subject()!==$subject||!is_string($f['stamp'])||!preg_match('/\A[a-f0-9]{64}\z/D',$f['stamp'])||!array_key_exists('record',$f)||!is_bool($f['retired']??null)||$l->checkpoint()!==$root){throw new StorageException('Revocation directory snapshot changed.','account.revocation_changed');}
        return ['facts'=>$f,'workers'=>$root,'state'=>hash('sha256',self::json([$root,$f['row'],$f['checkpoint'],$f['stamp']]))];
    }
    private function eligible(array $f,bool $cleanup):void
    {
        if($cleanup){if(($f['data']['origin']??null)!=='revoked'||!$f['retired']||!$f['slot']->enabled()){throw new SecurityException('Use exact retained privileged revocation metadata.','account.revocation_changed');}return;}
        $r=$f['record'];if(!$r instanceof AccountRecord||$r->status()!=='active'||!$r->verified()||!$r->account()->enabled()||!$r->account()->mfaRequired()||$f['retired']||!$f['slot']->enabled()){throw new SecurityException('Current active MFA account required for privileged revocation.','account.revocation_changed');}
    }
    private function deadline(SqlTransaction $u,array $v):void{if($u->now()<$v['issued']||$u->now()>=$v['expires']){throw new SecurityException('Revocation review expired.','account.revocation_expired');}}
    private function input(array $v):array
    {
        $fields=['format','purpose','effect','site','scope','epoch','authority','subject','operation','state','issued','expires','key','seal'];$keys=array_keys($v);sort($keys);$expected=$fields;sort($expected);
        if($keys!==$expected||$v['format']!==1||!in_array($v['purpose'],['factor_privileged_revoke','factor_privileged_cleanup'],true)||$v['effect']!=='block_mfa_login'||!is_int($v['issued'])||!is_int($v['expires'])||$v['issued']<0||$v['expires']<=$v['issued']||$v['expires']-$v['issued']>300){throw new ValidationException('Use the exact signed revocation review.','account.revocation_input');}
        foreach(['site','scope','subject'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid revocation labels.','account.revocation_input');}self::label($v[$key]);}
        foreach(['epoch','authority','operation','state','seal'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid revocation identifiers.','account.revocation_input');}self::id($v[$key]);}
        if(!is_string($v['key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v['key'])){throw new ValidationException('Invalid revocation key.','account.revocation_input');}
        $ordered=[];foreach($fields as $key){$ordered[$key]=$v[$key];}$v=$ordered;$seal=$v['seal'];unset($v['seal']);$d=$this->d();
        if($v['site']!==$d[1]||$v['scope']!==$d[2]||$v['epoch']!==$d[3]||$v['authority']!==$d[6]->binding()||!$d[4]->verify($v['key'],'SoSecurity.Account.PrivilegedRevocation.Review.1.'.self::json($v),hex2bin($seal))){throw new SecurityException('Revocation context cannot be authenticated.','account.revocation_denied');}return $v+['seal'=>$seal];
    }
    private static function proof(array $proof):void{$keys=array_keys($proof);sort($keys);if($keys!==['code','type']||$proof['type']!=='approved'||!is_string($proof['code'])||$proof['code']===''||strlen($proof['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$proof['code'])){throw new ValidationException('Use independent bounded revocation approval.','account.revocation_input');}}
    public function review(string $subject,string $source,bool $cleanup=false):array{return $this->reviewUsing($subject,$source,$cleanup,false);}
    public function reviewClosed(string $subject,string $source,bool $cleanup=false):array{return $this->reviewUsing($subject,$source,$cleanup,true);}
    private function reviewUsing(string $subject,string $source,bool $cleanup,bool $closed):array
    {
        self::label($subject);self::label($source);$d=$this->d();$method=$closed?'closedWork':'work';$operation=bin2hex(random_bytes(32));$purpose=$cleanup?'factor_privileged_cleanup':'factor_privileged_revoke';
        return $d[6]->$method(function()use($subject,$source,$cleanup,$operation,$purpose,$d):array{$u=$this->unit();return $this->requested($u,function()use($u,$subject,$cleanup,$operation,$purpose,$d):array{$s=$this->frame($u,$subject);$this->eligible($s['facts'],$cleanup);$v=['format'=>1,'purpose'=>$purpose,'effect'=>'block_mfa_login','site'=>$d[1],'scope'=>$d[2],'epoch'=>$d[3],'authority'=>$d[6]->binding(),'subject'=>$subject,'operation'=>$operation,'state'=>$s['state'],'issued'=>$u->now(),'expires'=>$u->now()+min(300,$d[14]->lifetime('recover_account')),'key'=>$d[4]->currentId()];$v['seal']=bin2hex($d[4]->sign('SoSecurity.Account.PrivilegedRevocation.Review.1.'.self::json($v)));return ['context'=>$v,'closes_worker_authority'=>true,'mfa_required'=>true,'requires_independent_restoration'=>true,'cleanup_only'=>$cleanup];},'review',$source,$operation,$purpose,['purpose'=>$purpose,'subject'=>$subject,'operation'=>$operation],function(array $r)use($u,$source,$operation,$purpose):void{$v=$r['context'];$this->budget($u,'final',$source,$operation,$purpose);$this->guard($u,'review_return',$v);$this->same($u,$v);});});
    }
    private function same(SqlTransaction $u,array $v):array
    {
        $this->deadline($u,$v);$s=$this->frame($u,$v['subject']);$this->eligible($s['facts'],$v['purpose']==='factor_privileged_cleanup');if($s['state']!==$v['state']){throw new StorageException('Revocation review is stale.','account.revocation_changed');}return $s;
    }
    private function approved(SqlTransaction $u,string $phase,array $v,array $proof):void{$d=$this->d();if($u->invoke($d[11],[$phase,$v,$proof],'account.revocation_approval')!==true){throw new SecurityException('Exact independent revocation approval required.','account.revocation_denied');}}
    private function check(SqlTransaction $u,string $phase,array $v,string $source,array $proof):array{$this->budget($u,'final',$source,$v['operation'],$v['purpose']);$this->approved($u,$phase,$v,$proof);$this->guard($u,$phase,$v);return $this->same($u,$v);}
    private function verify(array $v,string $source,array $proof):void
    {
        $u=$this->unit();$this->requested($u,function()use($u,$v,$source,$proof):void{$this->check($u,'inspect',$v,$source,$proof);},'inspect',$source,$v['operation'],$v['purpose'],$v);
        $d=$this->d();$deadline=new Deadline($d[14]->ioMilliseconds());$before=$d[15]->now();try{$ok=call_user_func($d[11],'verify',$v,$proof);}catch(\Throwable $error){throw new DependencyException('Independent revocation approval unavailable.','account.revocation_approval',$error);}$deadline->check('account.revocation_expired');$now=$d[15]->now();if($now<$before||$now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Revocation approval expired.','account.revocation_expired');}if($ok!==true){throw new SecurityException('Exact independent revocation approval required.','account.revocation_denied');}
    }
    public function execute(array $context,string $source,array $proof):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);$d=$this->d();$d[6]->work(function()use($v,$source,$proof):void{$this->verify($v,$source,$proof);});$closing=false;
        try{return $d[6]->drain(function()use($v,$source,$proof):array{return $this->apply($v,$source,$proof);},function()use($v,$source,$proof,&$closing):bool{$u=$this->unit();$u->run(function()use($u,$v,$source,$proof):void{$this->check($u,'authorize',$v,$source,$proof);});$closing=true;return true;});}catch(\Throwable $error){if($closing){throw new StorageException('Revocation completion is unknown; inspect the retained directory under closed authority.','account.completion_unknown',$error);}throw $error;}
    }
    public function executeClosed(array $context,string $source,array $proof):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);$d=$this->d();$attempt=false;
        try{return $d[6]->closedWork(function()use($v,$source,$proof,&$attempt):array{$this->verify($v,$source,$proof);$attempt=true;return $this->apply($v,$source,$proof);});}catch(\Throwable $error){if($attempt){throw new StorageException('Closed revocation completion is unknown.','account.completion_unknown',$error);}throw $error;}
    }
    private function unchanged(SqlTransaction $u,array $expected,string $subject):void{if($this->frame($u,$subject)['state']!==$expected['state']){throw new StorageException('Revocation changed after its decision.','account.revocation_changed');}}
    private function resultCheck(SqlTransaction $u,string $phase,array $v,string $source,array $proof,array $saved):void{$this->budget($u,'final',$source,$v['operation'],$v['purpose']);$this->approved($u,$phase,$v,$proof);$this->guard($u,$phase,$v);$this->deadline($u,$v);$this->unchanged($u,$saved,$v['subject']);}
    private function apply(array $v,string $source,array $proof):array
    {
        $d=$this->d();$d[6]->closedWork(static function():void{});$u=$this->unit();$saved=$this->requested($u,function()use($u,$v,$source,$proof,$d):array{
            $before=$this->check($u,'current',$v,$source,$proof);if($v['purpose']==='factor_privileged_cleanup'){return $before;}
            $after=$u->invoke($d[8],[$u,$before['facts'],$v],'account.revocation_directory');$s=$this->frame($u,$v['subject']);$a=$before['facts'];$b=$s['facts'];$ar=$a['record'];$br=$b['record'];$this->eligible($b,true);
            if($after['stamp']!==$b['stamp']||$s['workers']!==$before['workers']||!$br instanceof AccountRecord||$br->account()->version()===$ar->account()->version()||!$br->account()->mfaRequired()||$br->account()->roles()!==$ar->account()->roles()||$br->status()!==$ar->status()||$br->verified()!==$ar->verified()||!$br->address()->equals($ar->address())||$br->addressVersion()!==$ar->addressVersion()||$b['slot']->slotScope()!==$a['slot']->slotScope()||$b['slot']->slotSubject()!==$a['slot']->slotSubject()||$b['slot']->factorId()!==$a['slot']->factorId()||$b['data']['revocation']['operation']!==$v['operation']||$b['data']['revocation']['context']!==hash('sha256',self::json($v))){throw new StorageException('Revocation must advance credentials and preserve account and exact old factor.','account.revocation_changed');}
            if($u->invoke($d[12],[$v,$a,$b],'account.revocation_audit')!==true||$u->invoke($d[13],['factor_privileged_revoked',$v,$a,$b],'account.revocation_event')!==true){throw new StorageException('Same-PDO revocation audit and notification required.','account.revocation_audit');}return $s;
        },'current',$source,$v['operation'],$v['purpose'],$v,function(array $s)use($u,$v,$source,$proof):void{$this->resultCheck($u,'commit',$v,$source,$proof,$s);});
        $u=$this->unit();$removed=$this->requested($u,function()use($u,$v,$source,$proof,$saved,$d):bool{$this->resultCheck($u,'delete',$v,$source,$proof,$saved);$slot=$saved['facts']['slot'];return $u->invoke([$d[5],'revokeGenerationClosed'],[$d[6],$slot->slotScope(),$slot->slotSubject(),$slot->factorId(),function()use($u,$v,$source,$proof,$saved):bool{$this->resultCheck($u,'delete_current',$v,$source,$proof,$saved);return true;}],'account.factor_store');},'cleanup',$source,$v['operation'],$v['purpose'],$v,function()use($u,$v,$source,$proof,$saved):void{$this->resultCheck($u,'return',$v,$source,$proof,$saved);});
        return ['operation'=>$saved['facts']['data']['revocation']['operation'],'revoked'=>true,'mfa_required'=>true,'login_blocked'=>true,'factor_removed'=>$removed,'requires_independent_restoration'=>true];
    }
    public function inspectClosed(string $subject,string $source):array
    {
        self::label($subject);self::label($source);$d=$this->d();return $d[6]->closedWork(function()use($subject,$source):array{$u=$this->unit();$s=$this->requested($u,function()use($u,$subject):array{return $this->frame($u,$subject);},'inspect',$source,hash('sha256',$subject),'factor_privileged_revoke',null,function(array $s)use($u,$subject,$source):void{$this->budget($u,'final',$source,hash('sha256',$subject),'factor_privileged_revoke');$this->guard($u,'inspect_return',null);$this->unchanged($u,$s,$subject);});return ['subject'=>$subject,'revoked'=>$s['facts']['data']['origin']==='revoked','revocation'=>$s['facts']['data']['revocation']??null,'mfa_required'=>$s['facts']['record']===null?null:$s['facts']['record']->account()->mfaRequired()];});
    }
    public function __debugInfo():array{return ['factor_revocation'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload current revocation dependencies.','configuration.factor_revocation');}
    public function __wakeup():void{throw new ConfigurationException('Reload current revocation dependencies.','configuration.factor_revocation');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Revocation services are immutable.','configuration.immutable');}
}
