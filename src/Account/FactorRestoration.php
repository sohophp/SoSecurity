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

/** Independent new-factor restoration. A retirement marker is never made authenticating without new proof and exact approval. */
final class FactorRestoration
{
    private $dependencies;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $keys,TotpFactors $factors,LocalEpochFence $fence,callable $facts,callable $activate,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events,Policy $policy,Clock $clock)
    {
        self::label($site);self::label($scope);self::id($epoch);
        if(!$factors->registeredWith($connection)||!$factors->boundTo($fence)||!$fence->matches($site,$scope,$epoch)){throw new ConfigurationException('Use the exact registered restoration context.','configuration.factor_restoration');}
        new SqlTransaction($connection,$clock,$policy->ioMilliseconds());
        $this->dependencies=static function()use($connection,$site,$scope,$epoch,$keys,$factors,$fence,$facts,$activate,$authority,$budgets,$approval,$audit,$events,$policy,$clock):array{return [$connection,$site,$scope,$epoch,$keys,$factors,$fence,$facts,$activate,$authority,$budgets,$approval,$audit,$events,$policy,$clock];};
    }
    private function d():array{return ($this->dependencies)();}
    private function unit():SqlTransaction{$d=$this->d();return new SqlTransaction($d[0],$d[15],$d[14]->ioMilliseconds());}
    private function ledger(SqlTransaction $u):Ledger{$d=$this->d();return new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[14],2,$d[6]->binding());}
    private static function json(array $v):string{return json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    private static function label(string $v):void{try{Guard::label($v);}catch(ConfigurationException $e){throw new ValidationException('Use bounded restoration labels.','account.restoration_input',$e);}if(preg_match('//u',$v)!==1){throw new ValidationException('Use UTF-8 restoration labels.','account.restoration_input');}}
    private static function id(string $v):void{if(!preg_match('/\A[a-f0-9]{64}\z/D',$v)){throw new ValidationException('Use exact restoration identifiers.','account.restoration_input');}}
    private static function effect(string $purpose):string
    {
        $effects=['factor_restoration_begin'=>'require_mfa_with_new_factor','factor_restoration_activate'=>'require_mfa_with_new_factor','factor_restoration_cancel'=>'retain_retirement','factor_restoration_clean'=>'retire_noncurrent_factor','factor_restoration_clean_previous'=>'retire_noncurrent_factor'];
        if(!isset($effects[$purpose])){throw new ValidationException('Use a specific restoration purpose.','account.restoration_input');}return $effects[$purpose];
    }
    private function input(array $v,bool $historical=false):array
    {
        $fields=['format','purpose','effect','site','scope','epoch','authority','subject','operation','state','slot_scope','slot_subject','slot_factor','physical','issued','expires','nonce','key','seal'];$keys=array_keys($v);sort($keys);$wanted=$fields;sort($wanted);
        if($keys!==$wanted||$v['format']!==1||!is_string($v['purpose'])||$v['effect']!==self::effect($v['purpose'])||!is_int($v['issued'])||!is_int($v['expires'])||$v['issued']<0||$v['expires']<=$v['issued']||$v['expires']-$v['issued']>300){throw new ValidationException('Use an exact signed restoration review.','account.restoration_input');}
        foreach(['site','scope','subject','slot_scope','slot_subject'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid restoration labels.','account.restoration_input');}self::label($v[$key]);}
        foreach(['epoch','authority','operation','state','nonce','seal'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid restoration identifiers.','account.restoration_input');}self::id($v[$key]);}
        if(!is_string($v['slot_factor'])||!preg_match('/\A[a-f0-9]{32}\z/D',$v['slot_factor'])||!is_string($v['physical'])||($v['physical']!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$v['physical']))||($v['purpose']==='factor_restoration_activate'&&$v['physical']==='')||!is_string($v['key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v['key'])){throw new ValidationException('Invalid restoration target or key.','account.restoration_input');}
        $d=$this->d();$expected='factor-restoration:'.hash('sha256',self::json([$d[1],$d[2],$d[3],$v['operation']]));if($v['slot_scope']!==$expected||$v['slot_subject']!==$v['operation']){throw new ValidationException('Use the reserved restoration slot.','account.restoration_input');}
        $ordered=[];foreach($fields as $key){$ordered[$key]=$v[$key];}$v=$ordered;$seal=$v['seal'];unset($v['seal']);
        if($v['site']!==$d[1]||$v['scope']!==$d[2]||$v['epoch']!==$d[3]||(!$historical&&($v['authority']!==$d[6]->binding()||!$d[4]->verify($v['key'],'SoSecurity.Account.FactorRestoration.Review.1.'.self::json($v),hex2bin($seal))))){throw new SecurityException('Restoration review cannot be authenticated.','account.restoration_denied');}return $v+['seal'=>$seal];
    }
    private static function proof(array $v):void{$keys=array_keys($v);sort($keys);if($keys!==['code','type']||$v['type']!=='approved'||!is_string($v['code'])||$v['code']===''||strlen($v['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$v['code'])){throw new ValidationException('Use bounded independent restoration approval.','account.restoration_input');}}
    private function budget(SqlTransaction $u,string $purpose,string $phase,string $source,string $operation):void{$d=$this->d();if($u->invoke($d[10],[$purpose,$phase,$source,$operation],'account.restoration_budget')!==true){throw new SecurityException('Restoration budget denied.','account.restoration_budget');}}
    private function guard(SqlTransaction $u,string $phase,array $v):void
    {
        $d=$this->d();$d[5]->enlistWorkers($d[0]);$l=$this->ledger($u);$root=$l->checkpoint();if($u->invoke($d[9],[$v['purpose'],$phase,$d[2],$v],'account.restoration_authority')!==true){throw new SecurityException('Current restoration authority required.','account.restoration_denied');}if($l->checkpoint()!==$root){throw new StorageException('Restoration authority changed workflow history.','account.restoration_changed');}
    }
    private function requested(SqlTransaction $u,callable $body,string $source,array $v,string $phase,?callable $finish=null)
    {
        $rejected=null;$r=$u->run($body,function()use($u,$source,$v,$phase,&$rejected):bool{try{$this->budget($u,$v['purpose'],'public',$source,$v['operation']);$this->guard($u,$phase,$v);return true;}catch(\Throwable $e){$rejected=$e;return false;}},$finish);if($rejected!==null){throw $rejected;}return $r;
    }
    /** @return never */
    private static function corrupt():void{throw new StorageException('Restoration history cannot be authenticated.','account.restoration_corrupt');}
    private function parse(array $row):array
    {
        $b=json_decode($row['payload'],true,8);$fields=['format','purpose','review','state','before','after','old','valid_until','attempts','proved_at','physical','decision','old_cleaned','retain_until'];
        if($row['kind']!=='recover'||!is_array($b)||array_keys($b)!==$fields||$b['format']!==1||$b['purpose']!=='factor_restoration'||!is_array($b['review'])||!in_array($b['state'],['preparing','pending','proven','activated','cancelled','cleaned'],true)){self::corrupt();}
        try{$v=$this->input($b['review'],true);}catch(\Throwable $e){self::corrupt();}
        if($v['purpose']!=='factor_restoration_begin'||$v['physical']!==''||$v['issued']>$row['created_at']||$row['created_at']>=$v['expires']||$b['valid_until']>$row['retire_at']||$v['operation']!==$row['record_id']||$row['owner']!==hash('sha256','SoSecurity.Account.Restoration.Owner.1.'.$v['subject'])||!is_string($b['before'])||!preg_match('/\A[a-f0-9]{64}\z/D',$b['before'])||!is_string($b['after'])||($b['after']!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$b['after']))||!is_int($b['valid_until'])||$b['valid_until']<=$row['created_at']||$b['valid_until']>$row['created_at']+$this->d()[14]->lifetime('recover_account')||!is_int($b['attempts'])||$b['attempts']<0||$b['attempts']>$this->d()[14]->maximumAttempts()||!is_int($b['proved_at'])||$b['proved_at']<0||!is_string($b['physical'])||($b['physical']!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$b['physical']))||!is_string($b['decision'])||($b['decision']!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$b['decision']))||!is_int($b['retain_until'])||$b['retain_until']<0||!is_bool($b['old_cleaned'])||!is_array($b['old'])||array_keys($b['old'])!==['scope','subject','factor']){self::corrupt();}
        foreach(['scope','subject','factor'] as $key){if(!is_string($b['old'][$key])){self::corrupt();}}
        if($b['old']['factor']===''){if($b['old']['scope']!==''||$b['old']['subject']!==''){self::corrupt();}}else{try{new FactorSlot($v['subject'],$b['before'],$b['old']['scope'],$b['old']['subject'],$b['old']['factor']);}catch(\Throwable $e){self::corrupt();}}
        if((in_array($b['state'],['proven','activated'],true)&&($b['physical']===''||$b['proved_at']<$row['created_at']||$b['proved_at']>=$b['valid_until']))||($b['state']==='activated'&&($b['after']===''||$b['decision']===''))||self::json($b)!==$row['payload']){self::corrupt();}return $b;
    }
    private function cursorId(string $subject):string{return hash('sha256','SoSecurity.Account.Restoration.Cursor.1.'.$subject);}
    private function owner(string $subject):string{return hash('sha256','SoSecurity.Account.Restoration.Owner.1.'.$subject);}
    private function cursorReference(?array $row,string $subject):?string
    {
        if($row===null){return null;}$v=json_decode($row['payload'],true,3);if($row['kind']!=='budget'||$row['record_id']!==$this->cursorId($subject)||$row['owner']!==$this->owner($subject)||!is_array($v)||array_keys($v)!==['format','purpose','subject','operation']||$v['format']!==1||$v['purpose']!=='factor_restoration_cursor'||$v['subject']!==$subject||!is_string($v['operation'])||!preg_match('/\A[a-f0-9]{64}\z/D',$v['operation'])||self::json($v)!==$row['payload']){self::corrupt();}return $v['operation'];
    }
    private function frame(SqlTransaction $u,string $subject,string $operation):array
    {
        $d=$this->d();$l=$this->ledger($u);$root=$l->checkpoint();$row=$l->read($operation);$body=$row===null?null:$this->parse($row);$cursor=$l->read($this->cursorId($subject));$this->cursorReference($cursor,$subject);
        if($body!==null&&$body['review']['subject']!==$subject){throw new SecurityException('Restoration belongs to another account.','account.restoration_changed');}
        $f=$u->invoke($d[7],[$u,$subject],'account.restoration_directory');if(!is_array($f)||!isset($f['slot'],$f['stamp'],$f['row'],$f['checkpoint'])||!is_array($f['row'])||!is_array($f['checkpoint'])||!is_array($f['data']??null)||!array_key_exists('record',$f)||!is_bool($f['retired']??null)||($f['record']!==null&&(!$f['record'] instanceof AccountRecord||$f['record']->account()->scope()!==$d[2]||$f['record']->account()->subject()!==$subject))||!$f['slot'] instanceof FactorSlot||$f['slot']->subject()!==$subject||!is_string($f['stamp'])||!preg_match('/\A[a-f0-9]{64}\z/D',$f['stamp'])||$l->checkpoint()!==$root||$l->read($operation)!==$row){throw new StorageException('Restoration target or history changed during inspection.','account.restoration_changed');}
        return ['facts'=>$f,'row'=>$row,'body'=>$body,'cursor'=>$cursor,'root'=>$root,'state'=>hash('sha256',self::json([$root,$row,$f['row'],$f['checkpoint'],$f['stamp']]))];
    }
    private function fromOperation(SqlTransaction $u,string $operation):array
    {
        $l=$this->ledger($u);$root=$l->checkpoint();$row=$l->read($operation);if($row===null){throw new SecurityException('A retained restoration intent is required.','account.restoration_changed');}$body=$this->parse($row);$s=$this->frame($u,$body['review']['subject'],$operation);if($s['root']!==$root||$s['row']!==$row){throw new StorageException('Restoration intent changed.','account.restoration_changed');}return $s;
    }
    private function eligible(array $s,string $purpose,SqlTransaction $u):void
    {
        $f=$s['facts'];$b=$s['body'];$r=$f['record'];
        if(in_array($purpose,['factor_restoration_begin','factor_restoration_activate','factor_restoration_prove'],true)){
            if(!$r instanceof AccountRecord||$r->status()!=='active'||!$r->verified()||!$r->account()->enabled()||!$f['retired']){throw new SecurityException('Restore only an active verified account with a retained retirement marker.','account.restoration_changed');}
            if($b!==null&&($b['before']!==$f['stamp']||$u->now()>=$b['valid_until'])){throw new SecurityException('Restoration target changed or expired.','account.restoration_changed');}
        }
        if($purpose==='factor_restoration_begin'&&$s['cursor']!==null){$old=$this->cursorReference($s['cursor'],$f['slot']->subject());$row=$this->ledger($u)->read($old);if($row===null){self::corrupt();}$prior=$this->parse($row);if(!in_array($prior['state'],['activated','cancelled','cleaned'],true)&&$prior['valid_until']>$u->now()){throw new SecurityException('Resolve the existing restoration first.','account.restoration_pending');}}
        if(in_array($purpose,['factor_restoration_prove','factor_restoration_activate'],true)&&$b!==null&&$this->cursorReference($s['cursor'],$f['slot']->subject())!==$b['review']['operation']){throw new SecurityException('A newer restoration superseded this intent.','account.restoration_changed');}
        if($purpose==='factor_restoration_begin'&&$b!==null){throw new SecurityException('A restoration preparation is never replayed.','account.restoration_replayed');}
        if($purpose==='factor_restoration_activate'&&($b===null||$b['state']!=='proven')){throw new SecurityException('A proven new factor is required.','account.restoration_unproven');}
        if($purpose==='factor_restoration_prove'&&($b===null||!in_array($b['state'],['pending','proven'],true))){throw new SecurityException('Restoration proof attempts are unavailable.','account.restoration_unproven');}
        if($purpose==='factor_restoration_cancel'&&($b===null||!in_array($b['state'],['preparing','pending','proven'],true))){throw new SecurityException('Only an unactivated restoration can be cancelled.','account.restoration_changed');}
        if($purpose==='factor_restoration_clean'&&($b===null||!in_array($b['state'],['cancelled','cleaned'],true))){throw new SecurityException('Cancel before cleaning the prepared slot.','account.restoration_changed');}
        if($purpose==='factor_restoration_clean_previous'&&($b===null||$b['state']!=='activated')){throw new SecurityException('Activate before cleaning only the previous slot.','account.restoration_changed');}
    }
    private function physical(SqlTransaction $u,array $v,bool $closed):array{$d=$this->d();return $u->invoke($closed?[$d[5],'migrationSnapshotClosed']:[$d[5],'migrationSnapshot'],$closed?[$d[6],$v['slot_scope'],$v['slot_subject']]:[$v['slot_scope'],$v['slot_subject']],'account.restoration_factor');}
    private function context(SqlTransaction $u,array $s,string $purpose,string $subject,string $operation,?array $target=null,string $physical=''):array
    {
        $d=$this->d();$v=['format'=>1,'purpose'=>$purpose,'effect'=>self::effect($purpose),'site'=>$d[1],'scope'=>$d[2],'epoch'=>$d[3],'authority'=>$d[6]->binding(),'subject'=>$subject,'operation'=>$operation,'state'=>$s['state'],'slot_scope'=>$target['slot_scope']??'factor-restoration:'.hash('sha256',self::json([$d[1],$d[2],$d[3],$operation])),'slot_subject'=>$operation,'slot_factor'=>$target['slot_factor']??bin2hex(random_bytes(16)),'physical'=>$physical,'issued'=>$u->now(),'expires'=>$u->now()+min(300,$d[14]->lifetime('recover_account')),'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[4]->currentId()];if($purpose==='factor_restoration_activate'){$v['expires']=min($v['expires'],$s['body']['valid_until']);}$v['seal']=bin2hex($d[4]->sign('SoSecurity.Account.FactorRestoration.Review.1.'.self::json($v)));return $v;
    }
    private function deadline(SqlTransaction $u,array $v):void{if($u->now()<$v['issued']||$u->now()>=$v['expires']){throw new SecurityException('Restoration review expired.','account.restoration_expired');}}
    private function same(SqlTransaction $u,array $v,bool $physical=false,bool $closed=false):array
    {
        $this->deadline($u,$v);$s=$this->frame($u,$v['subject'],$v['operation']);$this->eligible($s,$v['purpose'],$u);if($s['state']!==$v['state']){throw new StorageException('Restoration review is stale.','account.restoration_changed');}
        if($s['body']!==null){$target=$s['body']['review'];foreach(['slot_scope','slot_subject','slot_factor'] as $key){if($v[$key]!==$target[$key]){throw new StorageException('Restoration target changed.','account.restoration_changed');}}}
        if($physical){$p=$this->physical($u,$v,$closed);if($p['factor_id']!==$v['slot_factor']||$p['digest']!==$v['physical']||$s['body']['physical']!==$v['physical']){throw new StorageException('The proven restoration factor changed.','account.restoration_changed');}}return $s;
    }
    private function approved(SqlTransaction $u,string $phase,array $v,array $proof):void{$d=$this->d();if($u->invoke($d[11],[$phase,$v,$proof],'account.restoration_approval')!==true){throw new SecurityException('Independent exact restoration approval required.','account.restoration_denied');}}
    private function check(SqlTransaction $u,string $phase,array $v,string $source,array $proof,bool $physical=false,bool $closed=false):array{$this->budget($u,$v['purpose'],'final',$source,$v['operation']);$this->approved($u,$phase,$v,$proof);$this->guard($u,$phase,$v);return $this->same($u,$v,$physical,$closed);}
    private function verify(array $v,string $source,array $proof,bool $physical=false,bool $closed=false):void
    {
        $u=$this->unit();$this->requested($u,function()use($u,$v,$source,$proof,$physical,$closed):void{$this->check($u,'inspect',$v,$source,$proof,$physical,$closed);},$source,$v,'inspect');$d=$this->d();$deadline=new Deadline($d[14]->ioMilliseconds());$before=$d[15]->now();try{$ok=call_user_func($d[11],'verify',$v,$proof);}catch(\Throwable $e){throw new DependencyException('Independent restoration approval unavailable.','account.restoration_approval',$e);}$deadline->check('account.restoration_expired');$now=$d[15]->now();if($now<$before||$now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Restoration approval expired.','account.restoration_expired');}if($ok!==true){throw new SecurityException('Independent exact restoration approval required.','account.restoration_denied');}
    }
    private function audit(SqlTransaction $u,string $phase,array $v,array $before,array $after):void{$d=$this->d();if($u->invoke($d[12],[$phase,$v,$before,$after],'account.restoration_audit')!==true||$u->invoke($d[13],['factor_restoration_'.$phase,$v,$before,$after],'account.restoration_event')!==true){throw new StorageException('Same-PDO restoration audit and notification required.','account.restoration_audit');}}
    private function savedCheck(SqlTransaction $u,string $phase,array $v,string $source,array $expected,?array $proof=null):void
    {
        $this->budget($u,$v['purpose'],'final',$source,$v['operation']);if($proof!==null){$this->approved($u,$phase,$v,$proof);}$this->guard($u,$phase,$v);$s=$this->frame($u,$v['subject'],$v['operation']);if($s['state']!==$expected['state']){throw new StorageException('Restoration changed before completion.','account.restoration_changed');}if($v['purpose']==='factor_restoration_prove'){if($u->now()<$s['body']['review']['issued']||$u->now()>=$s['body']['valid_until']){throw new SecurityException('Restoration proof expired.','account.restoration_expired');}}elseif(isset($v['expires'])){$this->deadline($u,$v);}
    }
    public function review(string $subject,string $source):array
    {
        self::label($subject);self::label($source);$d=$this->d();$op=bin2hex(random_bytes(32));$pre=['purpose'=>'factor_restoration_begin','operation'=>$op,'subject'=>$subject];return $d[6]->work(function()use($subject,$source,$op,$pre):array{$u=$this->unit();return $this->requested($u,function()use($u,$subject,$op):array{$s=$this->frame($u,$subject,$op);$this->eligible($s,'factor_restoration_begin',$u);return $this->context($u,$s,'factor_restoration_begin',$subject,$op);},$source,$pre,'review',function(array $v)use($u,$source):void{$this->budget($u,$v['purpose'],'final',$source,$v['operation']);$this->guard($u,'review_return',$v);$this->same($u,$v);});});
    }
    public function begin(array $context,string $source,array $proof):FactorEnrollment
    {
        $v=$this->input($context);self::label($source);self::proof($proof);if($v['purpose']!=='factor_restoration_begin'){throw new ValidationException('Use a begin-specific restoration review.','account.restoration_input');}$d=$this->d();$attempt=false;return $this->outcomeWork('work',function()use($v,$source,$proof,$d,&$attempt):FactorEnrollment{
            $this->verify($v,$source,$proof);
            try{$u=$this->unit();$reserved=$this->requested($u,function()use($u,$v,$source,$proof,$d):array{$s=$this->check($u,'current',$v,$source,$proof);$slot=$s['facts']['slot'];$now=$u->now();$b=['format'=>1,'purpose'=>'factor_restoration','review'=>$v,'state'=>'preparing','before'=>$s['facts']['stamp'],'after'=>'','old'=>['scope'=>$slot->slotScope(),'subject'=>$slot->slotSubject(),'factor'=>$slot->factorId()],'valid_until'=>$now+$d[14]->lifetime('recover_account'),'attempts'=>0,'proved_at'=>0,'physical'=>'','decision'=>'','old_cleaned'=>$slot->factorId()==='','retain_until'=>0];$l=$this->ledger($u);$l->capacity($s['cursor']===null?2:1);$retire=$b['valid_until']+$d[14]->lifetime('account_activated');$l->put($v['operation'],$this->owner($v['subject']),'recover',self::json($b),$retire);$l->put($this->cursorId($v['subject']),$this->owner($v['subject']),'budget',self::json(['format'=>1,'purpose'=>'factor_restoration_cursor','subject'=>$v['subject'],'operation'=>$v['operation']]),$retire,$s['cursor']['revision']??null);$saved=$this->frame($u,$v['subject'],$v['operation']);$this->audit($u,'started',$v,$s['facts'],$saved['facts']);return $saved;},$source,$v,'reserve',function(array $s)use($u,$v,$source,$proof,&$attempt):void{$this->deadline($u,$v);$this->savedCheck($u,'reserve_commit',$v,$source,$s,$proof);$attempt=true;});
                $attempt=true;$pending=$d[5]->prepare($v['slot_scope'],$v['slot_subject'],$v['slot_factor'],$reserved['facts']['record']->address()->value());$u=$this->unit();$saved=$this->requested($u,function()use($u,$v,$source,$proof,$reserved,$pending):array{$this->savedCheck($u,'prepared',$v,$source,$reserved,$proof);if($pending->id()!==$v['slot_factor']){self::corrupt();}$b=$reserved['body'];$b['state']='pending';$this->put($u,$reserved,$b);return $this->frame($u,$v['subject'],$v['operation']);},$source,$v,'prepared',function(array $s)use($u,$v,$source,$proof):void{$this->deadline($u,$v);$this->savedCheck($u,'prepared_return',$v,$source,$s,$proof);});$until=min($pending->expiresAt(),$saved['body']['valid_until']);if($d[15]->now()>=$until){throw new StorageException('Restoration provisioning expired before delivery.','account.restoration_expired');}return new FactorEnrollment($v['operation'],new \SoSecurity\Mfa\Enrollment($pending->id(),$pending->provisioningUri(),$until));
            }catch(\Throwable $e){if($attempt){throw new StorageException('Restoration preparation completion is unknown; inspect or cancel its retained intent.','account.completion_unknown',$e);}throw $e;}
        },$attempt);
    }
    private function outcomeWork(string $method,callable $body,bool &$effect)
    {
        $d=$this->d();try{return $d[6]->$method($body);}catch(\Throwable $e){if($effect){throw new StorageException('Restoration completion is unknown; retain the intent and inspect current authority.','account.completion_unknown',$e);}throw $e;}
    }
    private function put(SqlTransaction $u,array $s,array $body):void{$row=$s['row'];$this->ledger($u)->put($row['record_id'],$row['owner'],'recover',self::json($body),$row['retire_at'],$row['revision']);}
    public function prove(string $operation,string $code,string $source):?array
    {
        self::id($operation);self::label($source);if(!preg_match('/\A[0-9]{6,8}\z/D',$code)){throw new ValidationException('Use a bounded new-factor possession code.','account.restoration_input');}$d=$this->d();$pre=['purpose'=>'factor_restoration_prove','operation'=>$operation];$ready=false;return $this->outcomeWork('work',function()use($operation,$code,$source,$pre,$d,&$ready):?array{$u=$this->unit();
            try{$attempt=$this->requested($u,function()use($u,$operation):array{$s=$this->fromOperation($u,$operation);$this->eligible($s,'factor_restoration_prove',$u);$b=$s['body'];if($b['attempts']>=$this->d()[14]->maximumAttempts()){throw new SecurityException('Restoration proof attempts exhausted.','account.restoration_unproven');}++$b['attempts'];$this->put($u,$s,$b);return $this->frame($u,$b['review']['subject'],$operation);},$source,$pre,'prove',function(array $s)use($u,$source,&$ready):void{$v=$s['body']['review'];$v['purpose']='factor_restoration_prove';$this->savedCheck($u,'attempt_commit',$v,$source,$s);$ready=true;});}catch(\Throwable $e){if($ready||$u->committed()){throw new StorageException('Restoration proof attempt completion is unknown.','account.completion_unknown',$e);}throw $e;}
            $v=$attempt['body']['review'];
            try{$status=$d[5]->status($v['slot_scope'],$v['slot_subject']);$codes=$status['enabled']?($status['factor_id']===$v['slot_factor']&&$d[5]->verifyBound($v['slot_scope'],$v['slot_subject'],$v['slot_factor'],$code)?[]:null):$d[5]->confirm($v['slot_scope'],$v['slot_subject'],$v['slot_factor'],$code);if($codes===null){return null;}$u=$this->unit();$saved=$this->requested($u,function()use($u,$operation,$attempt,$v):array{$s=$this->fromOperation($u,$operation);if($s['state']!==$attempt['state']){throw new StorageException('Restoration proof was superseded.','account.restoration_changed');}$this->eligible($s,'factor_restoration_prove',$u);$p=$this->physical($u,$v,false);if($p['factor_id']!==$v['slot_factor']){throw new StorageException('New restoration factor changed.','account.restoration_changed');}$b=$s['body'];$b['state']='proven';$b['proved_at']=$u->now();$b['physical']=$p['digest'];$this->put($u,$s,$b);return $this->frame($u,$v['subject'],$operation);},$source,$pre,'proven',function(array $s)use($u,$source):void{$v=$s['body']['review'];$v['purpose']='factor_restoration_prove';$this->savedCheck($u,'proved_return',$v,$source,$s);});return $codes;
            }catch(\Throwable $e){throw new StorageException('Restoration proof completion is unknown; never replay recovery-code output.','account.completion_unknown',$e);}
        },$ready);
    }
    public function operationReview(string $operation,string $source,string $action='activate'):array{return $this->operationReviewUsing($operation,$source,$action,false);}
    public function operationReviewClosed(string $operation,string $source,string $action='activate'):array{return $this->operationReviewUsing($operation,$source,$action,true);}
    private function operationReviewUsing(string $operation,string $source,string $action,bool $closed):array
    {
        self::id($operation);self::label($source);if(!in_array($action,['activate','cancel','clean','clean_previous'],true)){throw new ValidationException('Use an explicit restoration action.','account.restoration_input');}$purpose='factor_restoration_'.$action;$d=$this->d();$method=$closed?'closedWork':'work';$pre=['purpose'=>$purpose,'operation'=>$operation];return $d[6]->$method(function()use($operation,$source,$purpose,$closed,$pre):array{$u=$this->unit();return $this->requested($u,function()use($u,$operation,$purpose,$closed):array{$s=$this->fromOperation($u,$operation);$this->eligible($s,$purpose,$u);$old=$s['body']['review'];$physical='';if($purpose==='factor_restoration_activate'){$p=$this->physical($u,$old,$closed);if($p['factor_id']!==$old['slot_factor']||$p['digest']!==$s['body']['physical']){throw new StorageException('Re-prove a changed restoration factor before requesting activation.','account.restoration_changed');}$physical=$p['digest'];}return $this->context($u,$s,$purpose,$old['subject'],$operation,$old,$physical);},$source,$pre,'review',function(array $v)use($u,$source,$closed):void{$this->budget($u,$v['purpose'],'final',$source,$v['operation']);$this->guard($u,'review_return',$v);$this->same($u,$v,$v['purpose']==='factor_restoration_activate',$closed);});});
    }
    public function activate(array $context,string $source,array $proof):array{return $this->drained($context,$source,$proof,'activate',false);}
    public function activateClosed(array $context,string $source,array $proof):array{return $this->drained($context,$source,$proof,'activate',true);}
    public function clean(array $context,string $source,array $proof):array{return $this->drained($context,$source,$proof,'clean',false);}
    public function cleanClosed(array $context,string $source,array $proof):array{return $this->drained($context,$source,$proof,'clean',true);}
    private function drained(array $context,string $source,array $proof,string $action,bool $closed):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);if(($action==='activate'&&$v['purpose']!=='factor_restoration_activate')||($action==='clean'&&!in_array($v['purpose'],['factor_restoration_clean','factor_restoration_clean_previous'],true))){throw new ValidationException('Use a distinct restoration action review.','account.restoration_input');}$d=$this->d();$physical=$action==='activate';$attempt=false;
        try{if($closed){return $d[6]->closedWork(function()use($v,$source,$proof,$physical,$action,&$attempt):array{$this->verify($v,$source,$proof,$physical,true);$attempt=true;return $action==='activate'?$this->applyActivation($v,$source,$proof):$this->applyCleanup($v,$source,$proof);});}
            $d[6]->work(function()use($v,$source,$proof,$physical):void{$this->verify($v,$source,$proof,$physical,false);});return $d[6]->drain(function()use($v,$source,$proof,$action):array{return $action==='activate'?$this->applyActivation($v,$source,$proof):$this->applyCleanup($v,$source,$proof);},function()use($v,$source,$proof,&$attempt):bool{$u=$this->unit();$u->run(function()use($u,$v,$source,$proof):void{$this->check($u,'authorize',$v,$source,$proof);});$attempt=true;return true;});
        }catch(\Throwable $e){if($attempt){throw new StorageException('Restoration completion is unknown; inspect retained history and the closed authority.','account.completion_unknown',$e);}throw $e;}
    }
    private function applyActivation(array $v,string $source,array $proof):array
    {
        $d=$this->d();$d[6]->closedWork(static function():void{});$u=$this->unit();$saved=$this->requested($u,function()use($u,$v,$source,$proof,$d):array{$s=$this->check($u,'activate',$v,$source,$proof,true,true);$after=$u->invoke($d[8],[$u,$s['facts'],$v],'account.restoration_directory');$l=$this->ledger($u);if($l->checkpoint()!==$s['root']||$l->read($v['operation'])!==$s['row']){throw new StorageException('Restoration CAS changed workflow history.','account.restoration_changed');}$new=$this->frame($u,$v['subject'],$v['operation']);$a=$s['facts']['record'];$b=$new['facts']['record'];$slot=$new['facts']['slot'];
            if($after['stamp']!==$new['facts']['stamp']||!$b instanceof AccountRecord||!$b->account()->mfaRequired()||$b->account()->version()===$a->account()->version()||$b->account()->roles()!==$a->account()->roles()||$b->status()!==$a->status()||$b->verified()!==$a->verified()||!$b->address()->equals($a->address())||$b->addressVersion()!==$a->addressVersion()||$new['facts']['retired']||$slot->slotScope()!==$v['slot_scope']||$slot->slotSubject()!==$v['slot_subject']||$slot->factorId()!==$v['slot_factor']||($new['facts']['data']['restoration']['operation']??null)!==$v['operation']||($new['facts']['data']['restoration']['context']??null)!==hash('sha256',self::json($v))){throw new StorageException('Restoration must bind only the proven new factor and revoke old credentials.','account.restoration_changed');}
            $body=$s['body'];$body['state']='activated';$body['after']=$new['facts']['stamp'];$body['decision']=$v['nonce'];$body['retain_until']=$u->now()+$this->d()[14]->lifetime('account_activated');$this->put($u,$s,$body);$result=$this->frame($u,$v['subject'],$v['operation']);$this->audit($u,'activated',$v,$s['facts'],$result['facts']);return $result;},$source,$v,'activate',function(array $s)use($u,$v,$source,$proof):void{$this->deadline($u,$v);$this->savedCheck($u,'commit',$v,$source,$s,$proof);$p=$this->physical($u,$v,true);if($p['factor_id']!==$v['slot_factor']||$p['digest']!==$v['physical']){throw new StorageException('New factor changed before restoration commit.','account.restoration_changed');}$this->deadline($u,$v);});
        $u=$this->unit();$u->run(function()use($u,$v,$source,$proof,$saved):void{$this->savedCheck($u,'return',$v,$source,$saved,$proof);});return ['operation'=>$v['operation'],'restored'=>true,'mfa_required'=>true,'requires_authority_handoff'=>true,'old_cleaned'=>$saved['body']['old_cleaned']];
    }
    public function cancel(array $context,string $source,array $proof):array{return $this->cancelUsing($context,$source,$proof,false);}
    public function cancelClosed(array $context,string $source,array $proof):array{return $this->cancelUsing($context,$source,$proof,true);}
    private function cancelUsing(array $context,string $source,array $proof,bool $closed):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);if($v['purpose']!=='factor_restoration_cancel'){throw new ValidationException('Use a cancel-specific restoration review.','account.restoration_input');}$d=$this->d();$method=$closed?'closedWork':'work';$ready=false;return $this->outcomeWork($method,function()use($v,$source,$proof,&$ready):array{$this->verify($v,$source,$proof);$u=$this->unit();try{$this->requested($u,function()use($u,$v,$source,$proof):array{$s=$this->check($u,'cancel',$v,$source,$proof);$body=$s['body'];$body['state']='cancelled';$body['decision']=$v['nonce'];$body['retain_until']=$u->now()+$this->d()[14]->lifetime('account_activated');$this->put($u,$s,$body);$saved=$this->frame($u,$v['subject'],$v['operation']);$this->audit($u,'cancelled',$v,$s['facts'],$saved['facts']);return $saved;},$source,$v,'cancel',function(array $s)use($u,$v,$source,$proof,&$ready):void{$this->deadline($u,$v);$this->savedCheck($u,'cancel_commit',$v,$source,$s,$proof);$ready=true;});return ['operation'=>$v['operation'],'cancelled'=>true];}catch(\Throwable $e){if($ready||$u->committed()){throw new StorageException('Restoration cancellation completion is unknown.','account.completion_unknown',$e);}throw $e;}},$ready);
    }
    private function applyCleanup(array $v,string $source,array $proof):array
    {
        $d=$this->d();$d[6]->closedWork(static function():void{});$u=$this->unit();$removed=false;$s=$this->requested($u,function()use($u,$v,$source,$proof):array{return $this->check($u,'clean',$v,$source,$proof);},$source,$v,'clean');$old=$v['purpose']==='factor_restoration_clean_previous';if(($old&&$s['body']['old_cleaned'])||(!$old&&$s['body']['state']==='cleaned')){return ['operation'=>$v['operation'],'removed'=>true,'changed'=>false,'state'=>$s['body']['state'],'old_cleaned'=>$s['body']['old_cleaned']];}$target=$old?$s['body']['old']:['scope'=>$v['slot_scope'],'subject'=>$v['slot_subject'],'factor'=>$v['slot_factor']];
        $u=$this->unit();$saved=$this->requested($u,function()use($u,$v,$source,$proof,$s,$old,$target,$d,&$removed):array{$this->savedCheck($u,'delete',$v,$source,$s,$proof);$slot=$s['facts']['slot'];if(!$s['facts']['retired']&&$slot->enabled()&&$slot->slotScope()===$target['scope']&&$slot->slotSubject()===$target['subject']){throw new SecurityException('Cleanup cannot remove the current factor slot.','account.restoration_changed');}
            $removed=$target['factor']===''||$u->invoke([$d[5],'revokeGenerationClosed'],[$d[6],$target['scope'],$target['subject'],$target['factor'],function()use($u,$v,$source,$proof,$s):bool{$this->savedCheck($u,'delete_current',$v,$source,$s,$proof);return true;}],'account.factor_store');if(!$removed){return $s;}$body=$s['body'];if($old){$body['old_cleaned']=true;}else{$body['state']='cleaned';}$body['retain_until']=max($body['retain_until'],$u->now()+$this->d()[14]->lifetime('account_activated'));$this->put($u,$s,$body);$result=$this->frame($u,$v['subject'],$v['operation']);$this->audit($u,$old?'previous_cleaned':'cleaned',$v,$s['facts'],$result['facts']);return $result;},$source,$v,'delete',function(array $saved)use($u,$v,$source,$proof):void{$this->deadline($u,$v);$this->savedCheck($u,'clean_commit',$v,$source,$saved,$proof);});return ['operation'=>$v['operation'],'removed'=>$removed,'state'=>$saved['body']['state'],'old_cleaned'=>$saved['body']['old_cleaned']];
    }
    public function inspect(string $operation,string $source):array{return $this->inspectUsing($operation,$source,false);}
    public function inspectClosed(string $operation,string $source):array{return $this->inspectUsing($operation,$source,true);}
    private function inspectUsing(string $operation,string $source,bool $closed):array
    {
        self::id($operation);self::label($source);$d=$this->d();$method=$closed?'closedWork':'work';$pre=['purpose'=>'factor_restoration_inspect','operation'=>$operation];return $d[6]->$method(function()use($operation,$source,$pre):array{$u=$this->unit();$s=$this->requested($u,function()use($u,$operation):array{return $this->fromOperation($u,$operation);},$source,$pre,'inspect',function(array $s)use($u,$source,$pre):void{$v=$pre+['subject'=>$s['body']['review']['subject']];$this->savedCheck($u,'inspect_return',$v,$source,$s);});return ['operation'=>$operation,'subject'=>$s['body']['review']['subject'],'state'=>$s['body']['state'],'attempts'=>$s['body']['attempts'],'proved_at'=>$s['body']['proved_at'],'valid_until'=>$s['body']['valid_until'],'decision'=>$s['body']['decision'],'retire_at'=>$s['row']['retire_at'],'old_cleaned'=>$s['body']['old_cleaned'],'retain_until'=>$s['body']['retain_until']];});
    }
    public function maintenance(callable $authority,callable $budgets,callable $approval,callable $audit,callable $events):FactorIntentMaintenance
    {
        $d=$this->d();$decode=function(array $row,SqlTransaction $u):array{$body=$this->parse($row);$subject=$body['review']['subject'];$cursor=$this->ledger($u)->read($this->cursorId($subject));$reference=$this->cursorReference($cursor,$subject);return ['body'=>$body,'linked_cursor'=>$reference===$row['record_id']?$cursor:null];};
        return new FactorIntentMaintenance($d[0],$d[1],$d[2],$d[3],$d[4],$d[5],$d[6],$decode,static function():bool{return false;},$authority,$budgets,$approval,$audit,$events,$d[14],$d[15],'restoration');
    }
    public function __debugInfo():array{return ['factor_restoration'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload current restoration dependencies.','configuration.factor_restoration');}
    public function __wakeup():void{throw new ConfigurationException('Reload current restoration dependencies.','configuration.factor_restoration');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Restoration services are immutable.','configuration.immutable');}
}
