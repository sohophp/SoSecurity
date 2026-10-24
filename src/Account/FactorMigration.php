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

/** Explicit reviewed legacy migration. SQL intent precedes external sealing; activation follows SQL completion. */
final class FactorMigration
{
    private $dependencies;
    public function __construct(PDO $pdo,string $site,string $scope,string $epoch,HmacKeys $keys,TotpFactors $legacy,TotpFactors $managed,LocalEpochFence $fence,callable $facts,callable $write,callable $authority,callable $budgets,callable $approval,callable $stopped,callable $audit,callable $events,Policy $policy,Clock $clock)
    {
        self::label($site);self::label($scope);self::id($epoch);if(!$fence->matches($site,$scope,$epoch)||!$managed->boundTo($fence)||!$managed->migratesFrom($legacy)){throw new ConfigurationException('Use the exact registered migration source and authority.','configuration.factor_migration');}new SqlTransaction($pdo,$clock,$policy->ioMilliseconds());$managed->validateConfiguration($clock,true);
        $this->dependencies=static function()use($pdo,$site,$scope,$epoch,$keys,$legacy,$managed,$fence,$facts,$write,$authority,$budgets,$approval,$stopped,$audit,$events,$policy,$clock):array{return [$pdo,$site,$scope,$epoch,$keys,$legacy,$managed,$fence,$facts,$write,$authority,$budgets,$approval,$stopped,$audit,$events,$policy,$clock];};
    }
    /** @internal Read-only state inventory context; it neither enters workers nor invokes host callbacks. */
    public function recoveryBoundary(LocalStateWitness $witness):bool{$f=$this->d()[7];return $f!==null&&$f->recoveryBoundary($witness);}
    public function stateHistory(\PDO $pdo,\SoSecurity\Mfa\TotpFactors $factors,string $site,string $scope,string $epoch,HmacKeys $keys,Clock $clock):?array
    {
        $d=$this->d();if($d[0]!==$pdo||$d[1]!==$site||$d[2]!==$scope||$d[3]!==$epoch||$d[4]!==$keys||$d[6]!==$factors||!($d[17]===$clock||($d[17] instanceof \SoSecurity\Support\SystemClock&&$clock instanceof \SoSecurity\Support\SystemClock))){return null;}
        $format=$d[7]===null?1:2;$authority=$d[7]===null?null:$d[7]->binding();$policy=$format===1?$d[16]->fingerprint():hash('sha256','SoSecurity.Account.FencedLedger.2.'.$d[16]->fingerprint().$authority);
        return ['namespace'=>hash('sha256',self::json(['SoSecurity.Account.Ledger.1','account-factor-recovery:'.hash('sha256',$site),$scope,$epoch])),'format'=>$format,'policy'=>$policy,'maximum'=>$d[16]->maximumEntries(),'owner_prefix'=>'SoSecurity.Account.FactorMigration.Owner.1.','authority'=>$authority];
    }
    /** @internal The original migration decoder validates retained records before coordinates are used. */
    public function stateSlots(array $row,string $subject):array
    {
        $b=$this->decode($row)['body'];$v=$b['review'];if($v['subject']!==$subject){throw new StorageException('Migration history belongs to another account.','account.migration_corrupt');}$slots=[];
        if($v['factor_id']!==null){$slots[]=['scope'=>$v['scope'],'subject'=>$subject,'factor'=>$v['factor_id']];}
        if($b['old']!==null){$d=$this->d();$old=FactorDirectoryState::read($d[1],$d[2],$d[3],['kind'=>'budget','record_id'=>hash('sha256','SoSecurity.Account.FactorRegistry.Pointer.1.'.$subject),'owner'=>hash('sha256',$subject),'payload'=>self::json($b['old'])],$subject);
            if($old['factor_id']!==''){if($old['slot_scope']!==$d[2]||$old['slot_subject']!==$subject){throw new StorageException('Migration may refer only to the fixed original legacy coordinate.','account.migration_corrupt');}$slots[]=['scope'=>$old['slot_scope'],'subject'=>$old['slot_subject'],'factor'=>$old['factor_id']];}}
        return ['slots'=>$slots,'reference'=>null];
    }
    private function d():array {return ($this->dependencies)();}
    private function unit():SqlTransaction {$d=$this->d();return new SqlTransaction($d[0],$d[17],$d[16]->ioMilliseconds());}
    private function ledger(SqlTransaction $u):Ledger {$d=$this->d();return new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[16],2,$d[7]->binding());}
    private static function label(string $v):void {Guard::label($v);if(preg_match('//u',$v)!==1){throw new ValidationException('Use bounded UTF-8 migration labels.','account.migration_input');}}
    private static function id(string $v):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$v)){throw new ValidationException('Use exact migration identifiers.','account.migration_input');}}
    private static function json(array $v):string {return json_encode($v,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
    private function owner(string $subject):string {return hash('sha256','SoSecurity.Account.FactorMigration.Owner.1.'.$subject);}
    private function guard(SqlTransaction $u,string $phase,?array $review=null,?array $facts=null):void {$d=$this->d();if($phase!=='initialize'){$d[6]->enlistWorkers($d[0]);}if($u->invoke($d[10],['migrate',$phase,$d[2],$facts['record']??null,$review],'account.migration_authority')!==true){throw new SecurityException('Current migration object authority required.','account.migration_denied');}}
    private function budget(SqlTransaction $u,string $phase,string $source,string $operation):void {$d=$this->d();if($u->invoke($d[11],['migrate',$phase,$source,$operation],'account.migration_budget')!==true){throw new SecurityException('Migration budget denied.','account.migration_budget');}}
    private function stopped(SqlTransaction $u,string $phase,array $review):void {$d=$this->d();if($u->invoke($d[13],[$phase,$review],'account.migration_stop')!==true){throw new SecurityException('Explicit current old-deployment stop evidence required.','account.migration_stop');}}
    private function approved(SqlTransaction $u,string $phase,array $review,array $proof,array $facts):void {$d=$this->d();if($u->invoke($d[12],[$phase,$review,$proof,$facts['record'],$facts['identity']],'account.migration_approval')!==true){throw new SecurityException('Independent exact migration approval required.','account.migration_denied');}}
    private function facts(SqlTransaction $u,string $subject,?string $operation=null):array {$d=$this->d();return $u->invoke($d[8],[$u,$subject,$operation],'account.migration_directory');}
    private function requested(SqlTransaction $u,callable $body,string $source,string $operation,string $phase,?array $review=null,?callable $finish=null)
    {
        $rejected=null;$result=$u->run($body,function()use($u,$source,$operation,$phase,$review,&$rejected):bool{try{$this->budget($u,'public',$source,$operation);if($phase==='initialize'){$this->ledger($u)->checkpointIfInitialized();}$this->guard($u,$phase,$review);return true;}catch(\Throwable $error){$rejected=$error;return false;}},$finish);if($rejected!==null){throw $rejected;}return $result;
    }
    public function initialize(string $source):void
    {
        self::label($source);$d=$this->d();$d[7]->work(function()use($source):void{$u=$this->unit();$this->requested($u,function()use($u):void{$this->ledger($u)->initialize();},$source,'','initialize',null,function()use($u,$source):void{$this->budget($u,'final',$source,'');$this->guard($u,'initialize_commit');$this->ledger($u)->checkpoint();});});
    }
    private function makeReview(SqlTransaction $u,string $mode,string $subject,string $operation,string $generation,array $facts,array $physical,string $stop):array
    {
        $d=$this->d();$v=['format'=>1,'purpose'=>'factor_migration','site'=>$d[1],'scope'=>$d[2],'epoch'=>$d[3],'authority'=>$d[7]->binding(),'mode'=>$mode,'subject'=>$subject,'operation'=>$operation,'generation'=>$generation,'account'=>$facts['account_stamp'],'directory'=>$facts['stamp'],'source_digest'=>$physical['digest'],'factor_id'=>$physical['factor_id'],'stopped'=>$stop,'issued'=>$u->now(),'expires'=>$u->now()+min(300,$d[16]->lifetime('recover_account')),'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[4]->currentId()];$v['seal']=bin2hex($d[4]->sign('SoSecurity.Account.FactorMigration.Review.1.'.self::json($v)));return $v;
    }
    private function input(array $v,bool $historical=false):array
    {
        $fields=['format','purpose','site','scope','epoch','authority','mode','subject','operation','generation','account','directory','source_digest','factor_id','stopped','issued','expires','nonce','key','seal'];$keys=array_keys($v);sort($keys);$wanted=$fields;sort($wanted);
        if($keys!==$wanted||$v['format']!==1||$v['purpose']!=='factor_migration'||!in_array($v['mode'],['start','resume','cancel'],true)||!is_int($v['issued'])||!is_int($v['expires'])||$v['issued']<0||$v['expires']<=$v['issued']||$v['expires']-$v['issued']>300){throw new ValidationException('Invalid migration review.','account.migration_input');}
        foreach(['site','scope','subject'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid migration label.','account.migration_input');}self::label($v[$key]);}
        foreach(['epoch','authority','operation','account','directory','source_digest','stopped','nonce','seal'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid migration digest.','account.migration_input');}self::id($v[$key]);}
        if(!is_string($v['generation'])||!preg_match('/\A[a-f0-9]{32}\z/D',$v['generation'])||($v['factor_id']!==null&&(!is_string($v['factor_id'])||!preg_match('/\A[a-f0-9]{32}\z/D',$v['factor_id'])))||!is_string($v['key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v['key'])){throw new ValidationException('Invalid migration factor/key.','account.migration_input');}
        $ordered=[];foreach($fields as $key){$ordered[$key]=$v[$key];}$v=$ordered;$d=$this->d();$seal=$v['seal'];unset($v['seal']);
        if($v['site']!==$d[1]||$v['scope']!==$d[2]||$v['epoch']!==$d[3]||(!$historical&&($v['authority']!==$d[7]->binding()||!$d[4]->verify($v['key'],'SoSecurity.Account.FactorMigration.Review.1.'.self::json($v),hex2bin($seal))))){throw new SecurityException('Migration review cannot be authenticated.','account.migration_denied');}return $v+['seal'=>$seal];
    }
    private static function proof(array $v):void {$keys=array_keys($v);sort($keys);if($keys!==['code','type']||$v['type']!=='approved'||!is_string($v['code'])||$v['code']===''||strlen($v['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$v['code'])){throw new ValidationException('Use bounded independent migration approval.','account.migration_input');}}
    private function raw(SqlTransaction $u,string $subject):array {$d=$this->d();return $u->invoke([$d[5],'legacyMigrationSnapshot'],[$d[2],$subject],'account.migration_source');}
    private function physical(SqlTransaction $u,string $subject):array {$d=$this->d();return $u->invoke([$d[6],'migrationSnapshot'],[$d[2],$subject],'account.migration_source');}
    private function eligible(array $facts,array $physical):void
    {
        if($facts['record']->account()->mfaRequired()&&$physical['factor_id']===null){throw new SecurityException('Migration never clears an existing MFA requirement.','account.migration_ineligible');}
        if($facts['data']!==null&&$facts['data']['factor_id']!==''&&$physical['factor_id']!==$facts['data']['factor_id']){throw new SecurityException('Legacy directory generation changed.','account.migration_changed');}
    }
    private function samePhysical(array $v,array $p,bool $prepared=false):void
    {
        if($p['factor_id']!==$v['factor_id']||($p['digest']!==$v['source_digest']&&(!$prepared||($p['migration']['state']??null)!=='committed'))){throw new SecurityException('Reviewed physical state changed.','account.migration_changed');}
        if($prepared&&($p['migration']===null||$p['migration']['operation']!==$v['operation']||$p['migration']['digest']!==$v['source_digest'])){throw new SecurityException('A matching physical receipt is required.','account.migration_changed');}
    }
    public function review(string $subject,string $source,string $stoppedDigest):array
    {
        self::label($subject);self::label($source);self::id($stoppedDigest);$d=$this->d();return $d[7]->work(function()use($subject,$source,$stoppedDigest):array{$u=$this->unit();$op=bin2hex(random_bytes(32));$result=$this->requested($u,function()use($u,$subject,$op,$stoppedDigest):array{$root=$this->ledger($u)->checkpoint();$facts=$this->facts($u,$subject);$physical=$this->raw($u,$subject);$this->eligible($facts,$physical);$v=$this->makeReview($u,'start',$subject,$op,bin2hex(random_bytes(16)),$facts,$physical,$stoppedDigest);return ['review'=>$v,'facts'=>$facts,'root'=>$root,'physical'=>$physical];},$source,$op,'review',null,function(array $s)use($u,$source):void{$v=$s['review'];$this->budget($u,'final',$source,$v['operation']);$this->stopped($u,'review',$v);$this->guard($u,'review_return',$v,$s['facts']);if($this->facts($u,$v['subject'])['stamp']!==$s['facts']['stamp']||$this->ledger($u)->checkpoint()!==$s['root']||$this->raw($u,$v['subject'])!==$s['physical']){throw new StorageException('Migration review changed.','account.migration_changed');}});return $result['review'];});
    }
    private function load(SqlTransaction $u,string $operation):?array
    {
        $l=$this->ledger($u);$root=$l->checkpoint();$row=$l->read($operation);return $row===null?null:$this->decode($row)+['root'=>$root];
    }
    private function decode(array $row):array
    {
        $operation=$row['record_id'];$b=json_decode($row['payload'],true,8);
        if(!is_array($b)||array_keys($b)!==['format','purpose','review','state','old','after','account','approval']||$b['format']!==1||$b['purpose']!=='factor_migration'||!is_array($b['review'])||!in_array($b['state'],['reserved','completed','activated','cancelled'],true)||($b['old']!==null&&!is_array($b['old']))){throw new StorageException('Migration intent is corrupt.','account.migration_corrupt');}
        $v=$this->input($b['review'],true);foreach(['after','account','approval'] as $key){if(!is_string($b[$key])||!preg_match('/\A[a-f0-9]{64}\z/D',$b[$key])){throw new StorageException('Migration bindings are corrupt.','account.migration_corrupt');}}
        if($v['mode']!=='start'||$v['operation']!==$operation||$row['kind']!=='recover'||$row['owner']!==$this->owner($v['subject'])||$row['created_at']<$v['issued']||$row['created_at']>=$v['expires']||self::json($b)!==$row['payload']){throw new StorageException('Migration intent identity is corrupt.','account.migration_corrupt');}return ['row'=>$row,'body'=>$b];
    }
    public function maintenance(callable $authority,callable $budgets,callable $approval,callable $audit,callable $events):FactorMigrationMaintenance
    {
        $d=$this->d();return new FactorMigrationMaintenance($d[0],$d[1],$d[2],$d[3],$d[4],$d[6],$d[7],function(array $row):array{return $this->decode($row);},$d[13],$authority,$budgets,$approval,$audit,$events,$d[16],$d[17]);
    }
    private function save(SqlTransaction $u,array $v,string $state,array $facts,?array $old=null):array
    {
        $b=['format'=>1,'purpose'=>'factor_migration','review'=>$old===null?$v:$old['body']['review'],'state'=>$state,'old'=>$old===null?$facts['original_data']:$old['body']['old'],'after'=>$facts['stamp'],'account'=>$facts['account_stamp'],'approval'=>hash('sha256',self::json($v))];$l=$this->ledger($u);$row=$l->put($v['operation'],$this->owner($v['subject']),'recover',self::json($b),$old===null?min($u->now()+1209600,$v['expires']+$this->d()[16]->lifetime('account_activated')):$old['row']['retire_at'],$old['row']['revision']??null);return ['row'=>$row,'body'=>$b,'root'=>$l->checkpoint()];
    }
    private function check(SqlTransaction $u,array $v,string $source,array $proof,array $expected,string $phase,?array $intent=null,bool $original=false):void
    {
        $root=$this->ledger($u)->checkpoint();$this->budget($u,'final',$source,$v['operation']);$this->approved($u,$phase,$v,$proof,$expected);$this->stopped($u,$phase,$v);$this->guard($u,$phase,$v,$expected);$fresh=$this->facts($u,$v['subject'],$original?null:$v['operation']);
        if($fresh['stamp']!==$expected['stamp']||$this->ledger($u)->checkpoint()!==$root||$u->now()<$v['issued']||$u->now()>=$v['expires']){throw new StorageException('Current migration target or deadline changed.','account.migration_changed');}
        if($intent!==null){$now=$this->load($u,$v['operation']);if($now===null||$now['row']!==$intent['row']||$now['root']!==$intent['root']){throw new StorageException('Migration intent changed during authorization.','account.migration_changed');}}
    }
    private function notify(SqlTransaction $u,string $phase,array $v,array $before,array $after):void
    {
        $d=$this->d();if($u->invoke($d[14],[$phase,$v,$before['record'],$after['record'],$v['operation']],'account.migration_audit')!==true||$u->invoke($d[15],['factor_migration_'.$phase,$d[2],$before['record'],$after['record'],$v['operation'],$v],'account.migration_event')!==true){throw new StorageException('Durable same-PDO migration audit and notification required.','account.migration_audit');}
    }
    private function verifyApproval(array $v,array $proof,array $facts):void
    {
        $d=$this->d();$deadline=new Deadline($d[16]->ioMilliseconds());$observed=$d[17]->now();try{$allowed=call_user_func($d[12],'verify',$v,$proof,$facts['record'],$facts['identity']);}catch(\Throwable $e){throw new DependencyException('Independent migration approval unavailable.','account.migration_approval');}$deadline->check('account.migration_expired');if($d[17]->now()<$observed||$d[17]->now()>=$v['expires']){throw new SecurityException('Migration approval expired.','account.migration_expired');}if($allowed!==true){throw new SecurityException('Independent exact migration approval required.','account.migration_denied');}
    }
    public function execute(array $review,string $source,array $proof):array
    {
        $v=$this->input($review);self::label($source);self::proof($proof);if($v['mode']!=='start'){throw new ValidationException('Use explicit resume or cancellation for retained migrations.','account.migration_input');}$d=$this->d();return $d[7]->work(function()use($v,$source,$proof,$d):array{
            $u=$this->unit();$facts=$this->requested($u,function()use($u,$v,$source,$proof):array{$l=$this->ledger($u);$l->checkpoint();if($l->read($v['operation'])!==null){throw new SecurityException('Never implicitly replay a migration.','account.migration_replayed');}$f=$this->facts($u,$v['subject']);if($f['stamp']!==$v['directory']||$f['account_stamp']!==$v['account']){throw new SecurityException('Migration review is stale.','account.migration_changed');}$this->samePhysical($v,$this->raw($u,$v['subject']));$this->check($u,$v,$source,$proof,$f,'inspect',null,true);return $f;},$source,$v['operation'],'request',$v);$this->verifyApproval($v,$proof,$facts);$possible=false;$ready=false;
            try{$u=$this->unit();$reserved=$u->run(function()use($u,$v,$source,$proof,$facts,$d):array{$l=$this->ledger($u);$l->checkpoint();if($l->read($v['operation'])!==null){throw new SecurityException('Migration already reserved.','account.migration_replayed');}$this->check($u,$v,$source,$proof,$facts,'reserve',null,true);$this->samePhysical($v,$this->raw($u,$v['subject']));$after=$u->invoke($d[9],[$u,$facts,$v,'reserve',null],'account.migration_directory');$after['original_data']=$facts['data'];$intent=$this->save($u,$v,'reserved',$after);$this->notify($u,'reserved',$v,$facts,$after);return ['intent'=>$intent,'facts'=>$after];},null,function(array $s)use($u,$v,$source,$proof,&$ready):void{$this->check($u,$v,$source,$proof,$s['facts'],'reserve_commit',$s['intent']);$this->samePhysical($v,$this->raw($u,$v['subject']));$ready=true;});$possible=true;
                return $this->advance($v,$source,$proof,$reserved['intent']);
            }catch(\Throwable $e){if($possible||$ready||$u->committed()){throw new StorageException('Migration completion is unknown; inspect and explicitly reapprove, never reopen legacy state.','account.completion_unknown',$e);}throw $e;}
        });
    }
    private function pendingFacts(array $intent,array $facts):void
    {
        $v=$intent['body']['review'];$data=$facts['data'];if($intent['body']['state']==='cancelled'){if($data!==$intent['body']['old']){throw new StorageException('Cancelled migration directory changed.','account.migration_changed');}return;}$reserved=$intent['body']['state']==='reserved';
        if($data===null||$data['format']!==($reserved?4:5)||$data['migration']!==$v['operation']||$data['factor_id']!==($v['factor_id']??'')||($reserved?$data['generation']!==$v['generation']:$facts['record']->account()->mfaRequired()!==($v['factor_id']!==null))){throw new SecurityException('Current migration directory semantics changed.','account.migration_changed');}
    }
    private function current(SqlTransaction $u,array $v,array $expected,array $states):array
    {
        $s=$this->load($u,$v['operation']);if($s===null||$s['row']!==$expected['row']||!in_array($s['body']['state'],$states,true)){throw new StorageException('Migration reservation changed.','account.migration_changed');}$f=$this->facts($u,$v['subject'],$v['operation']);$this->pendingFacts($s,$f);if($f['stamp']!==$s['body']['after']||$f['account_stamp']!==$s['body']['account']){throw new StorageException('Migration account or pointer changed.','account.migration_changed');}return ['intent'=>$s,'facts'=>$f];
    }
    private function advance(array $v,string $source,array $proof,array $expected):array
    {
        $d=$this->d();$u=$this->unit();
        if($expected['body']['state']==='reserved'){
            $d[6]->adoptManagedExact($d[2],$v['subject'],$v['factor_id'],$v['source_digest'],$v['operation'],function()use($v,$source,$proof,$expected):bool{$u=$this->unit();return $u->run(function()use($u,$v,$source,$proof,$expected):bool{$s=$this->current($u,$v,$expected,['reserved']);$this->check($u,$v,$source,$proof,$s['facts'],'physical',$s['intent']);return true;});});
            $u=$this->unit();$expected=$u->run(function()use($u,$v,$source,$proof,$expected,$d):array{$s=$this->current($u,$v,$expected,['reserved']);$this->check($u,$v,$source,$proof,$s['facts'],'apply',$s['intent']);$physical=$this->physical($u,$v['subject']);$this->samePhysical($v,$physical,true);if($physical['migration']['state']!=='prepared'){throw new StorageException('Physical activation preceded SQL completion.','account.migration_changed');}$after=$u->invoke($d[9],[$u,$s['facts'],$v,'finish',null],'account.migration_directory');$intent=$this->save($u,$v,'completed',$after,$s['intent']);$this->notify($u,'completed',$v,$s['facts'],$after);return ['intent'=>$intent,'facts'=>$after];},null,function(array $s)use($u,$v,$source,$proof):void{$this->check($u,$v,$source,$proof,$s['facts'],'commit',$s['intent']);});$expected=$expected['intent'];
        }
        $u=$this->unit();$out=$u->run(function()use($u,$v,$source,$proof,$expected,$d):array{$s=$this->current($u,$v,$expected,['completed']);$this->check($u,$v,$source,$proof,$s['facts'],'activate',$s['intent']);
            $d[6]->completeManagedMigration($d[2],$v['subject'],$v['factor_id'],$v['source_digest'],$v['operation'],function()use($u,$v,$source,$proof,$s):bool{$this->check($u,$v,$source,$proof,$s['facts'],'activation_physical',$s['intent']);return true;});
            $intent=$this->save($u,$v,'activated',$s['facts'],$s['intent']);$this->notify($u,'activated',$v,$s['facts'],$s['facts']);return ['intent'=>$intent,'facts'=>$s['facts']];},null,function(array $s)use($u,$v,$source,$proof):void{$this->check($u,$v,$source,$proof,$s['facts'],'activation_commit',$s['intent']);});
        $u=$this->unit();$u->run(function()use($u,$v,$source,$proof,$out):void{$s=$this->current($u,$v,$out['intent'],['activated']);$this->check($u,$v,$source,$proof,$s['facts'],'return',$s['intent']);$this->samePhysical($v,$this->physical($u,$v['subject']),true);});return ['operation'=>$v['operation'],'completed'=>true,'factor_id'=>$v['factor_id']];
    }
    public function inspect(string $operation,string $source):?array
    {
        self::id($operation);self::label($source);$d=$this->d();return $d[7]->work(function()use($operation,$source):?array{$u=$this->unit();$s=$this->requested($u,function()use($u,$operation):?array{return $this->load($u,$operation);},$source,$operation,'inspect',null,function(?array $s)use($u,$operation,$source):void{$this->budget($u,'final',$source,$operation);$this->guard($u,'inspect_return',$s['body']['review']??null);if($s!==null){$f=$this->load($u,$operation);if($f===null||$f['row']!==$s['row']||$f['root']!==$s['root']){throw new StorageException('Migration inspection changed.','account.migration_changed');}}});return $s===null?null:['operation'=>$operation,'subject'=>$s['body']['review']['subject'],'state'=>$s['body']['state'],'factor_id'=>$s['body']['review']['factor_id'],'source_digest'=>$s['body']['review']['source_digest'],'retire_at'=>$s['row']['retire_at']];});
    }
    public function reviewPending(string $operation,string $source,string $stoppedDigest,bool $cancel=false):?array
    {
        self::id($operation);self::label($source);self::id($stoppedDigest);$d=$this->d();return $d[7]->work(function()use($operation,$source,$stoppedDigest,$cancel):?array{$u=$this->unit();$s=$this->requested($u,function()use($u,$operation,$stoppedDigest,$cancel):?array{$s=$this->load($u,$operation);if($s===null||$s['body']['state']==='activated'||($cancel&&$s['body']['state']==='cancelled')){return null;}$old=$s['body']['review'];$f=$this->facts($u,$old['subject'],$operation);$this->pendingFacts($s,$f);$this->eligible($f,['factor_id'=>$old['factor_id']]);$physical=$this->physical($u,$old['subject']);if($s['body']['state']==='cancelled'&&!$physical['managed']){return null;}$this->samePhysical($old,$physical,$physical['managed']);if($s['body']['state']==='cancelled'&&($physical['migration']['state']??null)!=='prepared'){throw new StorageException('Only the exact pending seal can reconcile a cancellation.','account.migration_changed');}if($s['body']['state']==='reserved'&&$physical['managed']&&($physical['migration']['state']??null)!=='prepared'){throw new StorageException('A retained migration was activated before SQL completion.','account.migration_changed');}if($physical['managed']&&$physical['migration']===null){throw new SecurityException('Unknown managed migration state.','account.migration_changed');}if($s['body']['state']==='completed'&&($f['data']['format']!==5||!$physical['managed'])){throw new StorageException('SQL completion and physical state disagree.','account.migration_changed');}$v=$this->makeReview($u,$cancel?'cancel':'resume',$old['subject'],$operation,$old['generation'],$f,['factor_id'=>$old['factor_id'],'digest'=>$old['source_digest']],$stoppedDigest);return ['review'=>$v,'facts'=>$f,'intent'=>$s,'physical'=>$physical];},$source,$operation,'pending_review',null,function(?array $s)use($u,$source):void{if($s===null){return;}$v=$s['review'];$this->budget($u,'final',$source,$v['operation']);$this->stopped($u,'pending_review',$v);$this->guard($u,'pending_review_return',$v,$s['facts']);$now=$this->load($u,$v['operation']);if($now===null||$now['row']!==$s['intent']['row']||$now['root']!==$s['intent']['root']||$this->facts($u,$v['subject'],$v['operation'])['stamp']!==$s['facts']['stamp']||$this->physical($u,$v['subject'])!==$s['physical']){throw new StorageException('Retained migration review changed.','account.migration_changed');}});return $s===null?null:$s['review'];});
    }
    public function resume(array $review,string $source,array $proof):array {return $this->retained($review,$source,$proof,false);}
    public function cancel(array $review,string $source,array $proof):array {return $this->retained($review,$source,$proof,true);}
    private function retained(array $review,string $source,array $proof,bool $cancel):array
    {
        $v=$this->input($review);self::label($source);self::proof($proof);if($v['mode']!==($cancel?'cancel':'resume')){throw new ValidationException('Use a purpose-specific retained migration review.','account.migration_input');}$d=$this->d();return $d[7]->work(function()use($v,$source,$proof,$cancel,$d):array{
            $u=$this->unit();$s=$this->requested($u,function()use($u,$v,$source,$proof,$cancel):array{$s=$this->load($u,$v['operation']);if($s===null||$s['body']['state']==='activated'||($cancel&&$s['body']['state']==='cancelled')){throw new SecurityException('Use inspection for resolved migrations.','account.migration_replayed');}if($s['body']['approval']===hash('sha256',self::json($v))){throw new SecurityException('A migration reapproval is never implicitly replayed.','account.migration_replayed');}$old=$s['body']['review'];foreach(['subject','operation','generation','source_digest','factor_id'] as $key){if($old[$key]!==$v[$key]){throw new SecurityException('Retained review does not match its original migration.','account.migration_changed');}}$f=$this->facts($u,$v['subject'],$v['operation']);$this->pendingFacts($s,$f);if($f['stamp']!==$v['directory']||$f['account_stamp']!==$v['account']){throw new SecurityException('Retained migration review is stale.','account.migration_changed');}$this->check($u,$v,$source,$proof,$f,'inspect',$s);return ['intent'=>$s,'facts'=>$f];},$source,$v['operation'],'retained_request',$v);$this->verifyApproval($v,$proof,$s['facts']);$possible=false;$ready=false;
            try{$u=$this->unit();$refreshed=$u->run(function()use($u,$v,$source,$proof,$s,$cancel,$d,&$possible):array{$now=$this->load($u,$v['operation']);if($now===null||$now['row']!==$s['intent']['row']){throw new StorageException('Retained migration changed before reapproval.','account.migration_changed');}$f=$this->facts($u,$v['subject'],$v['operation']);$this->check($u,$v,$source,$proof,$s['facts'],'reapprove',$now);$physical=$this->physical($u,$v['subject']);$this->samePhysical($v,$physical,$physical['managed']);
                    if($cancel){if($now['body']['state']!=='reserved'||$physical['managed']||$f['account_stamp']!==$now['body']['review']['account']){throw new SecurityException('Permanent sealing cannot be rolled back; explicitly resume migration.','account.migration_irreversible');}$after=$u->invoke($d[9],[$u,$f,$v,'cancel',$now['body']['old']],'account.migration_directory');$intent=$this->save($u,$v,'cancelled',$after,$now);$possible=true;$this->notify($u,'cancelled',$v,$f,$after);return ['intent'=>$intent,'facts'=>$after];}
                    if($now['body']['state']==='cancelled'){if(!$physical['managed']||($physical['migration']['state']??null)!=='prepared'){throw new SecurityException('Cancellation reconciliation requires the exact pending seal.','account.migration_irreversible');}$after=$u->invoke($d[9],[$u,$f,$v,'reserve',null],'account.migration_directory');$intent=$this->save($u,$v,'reserved',$after,$now);$this->notify($u,'reapproved',$v,$f,$after);return ['intent'=>$intent,'facts'=>$after];}$intent=$this->save($u,$v,$now['body']['state'],$f,$now);$this->notify($u,'reapproved',$v,$f,$f);return ['intent'=>$intent,'facts'=>$f];
                },null,function(array $a)use($u,$v,$source,$proof,$cancel,&$ready):void{$this->check($u,$v,$source,$proof,$a['facts'],$cancel?'cancel_commit':'reapprove_commit',$a['intent'],$cancel);if($cancel){$physical=$this->physical($u,$v['subject']);if($physical['managed']){throw new StorageException('A cancellation callback sealed the legacy slot.','account.migration_changed');}$this->samePhysical($v,$physical);}$ready=true;});$possible=true;
                if($cancel){$u=$this->unit();$u->run(function()use($u,$v,$source,$proof,$refreshed):void{$now=$this->load($u,$v['operation']);if($now===null||$now['row']!==$refreshed['intent']['row']||$now['body']['state']!=='cancelled'){throw new StorageException('Cancelled migration changed after commit.','account.migration_changed');}$this->check($u,$v,$source,$proof,$refreshed['facts'],'cancel_return',$now,true);$physical=$this->physical($u,$v['subject']);if($physical['managed']){throw new StorageException('Physical state changed after cancellation commit.','account.migration_changed');}$this->samePhysical($v,$physical);});return ['operation'=>$v['operation'],'cancelled'=>true];}return $this->advance($v,$source,$proof,$refreshed['intent']);
            }catch(\Throwable $e){if($possible||$ready||$u->committed()){throw new StorageException('Retained migration completion is unknown; never reopen legacy state.','account.completion_unknown',$e);}throw $e;}
        });
    }
    public function __debugInfo():array {return ['factor_migration'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current migration dependencies.','configuration.factor_migration');}
    public function __wakeup():void {throw new ConfigurationException('Reload current migration state.','configuration.factor_migration');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Migration coordinators are immutable.','configuration.immutable');}
}
