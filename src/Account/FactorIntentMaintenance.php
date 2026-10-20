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

/** Internal explicit page maintenance. Purging closes the worker authority; physical receipts are never deleted. */
final class FactorIntentMaintenance
{
    private $dependencies;
    public function __construct(PDO $pdo,string $site,string $scope,string $epoch,HmacKeys $keys,TotpFactors $managed,LocalEpochFence $fence,callable $decode,callable $stopped,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events,Policy $policy,Clock $clock,string $profile='migration')
    {
        if(!in_array($profile,['migration','operations','restoration'],true)){throw new ConfigurationException('Use a fixed intent-history purpose.','configuration.factor_migration');}self::label($site);self::label($scope);self::id($epoch);if(!$fence->matches($site,$scope,$epoch)||!$managed->boundTo($fence)){throw new ConfigurationException('Use the exact registered migration history.','configuration.factor_migration');}new SqlTransaction($pdo,$clock,$policy->ioMilliseconds());
        $this->dependencies=static function()use($pdo,$site,$scope,$epoch,$keys,$managed,$fence,$decode,$stopped,$authority,$budgets,$approval,$audit,$events,$policy,$clock,$profile):array{return [$pdo,$site,$scope,$epoch,$keys,$managed,$fence,$decode,$stopped,$authority,$budgets,$approval,$audit,$events,$policy,$clock,$profile];};
    }
    private function d():array{return ($this->dependencies)();}
    private function purpose():string{return ['migration'=>'factor_migration_maintenance','operations'=>'factor_operation_maintenance','restoration'=>'factor_restoration_maintenance'][$this->d()[16]];}
    private function signingPurpose():string{return ['migration'=>'SoSecurity.Account.MigrationMaintenance.Review.1.','operations'=>'SoSecurity.Account.OperationMaintenance.Review.1.','restoration'=>'SoSecurity.Account.RestorationMaintenance.Review.1.'][$this->d()[16]];}
    private function terminal(array $body):bool
    {
        if($this->d()[16]==='restoration'){return $body['state']==='cleaned'||($body['state']==='activated'&&$body['old_cleaned']);}
        if($this->d()[16]==='migration'){return in_array($body['state'],['activated','cancelled'],true);}
        if(in_array($body['state'],['cleaned','abandoned'],true)){return true;}
        return $body['state']==='completed'&&($body['purpose']==='factor_enrollment'||in_array($body['review']['action'],['regenerate','reencrypt'],true));
    }
    private function unit():SqlTransaction{$d=$this->d();return new SqlTransaction($d[0],$d[15],$d[14]->ioMilliseconds());}
    private function ledger(SqlTransaction $u):Ledger{$d=$this->d();return new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[14],2,$d[6]->binding());}
    private static function json(array $value):string{return json_encode($value,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
    private static function label(string $value):void{Guard::label($value);if(preg_match('//u',$value)!==1){throw new ValidationException('Use bounded UTF-8 maintenance labels.','account.migration_input');}}
    private static function id(string $value):void{if(!preg_match('/\A[a-f0-9]{64}\z/D',$value)){throw new ValidationException('Use exact maintenance identifiers.','account.migration_input');}}
    private static function pageInput(string $mode,int $limit,string $after):void{if(!in_array($mode,['purge','rekey'],true)||$limit<1||$limit>50){throw new ValidationException('Use a fixed mode and a page of 1-50 records.','account.migration_input');}if($after!==''){self::id($after);}}
    private function budget(SqlTransaction $u,string $phase,string $source,string $operation):void{$d=$this->d();if($u->invoke($d[10],[$this->purpose(),$phase,$source,$operation],'account.migration_budget')!==true){throw new SecurityException('Migration history budget denied.','account.migration_budget');}}
    private function guard(SqlTransaction $u,string $phase,?array $context):void{$d=$this->d();$d[5]->enlistWorkers($d[0]);$before=$this->ledger($u)->checkpoint();if($u->invoke($d[9],[$this->purpose(),$phase,$d[2],$context],'account.migration_authority')!==true){throw new SecurityException('Current migration history authority required.','account.migration_denied');}if($this->ledger($u)->checkpoint()!==$before){throw new StorageException('History changed during current actor checks.','account.migration_changed');}}
    private function approval(SqlTransaction $u,string $phase,array $context,array $proof):void{$d=$this->d();if($u->invoke($d[11],[$phase,$context,$proof],'account.migration_approval')!==true){throw new SecurityException('Independent exact history approval required.','account.migration_denied');}}
    private function verifyApproval(array $context,array $proof):void
    {
        $d=$this->d();$deadline=new Deadline($d[14]->ioMilliseconds());$before=$d[15]->now();try{$ok=call_user_func($d[11],'verify',$context,$proof);}catch(\Throwable $error){throw new DependencyException('Migration history approval unavailable.','account.migration_approval');}$deadline->check('account.migration_expired');$now=$d[15]->now();if($now<$before||$now>=$context['expires']||$now<$context['issued']){throw new SecurityException('Migration history approval expired.','account.migration_expired');}if($ok!==true){throw new SecurityException('Independent exact history approval required.','account.migration_denied');}
    }
    private function stopped(SqlTransaction $u,array $frame,string $phase):void{$d=$this->d();if($d[16]!=='migration'||$frame['mode']!=='purge'){return;}foreach($frame['actions'] as $id=>$revision){if($u->invoke($d[8],['maintenance_'.$phase,$frame['migrations'][$id]['body']['review']],'account.migration_stop')!==true){throw new SecurityException('Current old-deployment stop evidence required.','account.migration_stop');}}}
    private function requested(SqlTransaction $u,callable $body,string $source,string $operation,string $phase,?array $context=null,?callable $finish=null)
    {
        $rejected=null;$result=$u->run($body,function()use($u,$source,$operation,$phase,$context,&$rejected):bool{try{$this->budget($u,'public',$source,$operation);$this->guard($u,$phase,$context);return true;}catch(\Throwable $error){$rejected=$error;return false;}},$finish);if($rejected!==null){throw $rejected;}return $result;
    }
    private function physical(SqlTransaction $u,string $subject,bool $closed):array{$d=$this->d();return $u->invoke($closed?[$d[5],'migrationSnapshotClosed']:[$d[5],'migrationSnapshot'],$closed?[$d[6],$d[2],$subject]:[$d[2],$subject],'account.migration_source');}
    private function frame(SqlTransaction $u,string $mode,int $limit,string $after,bool $closed):array
    {
        $d=$this->d();$l=$this->ledger($u);$root=$l->checkpoint();$rows=[];$scanned=[];$migrations=[];$metadata=[];$actions=[];$physical=[];$foreign=0;$protected=0;
        foreach($l->bodyPage($limit,$after) as $row){
            $id=$row['record_id'];$scanned[]=$id;$rows[$id]=$row;if(($metadata[$id]['reason']??null)==='linked_cursor'){continue;}$header=$row;unset($header['payload']);$value=json_decode($row['payload'],true,8);
            if(!is_array($value)||!in_array($value['purpose']??null,$d[16]==='migration'?['factor_migration']:($d[16]==='restoration'?['factor_restoration']:['factor_operation','factor_enrollment']),true)){$metadata[$id]=['record'=>$header,'subject'=>'','state'=>'other','reason'=>'foreign'];++$foreign;continue;}
            $migration=$u->invoke($d[7],$d[16]==='restoration'?[$row,$u]:[$row],'account.migration_corrupt');$migrations[$id]=$migration;$body=$migration['body'];$reason='retained';$eligible=false;
            if($mode==='rekey'){$eligible=$row['seal_key']!==$l->currentKeyId();$reason=$eligible?'rekey':'current_key';}
            elseif(!$this->terminal($body)){$reason='pending';++$protected;}
            elseif($d[16]==='restoration'&&$body['retain_until']>$u->now()){$reason='restoration_retention';}
            elseif(($body['state']==='abandoned'&&$body['resolution']['retain_until']>$u->now())){$reason='resolution_retention';}
            elseif($row['retire_at']>$u->now()){$reason='retention';}
            else{
                $eligible=true;$reason='purge';
                if($d[16]==='migration'&&$body['state']==='cancelled'){
                    $p=$this->physical($u,$body['review']['subject'],$closed);$physical[$id]=$p;
                    // Any pending receipt protects the slot, including a mismatched/corrupt workflow association.
                    if($p['managed']&&($p['migration']['state']??null)==='prepared'){$eligible=false;$reason='physical_pending';++$protected;}
                }
            }
            if($eligible){$actions[$id]=$row['revision'];}
            if($d[16]==='restoration'&&$migration['linked_cursor']!==null&&($mode==='rekey'||$eligible)){$cursor=$migration['linked_cursor'];$cursorId=$cursor['record_id'];if(($metadata[$cursorId]['reason']??null)==='foreign'){--$foreign;}$rows[$cursorId]=$cursor;if($mode==='purge'||$cursor['seal_key']!==$l->currentKeyId()){$actions[$cursorId]=$cursor['revision'];}$cursorHeader=$cursor;unset($cursorHeader['payload']);$metadata[$cursorId]=['record'=>$cursorHeader,'subject'=>$body['review']['subject'],'state'=>'cursor','reason'=>'linked_cursor'];}
            $metadata[$id]=['record'=>$header,'subject'=>$body['review']['subject'],'state'=>$body['state'],'reason'=>$reason];
        }
        if($l->checkpoint()!==$root){throw new StorageException('Migration history changed during inspection.','account.migration_changed');}
        $rootRotation=$mode==='rekey'&&$root['seal_key']!==$l->currentKeyId();$ids=$scanned;$count=count($ids);$selection=hash('sha256','SoSecurity.Account.MigrationMaintenance.Selection.1.'.self::json([$metadata,$actions,$physical,$rootRotation]));
        return ['mode'=>$mode,'root'=>$root,'rows'=>$rows,'migrations'=>$migrations,'metadata'=>$metadata,'physical'=>$physical,'actions'=>$actions,'root_rotation'=>$rootRotation,'selection'=>$selection,'counts'=>['examined'=>count($rows),'eligible'=>count($actions),'foreign'=>$foreign,'protected'=>$protected,'next'=>$count===$limit?$ids[$count-1]:'','complete'=>$count<$limit]];
    }
    private function context(SqlTransaction $u,array $frame,int $limit,string $after):array
    {
        $d=$this->d();$v=['format'=>1,'purpose'=>$this->purpose(),'site'=>$d[1],'scope'=>$d[2],'epoch'=>$d[3],'authority'=>$d[6]->binding(),'mode'=>$frame['mode'],'limit'=>$limit,'after'=>$after,'history'=>Ledger::digest($frame['root']),'selection'=>$frame['selection'],'target_key'=>$d[4]->currentId(),'issued'=>$u->now(),'expires'=>$u->now()+300,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[4]->currentId()];$v['seal']=bin2hex($d[4]->sign($this->signingPurpose().self::json($v)));return $v;
    }
    private function input(array $v):array
    {
        $fields=['format','purpose','site','scope','epoch','authority','mode','limit','after','history','selection','target_key','issued','expires','nonce','key','seal'];$keys=array_keys($v);sort($keys);$wanted=$fields;sort($wanted);
        if($keys!==$wanted||$v['format']!==1||$v['purpose']!==$this->purpose()||!is_string($v['mode'])||!is_int($v['limit'])||!is_string($v['after'])||!is_int($v['issued'])||!is_int($v['expires'])||$v['issued']<0||$v['expires']<=$v['issued']||$v['expires']-$v['issued']>300){throw new ValidationException('Invalid history maintenance review.','account.migration_input');}self::pageInput($v['mode'],$v['limit'],$v['after']);
        foreach(['site','scope'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid maintenance labels.','account.migration_input');}self::label($v[$key]);}foreach(['epoch','authority','history','selection','nonce','seal'] as $key){if(!is_string($v[$key])){throw new ValidationException('Invalid maintenance digest.','account.migration_input');}self::id($v[$key]);}foreach(['key','target_key'] as $key){if(!is_string($v[$key])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v[$key])){throw new ValidationException('Invalid maintenance key.','account.migration_input');}}
        $ordered=[];foreach($fields as $key){$ordered[$key]=$v[$key];}$v=$ordered;$seal=$v['seal'];unset($v['seal']);$d=$this->d();if($v['site']!==$d[1]||$v['scope']!==$d[2]||$v['epoch']!==$d[3]||$v['authority']!==$d[6]->binding()||$v['target_key']!==$d[4]->currentId()||!$d[4]->verify($v['key'],$this->signingPurpose().self::json($v),hex2bin($seal))){throw new SecurityException('History maintenance review cannot be authenticated.','account.migration_denied');}return $v+['seal'=>$seal];
    }
    private static function proof(array $proof):void{$keys=array_keys($proof);sort($keys);if($keys!==['code','type']||$proof['type']!=='approved'||!is_string($proof['code'])||$proof['code']===''||strlen($proof['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$proof['code'])){throw new ValidationException('Use bounded independent history approval.','account.migration_input');}}
    private function same(array $context,array $frame):void{if($context['history']!==Ledger::digest($frame['root'])||$context['selection']!==$frame['selection']){throw new StorageException('History maintenance review is stale.','account.migration_changed');}}
    private function deadline(SqlTransaction $u,array $context):void{if($u->now()<$context['issued']||$u->now()>=$context['expires']){throw new SecurityException('History maintenance review expired.','account.migration_expired');}}
    private function checkFrame(SqlTransaction $u,array $context,array $proof,string $source,array $expected,string $phase,bool $closed):void
    {
        $this->budget($u,'final',$source,$context['nonce']);$this->approval($u,$phase,$context,$proof);$this->stopped($u,$expected,$phase);$this->guard($u,$phase,$context);$this->deadline($u,$context);$this->same($context,$this->frame($u,$context['mode'],$context['limit'],$context['after'],$closed));
    }
    public function review(string $mode,string $source,int $limit=20,string $after=''):array{return $this->reviewUsing($mode,$source,$limit,$after,false);}
    /** Caller must already hold this exact durably closed EX drain; this method never opens or closes it. */
    public function reviewClosed(string $mode,string $source,int $limit=20,string $after=''):array{return $this->reviewUsing($mode,$source,$limit,$after,true);}
    private function reviewUsing(string $mode,string $source,int $limit,string $after,bool $closed):array
    {
        self::pageInput($mode,$limit,$after);self::label($source);$d=$this->d();$method=$closed?'closedWork':'work';return $d[6]->$method(function()use($mode,$source,$limit,$after,$closed):array{$u=$this->unit();$operation=bin2hex(random_bytes(32));$state=$this->requested($u,function()use($u,$mode,$limit,$after,$closed):array{$f=$this->frame($u,$mode,$limit,$after,$closed);return ['frame'=>$f,'context'=>$this->context($u,$f,$limit,$after)];},$source,$operation,'review',null,function(array $s)use($u,$source,$closed):void{$this->budget($u,'final',$source,$s['context']['nonce']);$this->stopped($u,$s['frame'],'review');$this->guard($u,'review_return',$s['context']);$this->same($s['context'],$this->frame($u,$s['context']['mode'],$s['context']['limit'],$s['context']['after'],$closed));});return ['context'=>$state['context'],'records'=>$state['frame']['metadata'],'counts'=>$state['frame']['counts']];});
    }
    private function inspectApproval(array $context,string $source,array $proof,bool $closed):array
    {
        $u=$this->unit();$frame=$this->requested($u,function()use($u,$context,$proof,$source,$closed):array{$f=$this->frame($u,$context['mode'],$context['limit'],$context['after'],$closed);$this->same($context,$f);$this->checkFrame($u,$context,$proof,$source,$f,'inspect',$closed);return $f;},$source,$context['nonce'],'request',$context);$this->verifyApproval($context,$proof);return $frame;
    }
    public function maintain(array $context,string $source,array $proof):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);if($v['mode']!=='rekey'){throw new ConfigurationException('Purging requires explicit worker drain.','configuration.factor_migration');}$d=$this->d();$finished=false;return $this->fencedOutcome('work',function()use($v,$source,$proof,&$finished):array{$this->inspectApproval($v,$source,$proof,false);$result=$this->apply($v,$source,$proof,false);$finished=true;return $result;},$finished);
    }
    public function drainAndMaintain(array $context,string $source,array $proof):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);if($v['mode']!=='purge'){throw new ConfigurationException('Drain is only for explicit history purge.','configuration.factor_migration');}$d=$this->d();$frame=$d[6]->work(function()use($v,$source,$proof):array{return $this->inspectApproval($v,$source,$proof,false);});
        if(!$frame['actions']){return $this->noEffect($v,$source,$proof,false);}
        $authorized=false;try{return $d[6]->drain(function()use($v,$source,$proof):array{try{return $this->apply($v,$source,$proof,true);}catch(\Throwable $error){throw new StorageException('History purge completion is unknown; authority remains closed.','account.completion_unknown',$error);}},function()use($v,$source,$proof,$frame,&$authorized):bool{$u=$this->unit();$u->run(function()use($u,$v,$source,$proof,$frame):void{$this->authorizeDrain($u,$v,$proof,$source,$frame);});$authorized=true;return true;});}catch(\Throwable $error){if($authorized){throw new StorageException('History purge completion is unknown; inspect SQL and the exact worker authority.','account.completion_unknown',$error);}throw $error;}
    }
    /** EX is held but still open here. Never re-enter normal physical work from this callback. */
    private function authorizeDrain(SqlTransaction $u,array $v,array $proof,string $source,array $frame):void
    {
        $this->budget($u,'final',$source,$v['nonce']);$this->approval($u,'authorize',$v,$proof);$this->stopped($u,$frame,'authorize');$this->guard($u,'authorize',$v);$this->deadline($u,$v);$l=$this->ledger($u);$ids=array_keys($frame['rows']);if(Ledger::digest($l->checkpoint())!==$v['history']||($ids?$l->readMany($ids):[])!==$frame['rows']){throw new StorageException('History selection changed before drain.','account.migration_changed');}
    }
    public function maintainClosed(array $context,string $source,array $proof):array
    {
        $v=$this->input($context);self::label($source);self::proof($proof);if($v['mode']!=='purge'){throw new ConfigurationException('Use open maintenance for rekey.','configuration.factor_migration');}$d=$this->d();$finished=false;return $this->fencedOutcome('closedWork',function()use($v,$source,$proof,&$finished):array{$this->inspectApproval($v,$source,$proof,true);$result=$this->apply($v,$source,$proof,true);$finished=true;return $result;},$finished);
    }
    private function fencedOutcome(string $method,callable $body,bool &$finished):array
    {
        $d=$this->d();try{return $d[6]->$method($body);}catch(\Throwable $error){if($finished){throw new StorageException('History maintenance completion is unknown; inspect SQL and the exact worker authority.','account.completion_unknown',$error);}throw $error;}
    }
    private function noEffect(array $context,string $source,array $proof,bool $closed):array
    {
        $d=$this->d();$method=$closed?'closedWork':'work';return $d[6]->$method(function()use($context,$source,$proof,$closed):array{$u=$this->unit();return $u->run(function()use($u,$context,$source,$proof,$closed):array{$f=$this->frame($u,$context['mode'],$context['limit'],$context['after'],$closed);$this->checkFrame($u,$context,$proof,$source,$f,'return',$closed);return $f['counts']+['removed'=>0,'resealed'=>0,'root_rotated'=>false,'operation'=>$context['nonce']];});});
    }
    private function verifyResult(SqlTransaction $u,array $v,array $proof,string $source,array $result,string $phase,bool $closed):void
    {
        $this->budget($u,'final',$source,$v['nonce']);$this->approval($u,$phase,$v,$proof);$this->stopped($u,$result['frame'],$phase);$this->guard($u,$phase,$v);$this->deadline($u,$v);$l=$this->ledger($u);$ids=array_keys($result['frame']['rows']);if($l->checkpoint()!==$result['root']||($ids?$l->readMany($ids):[])!==$result['rows']){throw new StorageException('History maintenance changed after effects.','account.migration_changed');}
        foreach($result['frame']['physical'] as $id=>$physical){if($this->physical($u,$result['frame']['migrations'][$id]['body']['review']['subject'],$closed)!==$physical){throw new StorageException('A cancellation receipt changed during purge.','account.migration_changed');}}if($l->checkpoint()!==$result['root']){throw new StorageException('History changed during physical inspection.','account.migration_changed');}
    }
    private function apply(array $v,string $source,array $proof,bool $closed):array
    {
        $u=$this->unit();$d=$this->d();$possible=false;$ready=false;try{
            $result=$u->run(function()use($u,$v,$source,$proof,$closed,$d,&$possible):array{$f=$this->frame($u,$v['mode'],$v['limit'],$v['after'],$closed);$this->checkFrame($u,$v,$proof,$source,$f,'current',$closed);$l=$this->ledger($u);$counts=$f['counts']+['removed'=>0,'resealed'=>0,'root_rotated'=>false,'operation'=>$v['nonce']];
                if($v['mode']==='purge'&&$f['actions']){$possible=true;$counts['removed']=$l->remove($f['actions']);}
                if($v['mode']==='rekey'){$possible=$f['root_rotation']||count($f['actions'])>0;$counts['root_rotated']=$l->rotateRoot();if($f['actions']){$counts['resealed']=$l->reseal($f['actions']);}}
                $ids=array_keys($f['rows']);$rows=$ids?$l->readMany($ids):[];$root=$l->checkpoint();if($possible&&($u->invoke($d[12],[$v,$counts,$v['nonce']],'account.migration_audit')!==true||$u->invoke($d[13],[(['migration'=>'factor_migration_history_','operations'=>'factor_operation_history_','restoration'=>'factor_restoration_history_'][$d[16]]).($v['mode']==='purge'?'purged':'rekeyed'),$v,$counts,$v['nonce']],'account.migration_event')!==true)){throw new StorageException('Same-PDO history audit and notification required.','account.migration_audit');}return ['frame'=>$f,'rows'=>$rows,'root'=>$root,'counts'=>$counts];
            },null,function(array $r)use($u,$v,$source,$proof,$closed,&$ready):void{$this->verifyResult($u,$v,$proof,$source,$r,'commit',$closed);$ready=true;});$finish=$this->unit();$finish->run(function()use($finish,$v,$source,$proof,$result,$closed):void{$this->verifyResult($finish,$v,$proof,$source,$result,'return',$closed);});return $result['counts'];
        }catch(\Throwable $error){if($possible||$ready||$u->committed()){throw new StorageException('History maintenance completion is unknown; inspect audit and obtain a new review.','account.completion_unknown',$error);}throw $error;}
    }
    public function __debugInfo():array{return ['factor_migration_maintenance'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload history maintenance dependencies.','configuration.factor_migration');}
    public function __wakeup():void{throw new ConfigurationException('Reload history maintenance dependencies.','configuration.factor_migration');}
    public function __set(string $name,$value):void{throw new ConfigurationException('History maintenance is immutable.','configuration.immutable');}
}
