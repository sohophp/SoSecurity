<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;

/** Fixed cross-generation fence and worker-root transition. Never activates accounts or grants normal work. */
final class StateWorkerHandoff
{
    private $dependencies;private $image;private $initial=false;private $execution;
    private function __construct(LocalStateWitness $w,CompositeStateSnapshot $source,SqlStateSnapshot $sql,string $sqlName,LocalEpochFence $old,StateBoundary $oldBoundary,LocalEpochFence $next,StateBoundary $nextBoundary,FactorRecovery $recovery,\SoSecurity\Mfa\TotpFactors $factors,string $site,string $scope,string $epoch,HmacKeys $keys,Policy $policy,Clock $clock)
    {
        $context=$recovery->stateHistory($sql->connection(),$factors,$site,$scope,$epoch,$keys,$clock);$types=Ledger::recordTypes();$types['payload']='blob:16384';
        if($w->format()!==3||!$w->matches($site,$scope,$epoch)||!$w->usesKeys($keys)||!$w->coversSnapshot($source)||!$source->contains($sqlName,$sql)||!$old->boundToStateBoundary($oldBoundary)||!$oldBoundary->recoveryAuthority($w)||!$nextBoundary->boundTo($w)||!$next->boundToStateBoundary($nextBoundary)||$old->sameStateBoundary($next)||!$old->usesKeys($keys)||!$next->usesKeys($keys)||!$w->coversFence($old)||!$w->coversFence($next)||$old->storageDomain()===$next->storageDomain()||!$old->matches($site,$scope,$epoch)||!$next->matches($site,$scope,$epoch)||$context===null||$context['format']!==2||$context['authority']!==$old->binding()||$context['maximum']!==$policy->maximumEntries()||$context['policy']!==hash('sha256','SoSecurity.Account.FencedLedger.2.'.$policy->fingerprint().$old->binding())||!$sql->containsDefinition('sosecurity_account_roots',Ledger::rootTypes(),['namespace'],[])||!$sql->containsDefinition('sosecurity_account_records',$types,['namespace','record_id'],[])){self::invalid();}
        $oldContext=json_encode(['SoSecurity.Account.LocalEpochFence.2',$site,$scope,$epoch,$oldBoundary->binding()]);$nextContext=json_encode(['SoSecurity.Account.LocalEpochFence.2',$site,$scope,$epoch,$nextBoundary->binding()]);
        $this->dependencies=static function()use($w,$source,$sql,$sqlName,$old,$next,$context,$oldContext,$nextContext,$keys,$policy,$clock,$epoch):array{return [$w,$source,$sql,$sqlName,$old,$next,$context,$oldContext,$nextContext,$keys,$policy,$clock,$epoch];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use the exact covered old and new worker generations.','configuration.worker_handoff');}
    /** @return never */
    private static function changed():void{throw new StorageException('Worker state is outside its fixed original and confirmed replacement images.','account.worker_changed');}
    private function d():array{return ($this->dependencies)();}
    private function m():array{return ($this->image)();}
    private static function authority(array $state):string{unset($state['key'],$state['seal']);return hash('sha256',json_encode($state,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
    public static function prepare(LocalStateWitness $w,CompositeStateSnapshot $source,SqlStateSnapshot $sql,string $sqlName,LocalEpochFence $old,StateBoundary $oldBoundary,LocalEpochFence $next,StateBoundary $nextBoundary,FactorRecovery $recovery,\SoSecurity\Mfa\TotpFactors $factors,string $site,string $scope,string $epoch,HmacKeys $keys,Policy $policy,Clock $clock,callable $budget):self
    {
        $self=new self($w,$source,$sql,$sqlName,$old,$oldBoundary,$next,$nextBoundary,$recovery,$factors,$site,$scope,$epoch,$keys,$policy,$clock);$state=$w->inspect($budget);if($state['status']!=='quarantined'||!isset($state['recovery_audit'])||(isset($state['remediation'])&&$state['remediation']['phase']!=='complete')){self::invalid();}
        $before=$source->digest();$frames=$self->frames();if($frames[0]===null||$frames[1]!==null){self::changed();}$view=$self->capture(false);if($view[0]!==$before){self::changed();}$root=$view[1];if($root['revision']>=PHP_INT_MAX-1){self::changed();}$after=$root;$after['policy']=hash('sha256','SoSecurity.Account.FencedLedger.2.'.$policy->fingerprint().$next->binding());++$after['revision'];$after['observed_at']=$clock->now();$after['seal_key']=$keys->currentId();$after['seal']=bin2hex($keys->sign(LedgerState::encoded($after,true)));
        $m=['format'=>1,'context'=>$w->binding(),'generation'=>$w->generation(),'source'=>$source->fingerprint(),'sql'=>$sql->fingerprint(),'sql_name'=>$sqlName,'from'=>$old->binding(),'to'=>$next->binding(),'namespace'=>$self->d()[6]['namespace'],'old_root'=>$root,'next_root'=>$after,'old_frame'=>$frames[0],'closed_frame'=>$self->frame(false),'next_frame'=>$self->frame(true),'authority'=>self::authority($state),'observed'=>$before];$self->load($m);$self->initial=true;if($self->observed()!==$before){self::changed();}return $self;
    }
    public static function resume(LocalStateWitness $w,CompositeStateSnapshot $source,SqlStateSnapshot $sql,string $sqlName,LocalEpochFence $old,StateBoundary $oldBoundary,LocalEpochFence $next,StateBoundary $nextBoundary,FactorRecovery $recovery,\SoSecurity\Mfa\TotpFactors $factors,string $site,string $scope,string $epoch,HmacKeys $keys,Policy $policy,Clock $clock,array $manifest):self
    {
        $self=new self($w,$source,$sql,$sqlName,$old,$oldBoundary,$next,$nextBoundary,$recovery,$factors,$site,$scope,$epoch,$keys,$policy,$clock);$self->load($manifest);return $self;
    }
    private function frame(bool $next):string{$d=$this->d();$state=$next?'open':'closed';return $state."\n".$d[9]->currentId()."\n".bin2hex($d[9]->sign($d[$next?8:7]."\n".$state))."\n";}
    private function load(array $m):void
    {
        if(!StateWorkerManifest::valid($m)){self::invalid();}$d=$this->d();foreach(['context'=>$d[0]->binding(),'generation'=>$d[0]->generation(),'source'=>$d[1]->fingerprint(),'sql'=>$d[2]->fingerprint(),'sql_name'=>$d[3],'from'=>$d[4]->binding(),'to'=>$d[5]->binding(),'namespace'=>$d[6]['namespace'],'closed_frame'=>$this->frame(false),'next_frame'=>$this->frame(true)] as $k=>$v){if($m[$k]!==$v){self::invalid();}}
        $before=LedgerState::authenticate($m['old_root'],true,$m['namespace'],$d[12],$d[6]['policy'],2,$d[10]->maximumEntries(),$d[9],$d[11]->now());$expected=$before;$expected['policy']=hash('sha256','SoSecurity.Account.FencedLedger.2.'.$d[10]->fingerprint().$d[5]->binding());++$expected['revision'];$expected['observed_at']=$m['next_root']['observed_at'];$expected['seal_key']=$d[9]->currentId();$expected['seal']=bin2hex($d[9]->sign(LedgerState::encoded($expected,true)));if($expected!==$m['next_root']||$expected['observed_at']<$before['observed_at']||$expected['observed_at']>$d[11]->now()){self::invalid();}
        $parts=explode("\n",$m['old_frame']);if(!$d[9]->verify($parts[1],$d[7]."\n".$parts[0],hex2bin($parts[2]))){self::invalid();}$m=json_decode(json_encode($m,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE),true,5);$this->image=static function()use($m):array{return $m;};
    }
    private function frames():array
    {
        $d=$this->d();$a=$d[4]->recoveryImage($d[0]);$b=$d[5]->recoveryImage($d[0]);$dir=$d[5]->storageDomain()['path'];$names=[];foreach(new \DirectoryIterator($dir) as $entry){if(!$entry->isDot()){$names[]=$entry->getFilename();}}
        $expected=hash('sha256',$d[8]).'.fence';if($b===null?count($names)!==0:($names!==[$expected])){self::changed();}return [$a,$b];
    }
    /** Authenticate every retained worker record; the root update never discards workflows. */
    private function capture(bool $allowNext):array
    {
        $d=$this->d();$cursor=null;$digest=null;$root=null;$count=0;$history=hash_init('sha256');hash_update($history,'SoSecurity.Account.History.1.'.$d[6]['namespace']);$deadline=new Deadline(30000);
        do{$deadline->check('account.witness_timeout');$view=$d[1]->capture([$d[3]=>['root'=>['table'=>'sosecurity_account_roots','key'=>['namespace'=>$d[6]['namespace']],'columns'=>array_keys(Ledger::rootTypes())],'records'=>['table'=>'sosecurity_account_records','key'=>['namespace'=>$d[6]['namespace']],'columns'=>array_keys(Ledger::recordTypes()),'page'=>true,'maximum'=>8,'after'=>$cursor]]]);if($digest!==null&&$digest!==$view->digest()){self::changed();}$digest=$view->digest();$part=$view->part($d[3]);if(!$part instanceof SqlStateCapture){self::invalid();}$row=$part->row('root');if($row===null){self::changed();}
            if($root===null){$policy=$d[6]['policy'];if($allowNext&&$row===$this->m()['next_root']){$policy=$row['policy'];}$root=LedgerState::authenticate($row,true,$d[6]['namespace'],$d[12],$policy,2,$d[10]->maximumEntries(),$d[9],$d[11]->now());}elseif($root!==$row){self::changed();}
            $page=$part->page('records');foreach($page['rows'] as $record){$payload=$record['payload'];unset($record['payload']);$record['body_length']=strlen($payload);$record=LedgerState::authenticate($record,false,$d[6]['namespace'],$d[12],$d[6]['policy'],2,$d[10]->maximumEntries(),$d[9],$d[11]->now());LedgerState::payload($record,$payload);if(++$count>$d[10]->maximumEntries()){self::changed();}hash_update($history,$record['record_id'].$record['seal']);}$cursor=$page['cursor'];
        }while($page['more']);if($count!==$root['entries']||hash_final($history)!==$root['history_digest']){self::changed();}return [$digest,$root];
    }
    public function manifest():array{return $this->m();}
    public function binding():string{return hash('sha256','SoSecurity.Account.StateWorkerHandoff.1.'.StateWorkerManifest::fingerprint($this->m()));}
    public function count():int{return 1;}
    public function boundTo(LocalStateWitness $w):bool{return $this->d()[0]===$w&&$w->coversSnapshot($this->d()[1]);}
    public function usesFences(LocalEpochFence $old,LocalEpochFence $next):bool{return $this->d()[4]===$old&&$this->d()[5]===$next;}
    public function initialFor(array $state):bool{return $this->initial&&self::authority($state)===$this->m()['authority']&&$this->observed()===$this->m()['observed'];}
    public function checkFrame(LocalEpochFence $fence,string $raw):void{$d=$this->d();$m=$this->m();if($fence===$d[4]?($raw!==$m['old_frame']&&$raw!==$m['closed_frame']):($fence!==$d[5]||$raw!==$m['next_frame'])){self::changed();}}
    public function checkClosed(LocalEpochFence $fence,string $raw):void{if($fence!==$this->d()[4]||$raw!==$this->m()['closed_frame']){self::changed();}}
    private function view():array
    {
        $d=$this->d();$m=$this->m();$digest=$d[1]->digest();$frames=$this->frames();if($frames[0]===null){self::changed();}$this->checkFrame($d[4],$frames[0]);if($frames[1]!==null){$this->checkFrame($d[5],$frames[1]);if($frames[0]!==$m['closed_frame']){self::changed();}}$view=$this->capture(true);if($view[0]!==$digest||($view[1]!==$m['old_root']&&$view[1]!==$m['next_root'])){self::changed();}if($view[1]===$m['next_root']&&($frames!==[$m['closed_frame'],$m['next_frame']])){self::changed();}return [$digest,$view[1],$frames];
    }
    public function observed():string{$this->writable();return $this->view()[0];}
    public function guard(LocalStateWitness $w,string $operation):void
    {
        if(!$this->boundTo($w)||!$w->workerHandoffActive($this,$operation)){self::invalid();}if($this->execution!==null){($this->execution)()->check('account.witness_timeout');}$w->workerHandoffCurrent($this,$operation);
    }
    public function apply(LocalStateWitness $w,string $operation,Deadline $deadline):void
    {
        $this->execution=static function()use($deadline):Deadline{return $deadline;};$this->guard($w,$operation);$view=$this->view();if(!$w->workerHandoffActive($this,$operation,$view[0])){self::changed();}$d=$this->d();$m=$this->m();$d[4]->handoff($this,$w,$operation,$d[5]);$this->guard($w,$operation);
        $unit=SqlTransaction::forWorkerHandoff($d[2]->connection(),$d[11],30000,$this,$w,$operation);
        $unit->run(function()use($unit,$w,$operation,$m):void{
            $q=$unit->query('SELECT '.implode(',',array_keys(Ledger::rootTypes())).' FROM '.$unit->prefix().'sosecurity_account_roots WHERE namespace=:namespace'.($unit->driver()==='mysql'?' FOR UPDATE':''),['namespace'=>$m['namespace']]);$raw=$q->fetch(\PDO::FETCH_ASSOC);$q->closeCursor();$this->dependencies($unit);if(!is_array($raw)){self::changed();}$d=$this->d();$row=LedgerState::metadata($raw,true,$m['namespace'],$d[9]);if($row===$m['next_root']){return;}if($row!==$m['old_root']){self::changed();}
            $fields=array_diff(array_keys(Ledger::rootTypes()),['namespace']);$q=$unit->query('UPDATE '.$unit->prefix().'sosecurity_account_roots SET '.implode(',',array_map(static function(string $f):string{return $f.'=:'.$f;},$fields)).' WHERE namespace=:namespace AND revision=:previous_revision AND seal=:previous_seal',$m['next_root']+['previous_revision'=>$row['revision'],'previous_seal'=>$row['seal']]);$count=$q->rowCount();$q->closeCursor();if($count!==1){self::changed();}$this->guard($w,$operation);
        },null,function()use($w,$operation):void{$this->guard($w,$operation);});$this->installed($w,$operation);
    }
    public function installed(LocalStateWitness $w,string $operation):string{$this->guard($w,$operation);$v=$this->view();$m=$this->m();if($v[1]!==$m['next_root']||$v[2]!==[$m['closed_frame'],$m['next_frame']]){self::changed();}return $v[0];}
    private function dependencies(SqlTransaction $unit):void
    {
        foreach(['sosecurity_account_roots','sosecurity_account_records'] as $table){$checks=[];
        if($unit->driver()==='mysql'){
            if((string)$unit->query('SELECT @@GLOBAL.partial_revokes')->fetchColumn()!=='0'){throw new StorageException('Partial revokes prevent this recovery connection from proving unrestricted dependency visibility.','account.containment_visibility');}

            // Recovery uses a dedicated inspection connection. Empty filtered metadata is not proof of no dependencies.
            $identity=$unit->query('SELECT CASE WHEN OCTET_LENGTH(CURRENT_USER())<=320 THEN CURRENT_USER() ELSE NULL END')->fetchColumn();
            if(!is_string($identity)||!preg_match('/\A([A-Za-z0-9_.-]{1,32})@([A-Za-z0-9_.:%\/-]{1,255})\z/D',$identity,$match)){throw new StorageException('Cannot prove database dependency metadata visibility.','account.containment_visibility');}
            $grantee="'".$match[1]."'@'".$match[2]."'";$q=$unit->query("SELECT 1 FROM information_schema.USER_PRIVILEGES WHERE BINARY GRANTEE=:grantee AND PRIVILEGE_TYPE='TRIGGER' LIMIT 1",['grantee'=>$grantee]);$visible=$q->fetchColumn()!==false;$q->closeCursor();
            if(!$visible){throw new StorageException('Dedicated recovery inspection visibility is required; ordinary application connections are not sufficient.','account.containment_visibility');}

            $checks[]=['SELECT 1 FROM information_schema.TRIGGERS WHERE LOWER(TRIGGER_SCHEMA)=LOWER(DATABASE()) AND LOWER(EVENT_OBJECT_TABLE)=:table LIMIT 1',['table'=>$table]];
            $checks[]=['SELECT 1 FROM information_schema.KEY_COLUMN_USAGE WHERE REFERENCED_TABLE_NAME IS NOT NULL AND ((LOWER(TABLE_SCHEMA)=LOWER(DATABASE()) AND LOWER(TABLE_NAME)=:outgoing) OR (LOWER(REFERENCED_TABLE_SCHEMA)=LOWER(DATABASE()) AND LOWER(REFERENCED_TABLE_NAME)=:incoming)) LIMIT 1',['outgoing'=>$table,'incoming'=>$table]];
        }else{
            foreach(['main','temp'] as $schema){$checks[]=["SELECT 1 FROM ".$schema.".sqlite_master WHERE type='trigger' AND tbl_name COLLATE NOCASE=:table LIMIT 1",['table'=>$table]];$checks[]=["SELECT 1 FROM ".$schema.".sqlite_master WHERE name COLLATE NOCASE='pragma_foreign_key_list' LIMIT 1",[]];}
            $checks[]=["SELECT 1 FROM main.sqlite_master m JOIN main.pragma_foreign_key_list(m.name,'main') f WHERE m.type='table' AND (m.name COLLATE NOCASE=:outgoing OR f.\"table\" COLLATE NOCASE=:incoming) LIMIT 1",['outgoing'=>$table,'incoming'=>$table]];
            $checks[]=["SELECT 1 FROM temp.sqlite_master m JOIN main.pragma_foreign_key_list(m.name,'temp') f WHERE m.type='table' AND (m.name COLLATE NOCASE=:outgoing OR f.\"table\" COLLATE NOCASE=:incoming) LIMIT 1",['outgoing'=>$table,'incoming'=>$table]];
        }
        foreach($checks as $check){$q=$unit->query($check[0],$check[1]);$related=$q->fetchColumn()!==false;$q->closeCursor();if($related){throw new StorageException('Fixed account containment requires a table without triggers or foreign-key dependencies.','account.containment_dependencies');}}
        }
    }
    private function writable():void{$unit=SqlTransaction::forObservation($this->d()[2]->connection(),$this->d()[11],30000);$unit->run(function()use($unit):void{$this->dependencies($unit);});}
    public function __debugInfo():array{return ['worker_handoff'=>'[redacted]'];}
    public function __clone(){self::invalid();}public function __sleep():array{self::invalid();}public function __wakeup():void{self::invalid();}public function __set(string $name,$value):void{self::invalid();}
}
