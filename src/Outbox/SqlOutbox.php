<?php
declare(strict_types=1);
namespace SoSecurity\Outbox;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Durable intent, never a network sender. Enqueue/reconcile join the caller; workers/maintenance own short transactions. */
final class SqlOutbox
{
    private $unit;
    private $site;
    private $epoch;
    private $keys;
    private $policy;
    private $authority;
    private $management;
    private $roots;
    private $records;
    private $state;
    private $clock;
    private $observing=false;
    public function __construct(PDO $connection,string $site,string $epoch,HmacKeys $integrityKeys,callable $authority,?Policy $policy=null,?Clock $clock=null,?callable $managementGuard=null,?\SoSecurity\Account\StateAccountConnection $state=null)
    {
        State::actor($site);if(!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)){throw new ConfigurationException('Use an external trusted deployment epoch.','configuration.outbox');}
        $clock=$clock??new SystemClock();if($state!==null){$state->validateOutbox($connection,$site,$epoch,$clock);}$this->state=$state;$this->clock=$clock;
        $this->policy=$policy ?? new Policy();$this->unit=new SqlTransaction($connection,$clock,$this->policy->ioMilliseconds());$this->site=$site;$this->epoch=$epoch;$this->keys=$integrityKeys;$this->authority=$authority;$this->management=$managementGuard;
        $this->roots=$this->unit->prefix().'sosecurity_outbox_roots';$this->records=$this->unit->prefix().'sosecurity_outbox_records';
    }
    private function lock():string {return !$this->observing&&$this->unit->driver()==='mysql'?' FOR UPDATE':'';}
    public function assertStateAccess():void{\SoSecurity\Support\SqlStateAccess::assertActive($this->unit->connection());}
    public function validateDispatchBudgets(\SoSecurity\Account\SendBudgets $budgets):void
    {
        if($this->state===null){if(\SoSecurity\Support\SqlStateAccess::isProtected($this->unit->connection())){throw new ConfigurationException('Declare the complete protected dispatcher connection.','configuration.state_connection');}return;}
        $this->state->validateSendBudgets($budgets);
    }
    private function bytes():string {return SqlSchema::blobLength($this->unit->driver(),'payload_body');}
    private function columns(bool $root=false):string
    {
        $types=$root?Schema::rootTypes():Schema::recordTypes();unset($types['payload_body']);return SqlSchema::boundedProjection($this->unit->driver(),$types);
    }
    private function namespace(string $scope,string $producer):string {return State::namespace($this->site,$scope,$producer);}
    private function authorized(string $action,string $phase,string $scope,string $producer,string $actor,?array $row,bool $management=false,?array $description=null):bool
    {
        $callback=$management?$this->management:$this->authority;
        $metadata=$description ?? ($row===null?[]:State::status($row)->metadata()+['fingerprint'=>$row['fingerprint'],'payload_bytes'=>$row['payload_bytes'],'created_at'=>$row['created_at']]);
        if($description===null&&$row!==null&&$row['status']==='resolved'){$metadata+=['resolution'=>$row['last_error']==='reconcile.received'?'received':'cancelled','evidence_digest'=>$row['token_digest'],'payload_digest'=>$row['payload_digest']];}
        return $callback!==null&&$this->unit->invoke($callback,[$action,$phase,$scope,$producer,$actor,$metadata],$management?'outbox.management':'outbox.authority')===true;
    }
    private function deny():void {throw new SecurityException('Current outbox authority required.','outbox.denied');}
    /** One bounded primary-key read, consumed and closed by its owning unit. @return array|false */
    private function first(string $sql,array $parameters)
    {
        $rows=$this->unit->metadataRows($sql,$parameters);if(!$rows){return false;}
        if(count($rows)!==1||!isset($rows[0])||!is_array($rows[0])){throw new StorageException('Unexpected queue metadata rows.','outbox.corrupt');}return $rows[0];
    }
    /** Bounded metadata keys; missing projected columns must not silently shorten a page. @return string[] */
    private function pageKeys(string $sql,array $parameters):array
    {
        $keys=[];foreach($this->unit->metadataRows($sql,$parameters) as $row){if(!isset($row['key_hash'])||!is_string($row['key_hash'])){throw new StorageException('Invalid outbox metadata key.','outbox.corrupt');}$keys[]=$row['key_hash'];}return $keys;
    }
    private function record(string $scope,string $producer,string $namespace,$key):?array
    {
        if(!is_string($key)||!preg_match('/\A[a-f0-9]{64}\z/D',$key)){throw new StorageException('Invalid outbox candidate key.','outbox.corrupt');}
        $row=$this->first('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash LIMIT 1'.$this->lock(),['namespace'=>$namespace,'key_hash'=>$key]);
        if($row===false){return null;}$row=State::record($row,$this->keys,$this->policy,$namespace,$this->epoch,$scope,$producer,$this->unit->now());unset($row['body_length']);return $row;
    }
    private function body(array $row):string
    {
        $bytes=$row['payload_present']===1?$row['payload_bytes']:0;
        if(!is_int($bytes)||$bytes<0||$bytes>$this->policy->maximumPayloadBytes()){throw new StorageException('Outbox payload length exceeds its policy.','outbox.corrupt');}
        // Bound the returned value as well as the selected row. Never truncate a
        // mismatching body into apparently valid bytes; the caller must reject it.
        $length=$this->bytes();$bodyColumn='CASE WHEN '.$length.'='.$bytes.' THEN payload_body ELSE NULL END AS payload_body';
        $stored=$this->first('SELECT '.$bodyColumn.','.$length.' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash AND '.$length.'=:bytes LIMIT 1'.$this->lock(),['namespace'=>$row['namespace'],'key_hash'=>$row['key_hash'],'bytes'=>$bytes]);
        if(!is_array($stored)||SqlSchema::integer($stored['body_length'])!==$bytes){throw new StorageException('Outbox payload is missing or exceeds its metadata.','outbox.corrupt');}
        // Older PDO SQLite versions return NULL for an empty BLOB. The SQL type/length guard above
        // must prove an actual zero-byte BLOB before normalizing that driver representation.
        $body=$stored['payload_body']===null&&$bytes===0?'':$stored['payload_body'];
        if(!is_string($body)||strlen($body)!==$bytes||($row['payload_present']===1&&!hash_equals($row['payload_digest'],hash('sha256',$body)))){throw new StorageException('Outbox payload bytes changed.','outbox.corrupt');}return $body;
    }
    private function history(string $scope,string $producer,string $namespace):array
    {
        $hash=hash_init('sha256');hash_update($hash,State::historyPrefix($namespace));$entries=0;$maximum=0;$cursor=null;$resolved=0;
        do{
            $limit=min(64,$this->policy->maximumEntries()+1-$entries);
            $parameters=['namespace'=>$namespace];if($cursor!==null){$parameters['after_key']=$cursor;}
            $rows=$this->unit->metadataRows('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace'.($cursor===null?'':' AND key_hash>:after_key').' ORDER BY '.$this->records.'.key_hash LIMIT '.$limit.$this->lock(),$parameters);
            foreach($rows as $raw){
                $row=State::record($raw,$this->keys,$this->policy,$namespace,$this->epoch,$scope,$producer,$this->unit->now());
                if(++$entries>$this->policy->maximumEntries()){throw new StorageException('Outbox history exceeds capacity.','outbox.history');}
                hash_update($hash,json_encode([$row['key_hash'],$row['order_no'],$row['seal']]));$maximum=max($maximum,$row['order_no']);$cursor=$row['key_hash'];
                if($row['format']===2){++$resolved;}
            }
        }while(count($rows)===$limit);
        return ['entries'=>$entries,'maximum'=>$maximum,'digest'=>hash_final($hash),'resolved'=>$resolved];
    }
    private function root(string $scope,string $producer,string $namespace,bool $optional=false):?array
    {
        $raw=$this->first('SELECT '.$this->columns(true).' FROM '.$this->roots.' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$namespace]);
        if($raw===false){if($optional){return null;}throw new StorageException('Outbox namespace is not initialized.','outbox.uninitialized');}
        $root=State::root($raw,$this->keys,$this->policy,$namespace,$this->epoch,$this->unit->now());$history=$this->history($scope,$producer,$namespace);
        if($root['entries']!==$history['entries']||$root['last_order']<$history['maximum']||($root['format']===1&&$history['resolved']>0)||!hash_equals($root['history_digest'],$history['digest'])){throw new StorageException('Outbox history changed or is missing.','outbox.history');}return $root;
    }
    private function saveRow(string $scope,string $producer,array $row,string $body,bool $insert=false):array
    {
        $row=State::seal($row,$this->keys,false);$canonical=[];foreach(State::recordFields() as $name){$canonical[$name]=$row[$name];}$row=$canonical;
        $fields=array_merge(State::recordFields(),['payload_body']);
        $sql=$insert?'INSERT INTO '.$this->records.'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->records.' SET '.implode(',',array_map(static function(string $name):string{return $name.'=:'.$name;},array_diff($fields,['namespace','key_hash']))).' WHERE namespace=:namespace AND key_hash=:key_hash';
        $this->unit->execute($sql,$row+['payload_body'=>$body],['payload_body']);$stored=$this->record($scope,$producer,$row['namespace'],$row['key_hash']);
        if($stored!==$row||$this->body($row)!==$body){throw new StorageException('Outbox record changed during storage.','outbox.corrupt');}return $row;
    }
    private function sync(string $scope,string $producer,array $root,bool $insert=false):array
    {
        if($root['revision']>=PHP_INT_MAX-1){throw new StorageException('Outbox revision exhausted.','outbox.capacity');}
        $history=$this->history($scope,$producer,$root['namespace']);$root['entries']=$history['entries'];$root['history_digest']=$history['digest'];if($history['resolved']>0){$root['format']=2;}++$root['revision'];$root['observed_at']=$this->unit->now();$root=State::seal($root,$this->keys,true);
        $canonical=[];foreach(State::rootFields() as $name){$canonical[$name]=$root[$name];}$root=$canonical;$fields=State::rootFields();
        $sql=$insert?'INSERT INTO '.$this->roots.'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->roots.' SET '.implode(',',array_map(static function(string $name):string{return $name.'=:'.$name;},array_diff($fields,['namespace']))).' WHERE namespace=:namespace';
        $this->unit->execute($sql,$root);if($this->root($scope,$producer,$root['namespace'])!==$root){throw new StorageException('Outbox root changed during storage.','outbox.corrupt');}return $root;
    }
    private function unchanged(string $scope,string $producer,array $root,?array $row=null):void
    {
        if($this->root($scope,$producer,$root['namespace'])!==$root){throw new StorageException('A callback changed the outbox history.','outbox.corrupt');}
        if($row!==null){if($this->record($scope,$producer,$root['namespace'],$row['key_hash'])!==$row){throw new StorageException('Outbox record changed during authority checks.','outbox.corrupt');}$this->body($row);}
    }
    private function current(string $action,string $scope,string $producer,string $actor,array $root,?array $row,bool $management=false,?array $description=null):void
    {
        if(!$this->authorized($action,'current',$scope,$producer,$actor,$row,$management,$description)){$this->deny();}$this->unchanged($scope,$producer,$root,$row);
    }
    private function finish(string $action,string $scope,string $producer,string $actor,array $state,bool $management=false):void
    {
        if(!$this->authorized($action,'commit',$scope,$producer,$actor,$state['row'],$management)){$this->deny();}$this->unchanged($scope,$producer,$state['root'],$state['row']);
        foreach($state['purged_resolutions'] ?? [] as $resolved){
            if(!$this->authorized('purge_resolution','commit',$scope,$producer,$actor,$resolved,true)){$this->deny();}$this->unchanged($scope,$producer,$state['root']);
            if($this->record($scope,$producer,$state['root']['namespace'],$resolved['key_hash'])!==null){throw new StorageException('A callback restored a purged resolution.','outbox.corrupt');}
        }
        if(($state['result'] instanceof Claim&&($state['row']['lease_until']<=$this->unit->now()||$state['row']['deliver_until']<=$this->unit->now()))||(isset($state['valid_until'])&&$state['valid_until']<=$this->unit->now())){throw new SecurityException('Outbox claim expired before commit.','outbox.lease');}
        $this->sync($scope,$producer,$state['root']);
    }
    /** Owned worker/management operation, never nested in a host transaction. */
    private function owned(string $action,string $scope,string $producer,string $actor,callable $operation,bool $management=false)
    {
        $namespace=$this->namespace($scope,$producer);State::actor($actor);
        $state=$this->unit->run(function()use($scope,$producer,$namespace,$operation):array{
            Schema::verify($this->unit);$root=$this->root($scope,$producer,$namespace);return $operation($root);
        },function()use($action,$scope,$producer,$actor,$management):bool{return $this->authorized($action,'request',$scope,$producer,$actor,null,$management);},function(array $state)use($action,$scope,$producer,$actor,$management):void{$this->finish($action,$scope,$producer,$actor,$state,$management);},function(array $state)use($action,$scope,$producer,$actor,$management):void{
            try{
            if(!$this->authorized($action,'return',$scope,$producer,$actor,$state['row'],$management)){$this->deny();}
            if($state['result'] instanceof Claim&&($state['row']['lease_until']<=$this->unit->now()||$state['row']['deliver_until']<=$this->unit->now())){throw new SecurityException('Outbox claim expired during completion; do not send.','outbox.lease');}
            }catch(\Throwable $error){if($action==='rotate'){throw new StorageException('Outbox rotation completion authority is uncertain; committed seals are not rolled back.','outbox.completion_unknown');}throw $error;}
        });
        return $state===null?null:$state['result'];
    }
    public function initialize(string $scope,string $producer,string $actor):bool
    {$this->assertStateAccess();
        $namespace=$this->namespace($scope,$producer);State::actor($actor);
        $state=$this->unit->run(function()use($scope,$producer,$actor,$namespace):array{
            Schema::verify($this->unit);$root=$this->root($scope,$producer,$namespace,true);
            if($root!==null){$this->current('initialize',$scope,$producer,$actor,$root,null,true);return ['root'=>$root,'row'=>null,'result'=>false];}
            if($this->unit->metadataRows('SELECT 1 FROM '.$this->records.' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$namespace])!==[]){throw new StorageException('Do not initialize orphaned outbox history.','outbox.history');}
            if(!$this->authorized('initialize','current',$scope,$producer,$actor,null,true)){$this->deny();}
            $now=$this->unit->now();$root=['namespace'=>$namespace,'format'=>1,'epoch'=>$this->epoch,'policy'=>$this->policy->fingerprint(),'entries'=>0,'history_digest'=>hash('sha256',State::historyPrefix($namespace)),'last_order'=>0,'revision'=>1,'created_at'=>$now,'observed_at'=>$now];
            $root=$this->sync($scope,$producer,$root,true);return ['root'=>$root,'row'=>null,'result'=>true];
        },function()use($scope,$producer,$actor):bool{return $this->authorized('initialize','request',$scope,$producer,$actor,null,true);},function(array $state)use($scope,$producer,$actor):void{$this->finish('initialize',$scope,$producer,$actor,$state,true);},function()use($scope,$producer,$actor):void{if(!$this->authorized('initialize','return',$scope,$producer,$actor,null,true)){$this->deny();}});
        return $state!==null&&$state['result']===true;
    }
    public function enqueue(Message $message,string $actor):Status
    {$this->assertStateAccess();
        $scope=$message->scope();$producer=$message->producer();$namespace=$this->namespace($scope,$producer);State::actor($actor);
        if(strlen($message->body())>$this->policy->maximumPayloadBytes()){throw new SecurityException('Outbox payload exceeds its policy.','outbox.payload');}
        $state=$this->unit->enlist(function()use($message,$scope,$producer,$actor,$namespace):array{
            Schema::verify($this->unit);$root=$this->root($scope,$producer,$namespace);$key=hash('sha256',$message->id());$row=$this->record($scope,$producer,$namespace,$key);
            $description=$row===null?['id'=>$message->id(),'destination'=>$message->destination(),'topic'=>$message->topic(),'aggregate'=>$message->aggregate(),'fingerprint'=>$message->fingerprint(),'payload_bytes'=>strlen($message->body()),'created_at'=>$message->createdAt()]:null;
            $this->current('enqueue',$scope,$producer,$actor,$root,$row,false,$description);
            $now=$this->unit->now();if($message->createdAt()>$now||$message->createdAt()+$this->policy->messageAge()<=$now){throw new SecurityException('Outbox event is future-dated or expired.','outbox.expired');}
            if($row!==null){if($row['fingerprint']!==$message->fingerprint()){throw new SecurityException('Outbox event ID has different content.','outbox.conflict');}return ['root'=>$root,'row'=>$row,'result'=>State::status($row)];}
            if($root['entries']>=$this->policy->maximumEntries()||$root['last_order']>=PHP_INT_MAX-1){throw new SecurityException('Outbox requires bounded maintenance/recovery.','outbox.capacity');}
            ++$root['last_order'];$row=['namespace'=>$namespace,'key_hash'=>$key,'message_id'=>$message->id(),'format'=>1,'epoch'=>$this->epoch,'policy'=>$this->policy->fingerprint(),'delivery_id'=>State::delivery($namespace,$message->id()),'order_no'=>$root['last_order'],'fingerprint'=>$message->fingerprint(),'destination'=>$message->destination(),'topic'=>$message->topic(),'aggregate_id'=>$message->aggregate(),'aggregate_hash'=>State::aggregate($message->aggregate()),'payload_bytes'=>strlen($message->body()),'payload_digest'=>hash('sha256',$message->body()),'payload_present'=>1,'status'=>'pending','attempts'=>0,'cycle_attempts'=>0,'manual_retries'=>0,'created_at'=>$message->createdAt(),'admit_until'=>$message->createdAt()+$this->policy->messageAge(),'deliver_until'=>$message->createdAt()+$this->policy->messageAge(),'available_at'=>$now,'lease_until'=>0,'generation'=>0,'worker_hash'=>str_repeat('0',64),'token_digest'=>str_repeat('0',64),'last_error'=>'','updated_at'=>$now,'sent_at'=>0];
            $row=$this->saveRow($scope,$producer,$row,$message->body(),true);$root=$this->sync($scope,$producer,$root);return ['root'=>$root,'row'=>$row,'result'=>State::status($row)];
        },function()use($scope,$producer,$actor):bool{return $this->authorized('enqueue','request',$scope,$producer,$actor,null);},function(array $state)use($scope,$producer,$actor):void{$this->finish('enqueue',$scope,$producer,$actor,$state);});
        if($state===null){$this->deny();}
        return $state['result'];
    }
    /** A bounded scan starts after an internal order cursor. null means no claim in this scan, not a globally empty queue. */
    public function claim(string $scope,string $producer,string $worker,int $afterOrder=0):?Claim
    {$this->assertStateAccess();
        return $this->claiming($scope,$producer,$worker,$afterOrder,null);
    }
    public function claimMessage(string $scope,string $producer,string $worker,string $id):?Claim
    {$this->assertStateAccess();
        State::idTime($id);return $this->claiming($scope,$producer,$worker,0,hash('sha256',$id));
    }
    /** One exact never-attempted message; never takes over or resumes an existing lease. */
    public function claimInitialMessage(string $scope,string $producer,string $worker,string $id):?Claim
    {return $this->claimSelectedMessage($scope,$producer,$worker,$id,null);}
    private function claimSelectedMessage(string $scope,string $producer,string $worker,string $id,?array $retry):?Claim
    {
        $this->assertStateAccess();State::idTime($id);$secret=bin2hex(random_bytes(32));$action=$retry===null?'claim_initial':'claim_rejected';
        return $this->owned($action,$scope,$producer,$worker,function(array $root)use($scope,$producer,$worker,$id,$secret,$retry,$action):array{
            $this->current($action,$scope,$producer,$worker,$root,null);
            $candidate=$this->selectedCandidate($scope,$producer,$root,$id,$retry);
            if($candidate===null){return ['root'=>$root,'row'=>null,'result'=>null];}
            $row=$candidate['row'];$body=$candidate['body'];$this->current($action,$scope,$producer,$worker,$root,$row);$now=$this->unit->now();
            if($row['deliver_until']<=$now){throw new SecurityException('Selected message expired before claim.','outbox.expired');}
            $row['status']='leased';++$row['attempts'];++$row['cycle_attempts'];++$row['generation'];$row['worker_hash']=hash('sha256','SoSecurity.Outbox.Worker.1.'.$worker);$row['token_digest']=hash('sha256',$secret);$row['lease_until']=min($now+$this->policy->leaseSeconds(),$row['deliver_until']);$row['updated_at']=$now;
            $row=$this->saveRow($scope,$producer,$row,$body);$root=$this->sync($scope,$producer,$root);$message=new Message($scope,$producer,$row['message_id'],$row['destination'],$row['topic'],$row['aggregate_id'],$body);
            return ['root'=>$root,'row'=>$row,'result'=>new Claim(State::status($row),$message,'c1.'.$row['key_hash'].'.'.$secret)];
        });
    }
    private function selectedCandidate(string $scope,string $producer,array $root,string $id,?array $retry=null):?array
    {
        $row=$this->record($scope,$producer,$root['namespace'],hash('sha256',$id));$now=$this->unit->now();
        if($row===null||$row['status']!=='pending'||$row['manual_retries']!==0||$row['payload_present']!==1||$row['available_at']>$now||$row['deliver_until']<=$now){return null;}
        if($retry===null){if($row['attempts']!==0||$row['cycle_attempts']!==0){return null;}}
        elseif($row['attempts']!==$retry['attempt']||$row['cycle_attempts']!==$row['attempts']||$row['cycle_attempts']>=$this->policy->maximumAttempts()||$row['attempts']>=100||$row['lease_until']!==0||$row['last_error']!==$retry['error']||!hash_equals($row['worker_hash'],hash('sha256','SoSecurity.Outbox.Worker.1.'.$retry['worker']))){return null;}
        $blocked=$this->first('SELECT 1 FROM '.$this->records.' WHERE namespace=:namespace AND aggregate_hash=:aggregate AND order_no<:before_order AND status<>:sent AND status<>:resolved ORDER BY order_no LIMIT 1'.$this->lock(),['namespace'=>$root['namespace'],'aggregate'=>$row['aggregate_hash'],'before_order'=>$row['order_no'],'sent'=>'sent','resolved'=>'resolved']);
        if($blocked!==false){return null;}return ['row'=>$row,'body'=>$this->body($row)];
    }
    private function selectedObservation(string $scope,string $producer,string $id,\SoSecurity\Support\Deadline $budget,?array $retry=null):?array
    {
        $original=$this->unit;$unit=SqlTransaction::forObservation($original->connection(),$this->clock,$this->policy->ioMilliseconds());
        $this->unit=$unit;$this->observing=true;
        try{return $unit->run(function()use($unit,$scope,$producer,$id,$retry):?array{Schema::verify($unit);$root=$this->root($scope,$producer,$this->namespace($scope,$producer));return $this->selectedCandidate($scope,$producer,$root,$id,$retry);},null,null,null,$budget);}
        finally{$this->unit=$original;$this->observing=false;}
    }
    private function claimAuthority(string $action,string $phase,string $scope,string $producer,string $worker,?array $row,array $decision=[]):bool
    {
        $metadata=$row===null?[]:State::status($row)->metadata()+['fingerprint'=>$row['fingerprint'],'payload_bytes'=>$row['payload_bytes'],'created_at'=>$row['created_at']];
        $metadata+=$decision;try{return ($this->authority)($action,$phase,$scope,$producer,$worker,$metadata)===true;}
        catch(\Throwable $error){throw new \SoSecurity\Exception\DependencyException('Outbox claim authority unavailable.','outbox.authority');}
    }
    private function completionTime():int
    {
        try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Outbox completion clock unavailable.','outbox.clock');}
        if($now<0||$now>PHP_INT_MAX-31536001){throw new StorageException('Invalid outbox completion clock.','outbox.clock');}return $now;
    }
    public function initialClaimTarget(string $scope,string $producer,string $worker,string $id):string
    {
        if($this->state===null){throw new ConfigurationException('Declare the complete native initial claim graph.','configuration.state_connection');}
        $this->namespace($scope,$producer);State::actor($worker);return $this->state->outboxInitialTarget($scope,$producer,$worker,$id,$this->rotationConfiguration());
    }
    public function claimInitialFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $producer,string $worker,string $id):?Claim
    {
        $this->initialClaimTarget($scope,$producer,$worker,$id);$budget=new \SoSecurity\Support\Deadline($this->policy->ioMilliseconds());$started=$this->completionTime();
        $result=$this->state->outboxInitial($policy,$permission,$scope,$producer,$worker,$id,$this->rotationConfiguration(),function()use($scope,$producer,$worker,$id,$started,$budget):bool{
            $budget->check('outbox.timeout');if(!$this->claimAuthority('claim_initial','admission',$scope,$producer,$worker,null)){return false;}$budget->check('outbox.timeout');$before=$this->completionTime();if($before<$started){throw new StorageException('Initial claim clock moved backwards.','outbox.clock');}
            $candidate=$this->selectedObservation($scope,$producer,$id,$budget);$observed=$this->completionTime();if($observed<$before){throw new StorageException('Initial claim clock moved backwards.','outbox.clock');}
            if($candidate===null){return false;}$allowed=$this->claimAuthority('claim_initial','admitted',$scope,$producer,$worker,$candidate['row']);$budget->check('outbox.timeout');$now=$this->completionTime();if($now<$observed){throw new StorageException('Initial claim clock moved backwards.','outbox.clock');}return $allowed&&$candidate['row']['deliver_until']>$now;
        },function()use($scope,$producer,$worker,$id,$budget):array{
            $budget->check('outbox.timeout');$claim=$this->claimInitialMessage($scope,$producer,$worker,$id);$budget->check('outbox.timeout');if($claim===null){throw new SecurityException('Initial outbox claim changed after admission.','outbox.claim_changed');}return ['claim'=>$claim];
        },$budget);
        $budget->check('outbox.timeout');if($result===null){return null;}$claim=$result['claim'];$now=$this->completionTime();
        if($now<$started||min($claim->status()->leaseUntil(),$claim->status()->deliverUntil())<=$now){throw new StorageException('Initial claim expired during native completion; do not send.','outbox.lease');}return $claim;
    }
    private function dispatchConfiguration(string $configuration):string
    {
        if(strlen($configuration)!==64||preg_match('/\A[a-f0-9]{64}\z/D',$configuration)!==1){throw new ConfigurationException('Use the exact server dispatcher configuration.','configuration.account_dispatch');}
        return hash('sha256','SoSecurity.Outbox.Dispatch.1.'.$this->rotationConfiguration().$configuration);
    }
    public function initialDispatchTarget(string $scope,string $producer,string $worker,string $id,string $configuration):string
    {
        $this->initialClaimTarget($scope,$producer,$worker,$id);return $this->state->outboxDispatchTarget($scope,$producer,$worker,$id,$this->dispatchConfiguration($configuration));
    }
    public function rejectedDispatchTarget(string $scope,string $producer,string $worker,string $id,string $configuration,int $previousAttempt,string $error):string
    {
        $this->initialClaimTarget($scope,$producer,$worker,$id);return $this->state->outboxRejectedDispatchTarget($scope,$producer,$worker,$id,$this->dispatchConfiguration($configuration),$previousAttempt,$error);
    }
    /** These callbacks are trusted server code, never request-provided operations. */
    public function dispatchInitialFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $producer,string $worker,string $id,string $configuration,\SoSecurity\Support\Deadline $requestDeadline,callable $dispatch):?array
    {return $this->dispatchSelectedFor($policy,$permission,$scope,$producer,$worker,$id,$configuration,$requestDeadline,$dispatch,null);}
    public function dispatchRejectedFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $producer,string $worker,string $id,string $configuration,int $previousAttempt,string $error,\SoSecurity\Support\Deadline $requestDeadline,callable $dispatch):?array
    {return $this->dispatchSelectedFor($policy,$permission,$scope,$producer,$worker,$id,$configuration,$requestDeadline,$dispatch,['attempt'=>$previousAttempt,'error'=>$error,'worker'=>$worker]);}
    private function dispatchSelectedFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $producer,string $worker,string $id,string $configuration,\SoSecurity\Support\Deadline $requestDeadline,callable $dispatch,?array $retry):?array
    {
        if($retry===null){$this->initialDispatchTarget($scope,$producer,$worker,$id,$configuration);}else{$this->rejectedDispatchTarget($scope,$producer,$worker,$id,$configuration,$retry['attempt'],$retry['error']);}$action=$retry===null?'claim_initial':'claim_rejected';$budget=new \SoSecurity\Support\Deadline($this->policy->ioMilliseconds());$budget->restrictTo($requestDeadline);$started=$this->completionTime();
        $admission=function()use($scope,$producer,$worker,$id,$started,$budget,$retry,$action):bool{
            $budget->check('outbox.timeout');if(!$this->claimAuthority($action,'admission',$scope,$producer,$worker,null)){return false;}$budget->check('outbox.timeout');$before=$this->completionTime();if($before<$started){throw new StorageException('Dispatch admission clock moved backwards.','outbox.clock');}
            $candidate=$this->selectedObservation($scope,$producer,$id,$budget,$retry);$observed=$this->completionTime();if($observed<$before){throw new StorageException('Dispatch admission clock moved backwards.','outbox.clock');}if($candidate===null){return false;}
            $allowed=$this->claimAuthority($action,'admitted',$scope,$producer,$worker,$candidate['row']);$budget->check('outbox.timeout');$now=$this->completionTime();if($now<$observed){throw new StorageException('Dispatch admission clock moved backwards.','outbox.clock');}return $allowed&&$candidate['row']['deliver_until']>$now;
        };$operation=function()use($scope,$producer,$worker,$id,$dispatch,$budget,$retry):array{
            $budget->check('outbox.timeout');$claim=$this->claimSelectedMessage($scope,$producer,$worker,$id,$retry);if($claim===null){throw new SecurityException('Dispatch candidate changed after admission.','outbox.claim_changed');}$budget->check('outbox.timeout');$result=$dispatch($claim,$budget);$budget->check('outbox.timeout');
            if(!is_array($result)||array_keys($result)!==['state','code']||!in_array($result['state'],['submitted','discarded','deferred','rejected'],true)||!is_string($result['code'])||strlen($result['code'])>64||preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$result['code'])!==1){throw new StorageException('Dispatch result is not a known bounded outcome.','account.delivery_unknown');}return $result;
        };
        $result=$retry===null?$this->state->outboxDispatch($policy,$permission,$scope,$producer,$worker,$id,$this->dispatchConfiguration($configuration),$admission,$operation,$budget):$this->state->outboxRejectedDispatch($policy,$permission,$scope,$producer,$worker,$id,$this->dispatchConfiguration($configuration),$retry['attempt'],$retry['error'],$admission,$operation,$budget);
        $budget->check('outbox.timeout');if($this->completionTime()<$started){throw new StorageException('Dispatch completion clock moved backwards.','outbox.clock');}return $result;
    }
    private function claiming(string $scope,string $producer,string $worker,int $afterOrder,?string $onlyKey):?Claim
    {
        if($afterOrder<0||$afterOrder>=PHP_INT_MAX){throw new ConfigurationException('Use a bounded outbox order cursor.','configuration.outbox');}
        $secret=bin2hex(random_bytes(32));
        return $this->owned('claim',$scope,$producer,$worker,function(array $root)use($scope,$producer,$worker,$afterOrder,$secret,$onlyKey):array{
            $this->current('claim',$scope,$producer,$worker,$root,null);$now=$this->unit->now();
            $parameters=['namespace'=>$root['namespace'],'after_order'=>$afterOrder,'pending'=>'pending','available'=>$now,'leased'=>'leased','expired'=>$now];if($onlyKey!==null){$parameters['selected']=$onlyKey;}
            $candidates=$this->unit->query('SELECT '.SqlSchema::boundedProjection($this->unit->driver(),['key_hash'=>'digest']).' FROM '.$this->records.' WHERE namespace=:namespace AND order_no>:after_order'.($onlyKey===null?'':' AND key_hash=:selected').' AND ((status=:pending AND available_at<=:available) OR (status=:leased AND lease_until<=:expired)) ORDER BY order_no LIMIT '.$this->policy->scanLimit().$this->lock(),$parameters)->fetchAll(PDO::FETCH_COLUMN);
            foreach($candidates as $key){
                $row=$this->record($scope,$producer,$root['namespace'],$key);if($row===null){throw new StorageException('Outbox candidate is missing.','outbox.corrupt');}$this->current('claim',$scope,$producer,$worker,$root,$row);
                if($row['deliver_until']<=$this->unit->now()||$row['attempts']>=100||$row['cycle_attempts']>=$this->policy->maximumAttempts()){
                    $this->body($row);$row['status']='dead';$row['lease_until']=0;$row['last_error']=$row['deliver_until']<=$this->unit->now()?'expired':'attempts_exhausted';$row['updated_at']=$this->unit->now();$this->saveRow($scope,$producer,$row,$this->body($row));$root=$this->sync($scope,$producer,$root);continue;
                }
                $blocked=$this->unit->query('SELECT 1 FROM '.$this->records.' WHERE namespace=:namespace AND aggregate_hash=:aggregate AND order_no<:before_order AND status<>:sent AND status<>:resolved ORDER BY order_no LIMIT 1'.$this->lock(),['namespace'=>$root['namespace'],'aggregate'=>$row['aggregate_hash'],'before_order'=>$row['order_no'],'sent'=>'sent','resolved'=>'resolved'])->fetchColumn();if($blocked!==false){continue;}
                $body=$this->body($row);$now=$this->unit->now();if($row['deliver_until']<=$now){throw new SecurityException('Outbox event expired during claim.','outbox.expired');}
                $row['status']='leased';++$row['attempts'];++$row['cycle_attempts'];++$row['generation'];$row['worker_hash']=hash('sha256','SoSecurity.Outbox.Worker.1.'.$worker);$row['token_digest']=hash('sha256',$secret);$row['lease_until']=min($now+$this->policy->leaseSeconds(),$row['deliver_until']);$row['updated_at']=$now;
                $row=$this->saveRow($scope,$producer,$row,$body);$root=$this->sync($scope,$producer,$root);
                $message=new Message($scope,$producer,$row['message_id'],$row['destination'],$row['topic'],$row['aggregate_id'],$body);$claim=new Claim(State::status($row),$message,'c1.'.$row['key_hash'].'.'.$secret);
                return ['root'=>$root,'row'=>$row,'result'=>$claim];
            }
            return ['root'=>$root,'row'=>null,'result'=>null];
        });
    }
    private function token(string $token):?array
    {
        if(strlen($token)!==132||!preg_match('/\Ac1\.([a-f0-9]{64})\.([a-f0-9]{64})\z/D',$token,$parts)){return null;}return [$parts[1],hash('sha256',$parts[2])];
    }
    private function held(array $row,string $worker,string $digest,bool $sent=false):bool
    {
        if(!hash_equals($row['token_digest'],$digest)||!hash_equals($row['worker_hash'],hash('sha256','SoSecurity.Outbox.Worker.1.'.$worker))){return false;}
        return ($sent&&$row['status']==='sent')||($row['status']==='leased'&&$row['lease_until']>$this->unit->now()&&$row['deliver_until']>$this->unit->now());
    }
    /** Fresh authenticated lease, not a client-built Claim or a descriptive status snapshot. No renewal or new attempt. */
    public function currentClaim(string $scope,string $producer,string $worker,string $token):?Claim
    {$this->assertStateAccess();
        State::group($scope,$producer);State::actor($worker);$parts=$this->token($token);if($parts===null){return null;}
        return $this->owned('current_claim',$scope,$producer,$worker,function(array $root)use($scope,$producer,$worker,$parts,$token):array{
            $row=$this->record($scope,$producer,$root['namespace'],$parts[0]);$this->current('current_claim',$scope,$producer,$worker,$root,$row);
            if($row===null||!$this->held($row,$worker,$parts[1])){return ['root'=>$root,'row'=>null,'result'=>null];}
            $body=$this->body($row);$message=new Message($scope,$producer,$row['message_id'],$row['destination'],$row['topic'],$row['aggregate_id'],$body);
            return ['root'=>$root,'row'=>$row,'result'=>new Claim(State::status($row),$message,$token)];
        });
    }
    private function currentObservation(string $scope,string $producer,string $worker,array $parts,\SoSecurity\Support\Deadline $budget):?array
    {
        $original=$this->unit;$unit=SqlTransaction::forObservation($original->connection(),$this->clock,$this->policy->ioMilliseconds());$this->unit=$unit;$this->observing=true;
        try{return $unit->run(function()use($unit,$scope,$producer,$worker,$parts):?array{
            Schema::verify($unit);$root=$this->root($scope,$producer,$this->namespace($scope,$producer));$row=$this->record($scope,$producer,$root['namespace'],$parts[0]);
            if($row===null||!$this->held($row,$worker,$parts[1])){return null;}$this->body($row);return $row;
        },null,null,null,$budget);}finally{$this->unit=$original;$this->observing=false;}
    }
    public function currentClaimTarget(string $scope,string $producer,string $worker,string $token):string
    {
        if($this->state===null){throw new ConfigurationException('Declare the complete native current claim graph.','configuration.state_connection');}
        $this->namespace($scope,$producer);State::actor($worker);return $this->state->outboxCurrentTarget($scope,$producer,$worker,$token,$this->rotationConfiguration());
    }
    /** Recheck the original active lease; no renewal, takeover, settlement or external effect. */
    public function currentClaimFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $producer,string $worker,string $token):?Claim
    {
        $this->currentClaimTarget($scope,$producer,$worker,$token);$parts=$this->token($token);if($parts===null){throw new ConfigurationException('Use a canonical original claim token.','configuration.state_connection');}$budget=new \SoSecurity\Support\Deadline($this->policy->ioMilliseconds());$started=$this->completionTime();
        $result=$this->state->outboxCurrent($policy,$permission,$scope,$producer,$worker,$token,$this->rotationConfiguration(),function()use($scope,$producer,$worker,$parts,$started,$budget):bool{
            $budget->check('outbox.timeout');if(!$this->claimAuthority('current_claim','admission',$scope,$producer,$worker,null)){return false;}$budget->check('outbox.timeout');$before=$this->completionTime();if($before<$started){throw new StorageException('Claim clock moved backwards.','outbox.clock');}
            $row=$this->currentObservation($scope,$producer,$worker,$parts,$budget);$observed=$this->completionTime();if($observed<$before){throw new StorageException('Claim clock moved backwards.','outbox.clock');}if($row===null){return false;}
            $allowed=$this->claimAuthority('current_claim','admitted',$scope,$producer,$worker,$row);$budget->check('outbox.timeout');$now=$this->completionTime();if($now<$observed){throw new StorageException('Claim clock moved backwards.','outbox.clock');}return $allowed&&min($row['lease_until'],$row['deliver_until'])>$now;
        },function()use($scope,$producer,$worker,$token,$budget):array{
            $budget->check('outbox.timeout');$claim=$this->currentClaim($scope,$producer,$worker,$token);$budget->check('outbox.timeout');if($claim===null){throw new SecurityException('Current claim changed after admission.','outbox.claim_changed');}return ['claim'=>$claim];
        },$budget);
        $budget->check('outbox.timeout');if($result===null){return null;}$claim=$result['claim'];$now=$this->completionTime();if($now<$started||min($claim->status()->leaseUntil(),$claim->status()->deliverUntil())<=$now){throw new StorageException('Current claim expired during native completion; do not send.','outbox.lease');}return $claim;
    }
    public function acknowledge(string $scope,string $producer,string $worker,string $token):bool {$this->assertStateAccess();return $this->settle($scope,$producer,$worker,$token,null,false);}
    public function acknowledgeTarget(string $scope,string $producer,string $worker,string $token):string
    {
        if($this->state===null){throw new ConfigurationException('Declare the complete native acknowledgement graph.','configuration.state_connection');}
        $this->namespace($scope,$producer);State::actor($worker);return $this->state->outboxAcknowledgeTarget($scope,$producer,$worker,$token,$this->rotationConfiguration());
    }
    /** Confirm a known successful outcome under the original live lease; never resume an uncertain receipt. */
    public function acknowledgeFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $producer,string $worker,string $token):bool
    {
        $this->acknowledgeTarget($scope,$producer,$worker,$token);$parts=$this->token($token);if($parts===null){throw new ConfigurationException('Use a canonical original claim token.','configuration.state_connection');}
        $budget=new \SoSecurity\Support\Deadline($this->policy->ioMilliseconds());$started=$this->completionTime();$until=0;
        $result=$this->state->outboxAcknowledge($policy,$permission,$scope,$producer,$worker,$token,$this->rotationConfiguration(),function()use($scope,$producer,$worker,$parts,$started,$budget,&$until):bool{
            $budget->check('outbox.timeout');if(!$this->claimAuthority('acknowledge','admission',$scope,$producer,$worker,null)){return false;}$budget->check('outbox.timeout');$before=$this->completionTime();if($before<$started){throw new StorageException('Acknowledgement clock moved backwards.','outbox.clock');}
            $row=$this->currentObservation($scope,$producer,$worker,$parts,$budget);$observed=$this->completionTime();if($observed<$before){throw new StorageException('Acknowledgement clock moved backwards.','outbox.clock');}if($row===null){return false;}
            $allowed=$this->claimAuthority('acknowledge','admitted',$scope,$producer,$worker,$row);$budget->check('outbox.timeout');$now=$this->completionTime();if($now<$observed){throw new StorageException('Acknowledgement clock moved backwards.','outbox.clock');}$until=min($row['lease_until'],$row['deliver_until']);return $allowed&&$until>$now;
        },function()use($scope,$producer,$worker,$token,$budget,$started,&$until):array{
            $budget->check('outbox.timeout');if(!$this->acknowledge($scope,$producer,$worker,$token)){throw new SecurityException('Acknowledgement lease changed after admission.','outbox.claim_changed');}$budget->check('outbox.timeout');$now=$this->completionTime();if($now<$started||$until<=$now){throw new StorageException('Acknowledgement completion exceeded the original lease.','outbox.completion_unknown');}return ['acknowledged'=>true];
        },$budget);
        $budget->check('outbox.timeout');if($result===null){return false;}$now=$this->completionTime();if($now<$started||$until<=$now){throw new StorageException('Acknowledgement completion exceeded the original lease.','outbox.completion_unknown');}return $result['acknowledged']===true;
    }
    public function rejectTarget(string $scope,string $producer,string $worker,string $token,string $error):string
    {
        if($this->state===null){throw new ConfigurationException('Declare the complete native rejection graph.','configuration.state_connection');}
        $this->namespace($scope,$producer);State::actor($worker);return $this->state->outboxRejectTarget($scope,$producer,$worker,$token,$error,$this->rotationConfiguration());
    }
    /** Terminate a known rejected outcome under the original live lease; never resume an uncertain receipt. */
    public function rejectFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $producer,string $worker,string $token,string $error):bool
    {
        $this->rejectTarget($scope,$producer,$worker,$token,$error);$parts=$this->token($token);if($parts===null){throw new ConfigurationException('Use a canonical original claim token.','configuration.state_connection');}
        $budget=new \SoSecurity\Support\Deadline($this->policy->ioMilliseconds());$started=$this->completionTime();$until=0;
        $result=$this->state->outboxReject($policy,$permission,$scope,$producer,$worker,$token,$error,$this->rotationConfiguration(),function()use($scope,$producer,$worker,$parts,$error,$started,$budget,&$until):bool{
            $budget->check('outbox.timeout');if(!$this->claimAuthority('fail','admission',$scope,$producer,$worker,null,['outcome'=>'rejected','error_code'=>$error,'retryable'=>false])){return false;}$budget->check('outbox.timeout');$before=$this->completionTime();if($before<$started){throw new StorageException('Rejection clock moved backwards.','outbox.clock');}
            $row=$this->currentObservation($scope,$producer,$worker,$parts,$budget);$observed=$this->completionTime();if($observed<$before){throw new StorageException('Rejection clock moved backwards.','outbox.clock');}if($row===null){return false;}
            $allowed=$this->claimAuthority('fail','admitted',$scope,$producer,$worker,$row,['outcome'=>'rejected','error_code'=>$error,'retryable'=>false]);$budget->check('outbox.timeout');$now=$this->completionTime();if($now<$observed){throw new StorageException('Rejection clock moved backwards.','outbox.clock');}$until=min($row['lease_until'],$row['deliver_until']);return $allowed&&$until>$now;
        },function()use($scope,$producer,$worker,$token,$error,$budget,$started,&$until):array{
            $budget->check('outbox.timeout');if(!$this->fail($scope,$producer,$worker,$token,$error,false)){throw new SecurityException('Rejection lease changed after admission.','outbox.claim_changed');}$budget->check('outbox.timeout');$now=$this->completionTime();if($now<$started||$until<=$now){throw new StorageException('Rejection completion exceeded the original lease.','outbox.completion_unknown');}return ['rejected'=>true];
        },$budget);
        $budget->check('outbox.timeout');if($result===null){return false;}$now=$this->completionTime();if($now<$started||$until<=$now){throw new StorageException('Rejection completion exceeded the original lease.','outbox.completion_unknown');}return $result['rejected']===true;
    }
    public function fail(string $scope,string $producer,string $worker,string $token,string $error,bool $retryable=true):bool
    {$this->assertStateAccess();
        if(!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$error)){throw new ConfigurationException('Use fixed safe transport error codes.','configuration.outbox');}return $this->settle($scope,$producer,$worker,$token,$error,$retryable);
    }
    private function settle(string $scope,string $producer,string $worker,string $token,?string $error,bool $retryable):bool
    {
        State::group($scope,$producer);State::actor($worker);$parts=$this->token($token);if($parts===null){return false;}$action=$error===null?'acknowledge':'fail';
        $result=$this->owned($action,$scope,$producer,$worker,function(array $root)use($action,$scope,$producer,$worker,$parts,$error,$retryable):array{
            $row=$this->record($scope,$producer,$root['namespace'],$parts[0]);$this->current($action,$scope,$producer,$worker,$root,$row);
            if($row===null||!$this->held($row,$worker,$parts[1],$error===null)){return ['root'=>$root,'row'=>null,'result'=>false];}
            $body=$this->body($row);if($row['status']==='sent'){return ['root'=>$root,'row'=>$row,'result'=>true];}
            if(!$this->held($row,$worker,$parts[1])){return ['root'=>$root,'row'=>null,'result'=>false];}$validUntil=min($row['lease_until'],$row['deliver_until']);$now=$this->unit->now();$row['lease_until']=0;$row['updated_at']=$now;
            if($error===null){$row['status']='sent';$row['sent_at']=$now;$row['payload_present']=0;$body='';$row['last_error']='';}
            else{$canRetry=$retryable&&$row['attempts']<100&&$row['cycle_attempts']<$this->policy->maximumAttempts();$row['status']=$canRetry?'pending':'dead';$row['available_at']=$now+($canRetry?$this->policy->backoff($row['cycle_attempts']):0);$row['last_error']=$error;}
            $row=$this->saveRow($scope,$producer,$row,$body);$root=$this->sync($scope,$producer,$root);return ['root'=>$root,'row'=>$row,'result'=>true,'valid_until'=>$validUntil];
        });return $result===true;
    }
    public function status(string $scope,string $producer,string $id,string $actor):?Status
    {$this->assertStateAccess();
        State::idTime($id);return $this->owned('status',$scope,$producer,$actor,function(array $root)use($scope,$producer,$id,$actor):array{
            $row=$this->record($scope,$producer,$root['namespace'],hash('sha256',$id));$this->current('status',$scope,$producer,$actor,$root,$row);return ['root'=>$root,'row'=>$row,'result'=>$row===null?null:State::status($row)];
        });
    }
    /** Bounded metadata page; workers use its actual cursor and claimMessage() to avoid scan starvation. */
    public function candidates(string $scope,string $producer,string $actor,int $limit=20,int $afterOrder=0):?array
    {$this->assertStateAccess();
        if($limit<1||$limit>50||$afterOrder<0||$afterOrder>=PHP_INT_MAX){throw new ConfigurationException('Use bounded outbox candidate pages.','configuration.outbox');}
        return $this->owned('candidates',$scope,$producer,$actor,function(array $root)use($scope,$producer,$actor,$limit,$afterOrder):array{
            $this->current('candidates',$scope,$producer,$actor,$root,null);$keys=$this->pageKeys('SELECT '.SqlSchema::boundedProjection($this->unit->driver(),['key_hash'=>'digest']).' FROM '.$this->records.' WHERE namespace=:namespace AND order_no>:after_order ORDER BY order_no LIMIT '.$limit.$this->lock(),['namespace'=>$root['namespace'],'after_order'=>$afterOrder]);$result=[];$cursor=$afterOrder;
            foreach($keys as $key){$row=$this->record($scope,$producer,$root['namespace'],$key);if($row===null){throw new StorageException('Outbox candidate disappeared.','outbox.corrupt');}$this->current('candidates',$scope,$producer,$actor,$root,$row);$result[]=State::status($row);$cursor=$row['order_no'];}
            return ['root'=>$root,'row'=>null,'result'=>['records'=>$result,'next_cursor'=>$cursor,'complete'=>count($keys)<$limit]];
        });
    }
    public function retry(string $scope,string $producer,string $id,string $actor):bool
    {$this->assertStateAccess();
        State::idTime($id);$result=$this->owned('retry',$scope,$producer,$actor,function(array $root)use($scope,$producer,$id,$actor):array{
            $row=$this->record($scope,$producer,$root['namespace'],hash('sha256',$id));$this->current('retry',$scope,$producer,$actor,$root,$row,true);
            if($row===null||$row['status']!=='dead'||$row['manual_retries']>=$this->policy->maximumManualRetries()||$row['attempts']>=100){return ['root'=>$root,'row'=>null,'result'=>false];}
            if($row['payload_present']!==1||$row['created_at']+$this->policy->recoveryAge()<=$this->unit->now()){throw new SecurityException('Expired outbox recovery requires business reconciliation.','outbox.expired');}
            $body=$this->body($row);++$row['manual_retries'];$row['cycle_attempts']=0;$row['status']='pending';$row['lease_until']=0;$row['available_at']=$this->unit->now();$row['deliver_until']=max($row['deliver_until'],min($row['created_at']+$this->policy->recoveryAge(),$this->unit->now()+$this->policy->messageAge()));$row['updated_at']=$this->unit->now();
            $row=$this->saveRow($scope,$producer,$row,$body);$root=$this->sync($scope,$producer,$root);return ['root'=>$root,'row'=>$row,'result'=>true];
        },true);return $result===true;
    }
    /**
     * Join the host audit transaction; true remains provisional until the host COMMIT.
     * The explicit guard must verify a durable received/cancelled decision in that same transaction.
     * It runs at request/current/commit with copied, bounded binding metadata, never network I/O.
     */
    public function reconcile(Message $original,string $actor,string $outcome,string $evidenceDigest,callable $decisionGuard):bool
    {$this->assertStateAccess();
        if(!in_array($outcome,['received','cancelled'],true)||strlen($evidenceDigest)!==64||!preg_match('/\A[a-f0-9]{64}\z/D',$evidenceDigest)){throw new ConfigurationException('Use a terminal decision and its exact evidence digest.','configuration.outbox_resolution');}
        if(strlen($original->body())>$this->policy->maximumPayloadBytes()){throw new SecurityException('Outbox payload exceeds its policy.','outbox.payload');}
        $scope=$original->scope();$producer=$original->producer();$namespace=$this->namespace($scope,$producer);State::actor($actor);
        $binding=['site'=>$this->site,'epoch'=>$this->epoch,'scope'=>$scope,'producer'=>$producer,'actor'=>$actor,'id'=>$original->id(),'delivery_id'=>State::delivery($namespace,$original->id()),'destination'=>$original->destination(),'topic'=>$original->topic(),'aggregate'=>$original->aggregate(),'fingerprint'=>$original->fingerprint(),'payload_bytes'=>strlen($original->body()),'payload_digest'=>hash('sha256',$original->body()),'created_at'=>$original->createdAt(),'outcome'=>$outcome,'evidence_digest'=>$evidenceDigest];
        $check=function(string $phase,?array $row)use($scope,$producer,$actor,$binding,$decisionGuard):bool{
            $description=$row===null?$binding:State::status($row)->metadata()+$binding;
            return $this->authorized('reconcile',$phase,$scope,$producer,$actor,$row,true,$description)&&$this->unit->invoke($decisionGuard,[$phase,$description],'outbox.reconciliation')===true;
        };
        $state=$this->unit->enlist(function()use($scope,$producer,$namespace,$original,$outcome,$evidenceDigest,$check):array{
            Schema::verify($this->unit);$root=$this->root($scope,$producer,$namespace);$row=$this->record($scope,$producer,$namespace,hash('sha256',$original->id()));
            if(!$check('current',$row)){$this->deny();}$this->unchanged($scope,$producer,$root,$row);
            if($row===null){return ['root'=>$root,'row'=>null,'result'=>false];}
            if(!hash_equals($row['fingerprint'],$original->fingerprint())){throw new SecurityException('Reconciliation content differs from the original intent.','outbox.conflict');}
            if($row['status']==='resolved'){
                if($row['last_error']!=='reconcile.'.$outcome||!hash_equals($row['token_digest'],$evidenceDigest)){throw new SecurityException('Reconciliation conflicts with the terminal decision.','outbox.conflict');}
                return ['root'=>$root,'row'=>$row,'result'=>false];
            }
            if($row['status']!=='dead'||$row['payload_present']!==0||$row['created_at']+$this->policy->recoveryAge()>$this->unit->now()){throw new SecurityException('Retire expired dead intent before reconciliation.','outbox.reconciliation_state');}
            $this->body($row);$row['format']=2;$row['status']='resolved';$row['last_error']='reconcile.'.$outcome;$row['token_digest']=$evidenceDigest;$row['updated_at']=$this->unit->now();
            $row=$this->saveRow($scope,$producer,$row,'');$root=$this->sync($scope,$producer,$root);return ['root'=>$root,'row'=>$row,'result'=>true];
        },static function()use($check):bool{return $check('request',null);},function(array $state)use($check,$scope,$producer):void{
            if(!$check('commit',$state['row'])){$this->deny();}$this->unchanged($scope,$producer,$state['root'],$state['row']);$this->sync($scope,$producer,$state['root']);
        });
        if($state===null){$this->deny();}return $state['result']===true;
    }
    public function maintain(string $scope,string $producer,string $actor,int $limit=20,string $afterKey=''):?array
    {$this->assertStateAccess();
        if($limit<1||$limit>50||($afterKey!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$afterKey))){throw new ConfigurationException('Use bounded outbox maintenance.','configuration.outbox');}
        return $this->owned('maintain',$scope,$producer,$actor,function(array $root)use($scope,$producer,$actor,$limit,$afterKey):array{
            $this->current('maintain',$scope,$producer,$actor,$root,null,true);
            $keys=$this->pageKeys('SELECT '.SqlSchema::boundedProjection($this->unit->driver(),['key_hash'=>'digest']).' FROM '.$this->records.' WHERE namespace=:namespace AND key_hash>:after_key ORDER BY '.$this->records.'.key_hash LIMIT '.$limit.$this->lock(),['namespace'=>$root['namespace'],'after_key'=>$afterKey]);$cursor=$afterKey;$purged=0;$retired=0;$rekeyed=0;$approved=[];$purgedResolutions=[];
            foreach($keys as $key){$row=$this->record($scope,$producer,$root['namespace'],$key);if($row!==null&&$row['status']==='resolved'&&$row['updated_at']+$this->policy->retentionSeconds()<=$this->unit->now()){$this->current('purge_resolution',$scope,$producer,$actor,$root,$row,true);$approved[$key]=$row;}}
            foreach($keys as $key){
                $row=$this->record($scope,$producer,$root['namespace'],$key);if($row===null){throw new StorageException('Outbox maintenance row is missing.','outbox.corrupt');}$body=$this->body($row);$now=$this->unit->now();$cursor=$key;
                if($row['status']==='sent'&&$row['admit_until']<=$now&&$row['sent_at']+$this->policy->retentionSeconds()<=$now){$deleted=$this->unit->execute('DELETE FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash',['namespace'=>$root['namespace'],'key_hash'=>$key]);if($deleted!==1){throw new StorageException('Sent outbox record changed during cleanup.','outbox.corrupt');}++$purged;continue;}
                if(isset($approved[$key])){if($row!==$approved[$key]){throw new StorageException('Resolution changed during maintenance.','outbox.corrupt');}$this->unit->query('DELETE FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash',['namespace'=>$root['namespace'],'key_hash'=>$key])->closeCursor();$purgedResolutions[]=$row;++$purged;continue;}
                $dirty=false;
                if(in_array($row['status'],['pending','leased'],true)&&$row['deliver_until']<=$now){$row['status']='dead';$row['lease_until']=0;$row['last_error']='expired';$dirty=true;}
                elseif($row['status']==='leased'&&$row['lease_until']<=$now){$row['status']=$row['cycle_attempts']>=$this->policy->maximumAttempts()||$row['attempts']>=100?'dead':'pending';$row['lease_until']=0;$row['available_at']=$now+$this->policy->backoff($row['cycle_attempts']);$row['last_error']='lease_expired';$dirty=true;}
                if($row['status']==='dead'&&$row['payload_present']===1&&$row['created_at']+$this->policy->recoveryAge()<=$now){$row['payload_present']=0;$body='';$dirty=true;++$retired;}
                if($row['seal_key']!==$this->keys->currentId()){$dirty=true;++$rekeyed;}
                if($dirty){$row['updated_at']=$now;$this->saveRow($scope,$producer,$row,$body);}
            }
            $root=$this->sync($scope,$producer,$root);return ['root'=>$root,'row'=>null,'purged_resolutions'=>$purgedResolutions,'result'=>['scanned'=>count($keys),'purged'=>$purged,'retired'=>$retired,'rekeyed'=>$rekeyed,'next_cursor'=>$cursor,'complete'=>count($keys)<$limit]];
        },true);
    }
    /** Reseal only: no lease transition, retry, payload retirement, reconciliation or deletion. */
    public function rotate(string $scope,string $producer,string $actor,int $limit=20,string $afterKey=''):?array
    {
        $this->assertStateAccess();
        if($limit<1||$limit>50||($afterKey!==''&&preg_match('/\A[a-f0-9]{64}\z/D',$afterKey)!==1)){throw new ConfigurationException('Use bounded outbox rotation.','configuration.outbox');}
        return $this->owned('rotate',$scope,$producer,$actor,function(array $root)use($scope,$producer,$actor,$limit,$afterKey):array{
            $this->current('rotate',$scope,$producer,$actor,$root,null,true);
            $keys=$this->pageKeys('SELECT '.SqlSchema::boundedProjection($this->unit->driver(),['key_hash'=>'digest']).' FROM '.$this->records.' WHERE namespace=:namespace AND key_hash>:after_key ORDER BY '.$this->records.'.key_hash LIMIT '.$limit.$this->lock(),['namespace'=>$root['namespace'],'after_key'=>$afterKey]);
            $cursor=$afterKey;$rekeyed=0;
            foreach($keys as $key){$row=$this->record($scope,$producer,$root['namespace'],$key);if($row===null){throw new StorageException('Outbox rotation row is missing.','outbox.corrupt');}$body=$this->body($row);$cursor=$key;if($row['seal_key']!==$this->keys->currentId()){$this->saveRow($scope,$producer,$row,$body);++$rekeyed;}}
            $root=$this->sync($scope,$producer,$root);return ['root'=>$root,'row'=>null,'result'=>['scanned'=>count($keys),'rekeyed'=>$rekeyed,'next_cursor'=>$cursor,'complete'=>count($keys)<$limit]];
        },true);
    }
    private function rotationConfiguration():string{return hash('sha256','SoSecurity.OutboxRotation.Configuration.1.'.$this->policy->fingerprint().$this->keys->stateDigest());}
    public function rotationTarget(string $scope,string $producer,string $actor,int $limit=20,string $afterKey=''):string
    {
        if($this->state===null){throw new ConfigurationException('Declare the complete native outbox rotation graph.','configuration.state_connection');}
        $this->namespace($scope,$producer);State::actor($actor);return $this->state->outboxRotationTarget($scope,$producer,$actor,$this->rotationConfiguration(),$limit,$afterKey);
    }
    public function rotateFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $producer,string $actor,int $limit=20,string $afterKey=''):?array
    {
        $this->rotationTarget($scope,$producer,$actor,$limit,$afterKey);$guard=$this->management;
        return $this->state->outboxRotation($policy,$permission,$scope,$producer,$actor,$this->rotationConfiguration(),$limit,$afterKey,function()use($guard,$scope,$producer,$actor):bool{
            if($guard===null){return false;}$action='rotate';$phase='admission';$metadata=[];
            try{return $guard($action,$phase,$scope,$producer,$actor,$metadata)===true;}catch(\Throwable $error){throw new \SoSecurity\Exception\DependencyException('Outbox rotation admission unavailable.','outbox.authority');}
        },function()use($scope,$producer,$actor,$limit,$afterKey):array{
            $result=$this->rotate($scope,$producer,$actor,$limit,$afterKey);if($result===null){throw new SecurityException('Outbox rotation authority changed.','outbox.denied');}return $result;
        });
    }
    public function __debugInfo():array {return ['outbox'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild outboxes from trusted configuration.','configuration.outbox_serialization');}
}
