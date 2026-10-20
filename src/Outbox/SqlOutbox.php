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
    public function __construct(PDO $connection,string $site,string $epoch,HmacKeys $integrityKeys,callable $authority,?Policy $policy=null,?Clock $clock=null,?callable $managementGuard=null)
    {
        State::actor($site);if(!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)){throw new ConfigurationException('Use an external trusted deployment epoch.','configuration.outbox');}
        $this->policy=$policy ?? new Policy();$this->unit=new SqlTransaction($connection,$clock ?? new SystemClock(),$this->policy->ioMilliseconds());$this->site=$site;$this->epoch=$epoch;$this->keys=$integrityKeys;$this->authority=$authority;$this->management=$managementGuard;
        $this->roots=$this->unit->prefix().'sosecurity_outbox_roots';$this->records=$this->unit->prefix().'sosecurity_outbox_records';
    }
    private function lock():string {return $this->unit->driver()==='mysql'?' FOR UPDATE':'';}
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
    private function record(string $scope,string $producer,string $namespace,$key):?array
    {
        if(!is_string($key)||!preg_match('/\A[a-f0-9]{64}\z/D',$key)){throw new StorageException('Invalid outbox candidate key.','outbox.corrupt');}
        $row=$this->unit->query('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash'.$this->lock(),['namespace'=>$namespace,'key_hash'=>$key])->fetch(PDO::FETCH_ASSOC);
        if($row===false){return null;}$row=State::record($row,$this->keys,$this->policy,$namespace,$this->epoch,$scope,$producer,$this->unit->now());unset($row['body_length']);return $row;
    }
    private function body(array $row):string
    {
        $bytes=$row['payload_present']===1?$row['payload_bytes']:0;
        if(!is_int($bytes)||$bytes<0||$bytes>$this->policy->maximumPayloadBytes()){throw new StorageException('Outbox payload length exceeds its policy.','outbox.corrupt');}
        // Bound the returned value as well as the selected row. Never truncate a
        // mismatching body into apparently valid bytes; the caller must reject it.
        $length=$this->bytes();$bodyColumn='CASE WHEN '.$length.'='.$bytes.' THEN payload_body ELSE NULL END AS payload_body';
        $stored=$this->unit->query('SELECT '.$bodyColumn.','.$length.' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash AND '.$length.'=:bytes'.$this->lock(),['namespace'=>$row['namespace'],'key_hash'=>$row['key_hash'],'bytes'=>$bytes])->fetch(PDO::FETCH_ASSOC);
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
            $rows=$this->unit->query('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace'.($cursor===null?'':' AND key_hash>:after_key').' ORDER BY '.$this->records.'.key_hash LIMIT '.$limit.$this->lock(),$parameters)->fetchAll(PDO::FETCH_ASSOC);
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
        $raw=$this->unit->query('SELECT '.$this->columns(true).' FROM '.$this->roots.' WHERE namespace=:namespace'.$this->lock(),['namespace'=>$namespace])->fetch(PDO::FETCH_ASSOC);
        if($raw===false){if($optional){return null;}throw new StorageException('Outbox namespace is not initialized.','outbox.uninitialized');}
        $root=State::root($raw,$this->keys,$this->policy,$namespace,$this->epoch,$this->unit->now());$history=$this->history($scope,$producer,$namespace);
        if($root['entries']!==$history['entries']||$root['last_order']<$history['maximum']||($root['format']===1&&$history['resolved']>0)||!hash_equals($root['history_digest'],$history['digest'])){throw new StorageException('Outbox history changed or is missing.','outbox.history');}return $root;
    }
    private function saveRow(string $scope,string $producer,array $row,string $body,bool $insert=false):array
    {
        $row=State::seal($row,$this->keys,false);$canonical=[];foreach(State::recordFields() as $name){$canonical[$name]=$row[$name];}$row=$canonical;
        $fields=array_merge(State::recordFields(),['payload_body']);
        $sql=$insert?'INSERT INTO '.$this->records.'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->records.' SET '.implode(',',array_map(static function(string $name):string{return $name.'=:'.$name;},array_diff($fields,['namespace','key_hash']))).' WHERE namespace=:namespace AND key_hash=:key_hash';
        $this->unit->query($sql,$row+['payload_body'=>$body],['payload_body'])->closeCursor();$stored=$this->record($scope,$producer,$row['namespace'],$row['key_hash']);
        if($stored!==$row||$this->body($row)!==$body){throw new StorageException('Outbox record changed during storage.','outbox.corrupt');}return $row;
    }
    private function sync(string $scope,string $producer,array $root,bool $insert=false):array
    {
        if($root['revision']>=PHP_INT_MAX-1){throw new StorageException('Outbox revision exhausted.','outbox.capacity');}
        $history=$this->history($scope,$producer,$root['namespace']);$root['entries']=$history['entries'];$root['history_digest']=$history['digest'];if($history['resolved']>0){$root['format']=2;}++$root['revision'];$root['observed_at']=$this->unit->now();$root=State::seal($root,$this->keys,true);
        $canonical=[];foreach(State::rootFields() as $name){$canonical[$name]=$root[$name];}$root=$canonical;$fields=State::rootFields();
        $sql=$insert?'INSERT INTO '.$this->roots.'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->roots.' SET '.implode(',',array_map(static function(string $name):string{return $name.'=:'.$name;},array_diff($fields,['namespace']))).' WHERE namespace=:namespace';
        $this->unit->query($sql,$root)->closeCursor();if($this->root($scope,$producer,$root['namespace'])!==$root){throw new StorageException('Outbox root changed during storage.','outbox.corrupt');}return $root;
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
            if(!$this->authorized($action,'return',$scope,$producer,$actor,$state['row'],$management)){$this->deny();}
            if($state['result'] instanceof Claim&&($state['row']['lease_until']<=$this->unit->now()||$state['row']['deliver_until']<=$this->unit->now())){throw new SecurityException('Outbox claim expired during completion; do not send.','outbox.lease');}
        });
        return $state===null?null:$state['result'];
    }
    public function initialize(string $scope,string $producer,string $actor):bool
    {
        $namespace=$this->namespace($scope,$producer);State::actor($actor);
        $state=$this->unit->run(function()use($scope,$producer,$actor,$namespace):array{
            Schema::verify($this->unit);$root=$this->root($scope,$producer,$namespace,true);
            if($root!==null){$this->current('initialize',$scope,$producer,$actor,$root,null,true);return ['root'=>$root,'row'=>null,'result'=>false];}
            if($this->unit->query('SELECT 1 FROM '.$this->records.' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$namespace])->fetchColumn()!==false){throw new StorageException('Do not initialize orphaned outbox history.','outbox.history');}
            if(!$this->authorized('initialize','current',$scope,$producer,$actor,null,true)){$this->deny();}
            $now=$this->unit->now();$root=['namespace'=>$namespace,'format'=>1,'epoch'=>$this->epoch,'policy'=>$this->policy->fingerprint(),'entries'=>0,'history_digest'=>hash('sha256',State::historyPrefix($namespace)),'last_order'=>0,'revision'=>1,'created_at'=>$now,'observed_at'=>$now];
            $root=$this->sync($scope,$producer,$root,true);return ['root'=>$root,'row'=>null,'result'=>true];
        },function()use($scope,$producer,$actor):bool{return $this->authorized('initialize','request',$scope,$producer,$actor,null,true);},function(array $state)use($scope,$producer,$actor):void{$this->finish('initialize',$scope,$producer,$actor,$state,true);},function()use($scope,$producer,$actor):void{if(!$this->authorized('initialize','return',$scope,$producer,$actor,null,true)){$this->deny();}});
        return $state!==null&&$state['result']===true;
    }
    public function enqueue(Message $message,string $actor):Status
    {
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
    {
        return $this->claiming($scope,$producer,$worker,$afterOrder,null);
    }
    public function claimMessage(string $scope,string $producer,string $worker,string $id):?Claim
    {
        State::idTime($id);return $this->claiming($scope,$producer,$worker,0,hash('sha256',$id));
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
    {
        State::group($scope,$producer);State::actor($worker);$parts=$this->token($token);if($parts===null){return null;}
        return $this->owned('current_claim',$scope,$producer,$worker,function(array $root)use($scope,$producer,$worker,$parts,$token):array{
            $row=$this->record($scope,$producer,$root['namespace'],$parts[0]);$this->current('current_claim',$scope,$producer,$worker,$root,$row);
            if($row===null||!$this->held($row,$worker,$parts[1])){return ['root'=>$root,'row'=>null,'result'=>null];}
            $body=$this->body($row);$message=new Message($scope,$producer,$row['message_id'],$row['destination'],$row['topic'],$row['aggregate_id'],$body);
            return ['root'=>$root,'row'=>$row,'result'=>new Claim(State::status($row),$message,$token)];
        });
    }
    public function acknowledge(string $scope,string $producer,string $worker,string $token):bool {return $this->settle($scope,$producer,$worker,$token,null,false);}
    public function fail(string $scope,string $producer,string $worker,string $token,string $error,bool $retryable=true):bool
    {
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
    {
        State::idTime($id);return $this->owned('status',$scope,$producer,$actor,function(array $root)use($scope,$producer,$id,$actor):array{
            $row=$this->record($scope,$producer,$root['namespace'],hash('sha256',$id));$this->current('status',$scope,$producer,$actor,$root,$row);return ['root'=>$root,'row'=>$row,'result'=>$row===null?null:State::status($row)];
        });
    }
    /** Bounded metadata page; workers use its actual cursor and claimMessage() to avoid scan starvation. */
    public function candidates(string $scope,string $producer,string $actor,int $limit=20,int $afterOrder=0):?array
    {
        if($limit<1||$limit>50||$afterOrder<0||$afterOrder>=PHP_INT_MAX){throw new ConfigurationException('Use bounded outbox candidate pages.','configuration.outbox');}
        return $this->owned('candidates',$scope,$producer,$actor,function(array $root)use($scope,$producer,$actor,$limit,$afterOrder):array{
            $this->current('candidates',$scope,$producer,$actor,$root,null);$keys=$this->unit->query('SELECT '.SqlSchema::boundedProjection($this->unit->driver(),['key_hash'=>'digest']).' FROM '.$this->records.' WHERE namespace=:namespace AND order_no>:after_order ORDER BY order_no LIMIT '.$limit.$this->lock(),['namespace'=>$root['namespace'],'after_order'=>$afterOrder])->fetchAll(PDO::FETCH_COLUMN);$result=[];$cursor=$afterOrder;
            foreach($keys as $key){$row=$this->record($scope,$producer,$root['namespace'],$key);if($row===null){throw new StorageException('Outbox candidate disappeared.','outbox.corrupt');}$this->current('candidates',$scope,$producer,$actor,$root,$row);$result[]=State::status($row);$cursor=$row['order_no'];}
            return ['root'=>$root,'row'=>null,'result'=>['records'=>$result,'next_cursor'=>$cursor,'complete'=>count($keys)<$limit]];
        });
    }
    public function retry(string $scope,string $producer,string $id,string $actor):bool
    {
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
    {
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
    {
        if($limit<1||$limit>50||($afterKey!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$afterKey))){throw new ConfigurationException('Use bounded outbox maintenance.','configuration.outbox');}
        return $this->owned('maintain',$scope,$producer,$actor,function(array $root)use($scope,$producer,$actor,$limit,$afterKey):array{
            $this->current('maintain',$scope,$producer,$actor,$root,null,true);
            $keys=$this->unit->query('SELECT '.SqlSchema::boundedProjection($this->unit->driver(),['key_hash'=>'digest']).' FROM '.$this->records.' WHERE namespace=:namespace AND key_hash>:after_key ORDER BY '.$this->records.'.key_hash LIMIT '.$limit.$this->lock(),['namespace'=>$root['namespace'],'after_key'=>$afterKey])->fetchAll(PDO::FETCH_COLUMN);$cursor=$afterKey;$purged=0;$retired=0;$rekeyed=0;$approved=[];$purgedResolutions=[];
            foreach($keys as $key){$row=$this->record($scope,$producer,$root['namespace'],$key);if($row!==null&&$row['status']==='resolved'&&$row['updated_at']+$this->policy->retentionSeconds()<=$this->unit->now()){$this->current('purge_resolution',$scope,$producer,$actor,$root,$row,true);$approved[$key]=$row;}}
            foreach($keys as $key){
                $row=$this->record($scope,$producer,$root['namespace'],$key);if($row===null){throw new StorageException('Outbox maintenance row is missing.','outbox.corrupt');}$body=$this->body($row);$now=$this->unit->now();$cursor=$key;
                if($row['status']==='sent'&&$row['admit_until']<=$now&&$row['sent_at']+$this->policy->retentionSeconds()<=$now){$this->unit->query('DELETE FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash',['namespace'=>$root['namespace'],'key_hash'=>$key])->closeCursor();++$purged;continue;}
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
    public function __debugInfo():array {return ['outbox'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild outboxes from trusted configuration.','configuration.outbox_serialization');}
}
