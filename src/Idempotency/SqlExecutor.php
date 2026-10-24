<?php
declare(strict_types=1);
namespace SoSecurity\Idempotency;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Authenticated SQL result replay. Business writes and result commit together; no cross-resource guarantee. */
final class SqlExecutor
{
    private $unit;
    private $site;
    private $epoch;
    private $keys;
    private $authority;
    private $management;
    private $policy;
    private $roots;
    private $records;
    private $clock;
    private $state;
    private $observing=false;
    private $expectedRoot;
    private $checkRoot=false;
    private $nativeBusy=false;

    public function __construct(PDO $connection,string $site,string $epoch,HmacKeys $integrityKeys,callable $authority,?Policy $policy=null,?Clock $clock=null,?callable $managementGuard=null,?\SoSecurity\Account\StateAccountConnection $state=null)
    {
        Guard::label($site);if(!preg_match('//u',$site)||!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)){throw new ConfigurationException('Use a fixed site and trusted deployment epoch.','configuration.idempotency');}
        $clock=$clock??new SystemClock();if($state!==null){$state->validateIdempotency($connection,$site,$epoch,$clock);}$this->clock=$clock;$this->state=$state;
        $this->policy=$policy ?? new Policy();$this->unit=new SqlTransaction($connection,$clock,$this->policy->ioMilliseconds());$this->site=$site;$this->epoch=$epoch;$this->keys=$integrityKeys;$this->authority=$authority;$this->management=$managementGuard;$prefix=$this->unit->prefix();$this->roots=$prefix.'sosecurity_idempotency_roots';$this->records=$prefix.'sosecurity_idempotency_records';
    }
    private function lock():string{return !$this->observing&&$this->unit->driver()==='mysql'?' FOR UPDATE':'';}
    private function namespace(string $scope,string $subject,string $operation):string {return State::namespace($this->site,$scope,$subject,$operation);}
    private function management(string $operation,string $scope,string $subject,string $action):bool
    {
        return $this->management!==null&&$this->unit->invoke($this->management,[$operation,$scope,$subject,$action],'idempotency.management')===true;
    }
    private function authorize(string $phase,Request $request,array $metadata=[]):bool
    {
        return $this->unit->invoke($this->authority,[$phase,$request,$metadata],'idempotency.authority')===true;
    }
    private function columns(bool $root=false):string
    {
        $types=$root?Schema::rootTypes():Schema::recordTypes();unset($types['response_body']);
        return SqlSchema::boundedProjection($this->unit->driver(),$types);
    }
    /** Exactly one aggregate row; retain the existing SQL and integer range checks. */
    private function entryCount(string $table):int
    {
        $row=$this->first('SELECT COUNT(*) FROM '.$table,[]);if($row===false||count($row)!==1){throw new StorageException('Invalid idempotency capacity observation.','idempotency.corrupt');}return SqlSchema::integer(reset($row));
    }
    private function root(string $namespace,bool $optional=false):?array
    {
        $row=$this->first('SELECT '.$this->columns(true).' FROM '.$this->roots.' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$namespace]);
        if($this->checkRoot){$normalized=$row===false?null:State::root($row,$this->keys,$this->policy,$namespace,$this->epoch,$this->unit->now());if($normalized!==$this->expectedRoot){throw new StorageException('Idempotency root changed after admission.','idempotency.changed');}$this->checkRoot=false;}
        if($row===false){if($optional){return null;}throw new StorageException('Idempotency namespace is not initialized.','idempotency.uninitialized');}
        $root=State::root($row,$this->keys,$this->policy,$namespace,$this->epoch,$this->unit->now());$this->count($root);return $root;
    }
    private function count(array $root):void
    {
        $actual=$this->history($root['namespace']);
        if($actual['entries']!==$root['entries']||!hash_equals($root['history_digest'],$actual['digest'])){throw new StorageException('Idempotency key history is missing or inconsistent.','idempotency.history');}
    }
    private function history(string $namespace):array
    {
        $hash=hash_init('sha256');hash_update($hash,State::historyPrefix($namespace));$entries=0;$cursor=null;
        do{
            $limit=min(512,$this->policy->maximumEntries()+1-$entries);$parameters=['namespace'=>$namespace];if($cursor!==null){$parameters['after_key']=$cursor;}
            $rows=$this->unit->metadataRows('SELECT '.SqlSchema::boundedProjection($this->unit->driver(),['key_hash'=>'digest','execution_id'=>'id']).' FROM '.$this->records.' WHERE namespace=:namespace'.($cursor===null?'':' AND key_hash>:after_key').' ORDER BY '.$this->records.'.key_hash LIMIT '.$limit.$this->lock(),$parameters);
            foreach($rows as $row){
                if(!is_string($row['key_hash'])||!preg_match('/\A[a-f0-9]{64}\z/D',$row['key_hash'])||!is_string($row['execution_id'])||!preg_match('/\A[a-f0-9]{32}\z/D',$row['execution_id'])||++$entries>$this->policy->maximumEntries()){throw new StorageException('Idempotency key history is invalid.','idempotency.history');}
                hash_update($hash,$row['key_hash'].$row['execution_id']);$cursor=$row['key_hash'];
            }
        }while(count($rows)===$limit);
        return ['entries'=>$entries,'digest'=>hash_final($hash)];
    }
    private function touch(array $root):array
    {
        if($root['revision']>=PHP_INT_MAX-1){throw new StorageException('Idempotency revision exhausted.','idempotency.capacity');}
        ++$root['revision'];$root['observed_at']=$this->unit->now();return State::seal($root,$this->keys,true);
    }
    private function saveRoot(array $root,bool $insert=false):array
    {
        $fields=State::rootFields();
        $sql=$insert?'INSERT INTO '.$this->roots.'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->roots.' SET '.implode(',',array_map(static function(string $name):string{return $name.'=:'.$name;},array_diff($fields,['namespace']))).' WHERE namespace=:namespace';
        $this->unit->execute($sql,$root);$read=$this->root($root['namespace']);if($read!==$root){throw new StorageException('Idempotency root changed during storage.','idempotency.corrupt');}return $root;
    }
    private function bytes():string {return SqlSchema::blobLength($this->unit->driver(),'response_body');}
    /** One bounded single-row read, consumed and closed by its owning unit. @return array|false */
    private function first(string $sql,array $parameters)
    {
        $rows=$this->unit->metadataRows($sql,$parameters);if(!$rows){return false;}
        if(count($rows)!==1||!isset($rows[0])||!is_array($rows[0])){throw new StorageException('Unexpected queue metadata rows.','idempotency.corrupt');}return $rows[0];
    }
    private function record(string $namespace,string $key):?array
    {
        $row=$this->first('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash LIMIT 1'.$this->lock(),['namespace'=>$namespace,'key_hash'=>$key]);
        return $row===false?null:State::record($row,$this->keys,$this->policy,$namespace,$this->epoch,$this->unit->now());
    }
    private function body(array $row):string
    {
        $stored=$this->first('SELECT CASE WHEN '.$this->bytes().'='.(int)$row['response_bytes'].' THEN response_body ELSE NULL END AS response_body,'.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash AND '.$this->bytes().'=:bytes LIMIT 1'.$this->lock(),['namespace'=>$row['namespace'],'key_hash'=>$row['key_hash'],'bytes'=>$row['response_bytes']]);
        if(!is_array($stored)||!array_key_exists('response_body',$stored)||SqlSchema::integer($stored['body_length'])!==$row['response_bytes']){throw new StorageException('Idempotency response row is missing or changed.','idempotency.corrupt');}
        // PDO SQLite 7.2 returns null for a real zero-byte BLOB. The row and SQL length predicate distinguish it from NULL/missing state.
        $body=$stored['response_body']===null&&$row['response_bytes']===0?'':$stored['response_body'];
        if(!is_string($body)||strlen($body)!==$row['response_bytes']||!hash_equals(hash('sha256',$body),$row['response_digest'])){throw new StorageException('Idempotency response bytes changed.','idempotency.corrupt');}return $body;
    }
    private function saveRecord(array $row,string $body,bool $insert=false):array
    {
        unset($row['body_length']);$row=State::seal($row,$this->keys,false);$parameters=$row;$parameters['response_body']=$body;$fields=array_merge(State::recordFields(),['response_body']);
        $sql=$insert?'INSERT INTO '.$this->records.'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->records.' SET '.implode(',',array_map(static function(string $name):string{return $name.'=:'.$name;},array_diff($fields,['namespace','key_hash']))).' WHERE namespace=:namespace AND key_hash=:key_hash';
        $this->unit->execute($sql,$parameters,['response_body']);$row['body_length']=strlen($body);$read=$this->record($row['namespace'],$row['key_hash']);
        if($read!==$row||$this->body($row)!==$body){throw new StorageException('Idempotency response changed during storage.','idempotency.corrupt');}return $row;
    }
    private function metadata(array $row,bool $replayed):array {return ['execution_id'=>$row['execution_id'],'fingerprint'=>$row['fingerprint'],'created_at'=>$row['created_at'],'expires_at'=>$row['expires_at'],'replayed'=>$replayed];}
    public function initialize(string $scope,string $subject,string $operation):bool{return $this->initializeInternal($scope,$subject,$operation,null);}
    private function initializeInternal(string $scope,string $subject,string $operation,?Deadline $budget):bool
    {
        $namespace=$this->namespace($scope,$subject,$operation);
        $result=$this->unit->run(function()use($namespace):array{
            Schema::verify($this->unit);$root=$this->root($namespace,true);if($root!==null){return ['created'=>false,'root'=>$root];}
            if($this->unit->metadataRows('SELECT 1 FROM '.$this->records.' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$namespace])!==[]){throw new StorageException('Do not initialize an orphaned idempotency history.','idempotency.history');}
            $now=$this->unit->now();$root=State::seal(['namespace'=>$namespace,'format'=>2,'epoch'=>$this->epoch,'policy'=>$this->policy->fingerprint(),'entries'=>0,'history_digest'=>hash('sha256',State::historyPrefix($namespace)),'revision'=>1,'created_at'=>$now,'observed_at'=>$now],$this->keys,true);$this->saveRoot($root,true);return ['created'=>true,'root'=>$root];
        },function()use($scope,$subject,$operation):bool{return $this->management('initialize',$scope,$subject,$operation);},function(array $state)use($scope,$subject,$operation){
            if(!$this->management('initialize',$scope,$subject,$operation)){throw new SecurityException('Idempotency management changed.','idempotency.denied');}
            if($this->root($state['root']['namespace'])!==$state['root']){throw new StorageException('Idempotency root changed.','idempotency.corrupt');}$this->saveRoot($this->touch($state['root']));
        },function()use($scope,$subject,$operation){if(!$this->management('initialize',$scope,$subject,$operation)){throw new SecurityException('Idempotency management changed after commit.','idempotency.denied');}},$budget);
        return $result!==null&&$result['created']===true;
    }
    public function execute(Request $request,callable $handler):?Outcome {return $this->operate($request,$handler);}
    public function lookup(Request $request):?Outcome {return $this->operate($request,null);}
    private function operate(Request $request,?callable $handler,?Deadline $budget=null,?array $native=null):?Outcome
    {
        $namespace=$this->namespace($request->scope(),$request->subject(),$request->operation());$key=hash('sha256',$request->key());$execution=$native===null?bin2hex(random_bytes(16)):$native['execution'];$budget=$budget??new Deadline($this->policy->ioMilliseconds());
        try{$result=$this->unit->run(function()use($request,$handler,$namespace,$key,$execution,$native):array{
            Schema::verify($this->unit);$root=$this->root($namespace);$row=$this->record($namespace,$key);
            if($native!==null&&($root!==$native['root']||$row!==$native['row'])){throw new StorageException('Idempotency request changed after admission.','idempotency.changed');}
            $state=['root'=>$root,'row'=>$row,'phase'=>'lookup','metadata'=>[],'outcome'=>null,'error'=>null];
            if($row!==null){
                $state['phase']='replay';$state['metadata']=$this->metadata($row,true);if(!$this->authorize('replay',$request,$state['metadata'])){throw new SecurityException('Current replay authority required.','idempotency.denied');}
                if($row['status']==='running'){throw new StorageException('A partially committed idempotency operation requires reconciliation.','idempotency.uncertain');}
                if($row['fingerprint']!==$request->fingerprint()){$state['error']='idempotency.conflict';return $state;}
                if($row['status']==='expired'||$row['expires_at']<=$this->unit->now()){
                    if($row['status']!=='expired'){$this->body($row);$row['status']='expired';$row['status_code']=0;$row['response_bytes']=0;$row['response_digest']=hash('sha256','');$row['updated_at']=$this->unit->now();$state['row']=$this->saveRecord($row,'');}
                    $state['error']='idempotency.expired';return $state;
                }
                $response=new Response($row['status_code'],$this->body($row));$state['outcome']=new Outcome($row['execution_id'],$response,true,$row['expires_at']);return $state;
            }
            if($handler===null){return $state;}
            if($root['entries']>=$this->policy->maximumEntries()){$state['error']='idempotency.capacity';return $state;}
            $state['phase']='execute';$now=$this->unit->now();$created=$native===null?$now:$native['created'];if($created+$this->policy->ttl()<=$now){throw new SecurityException('Idempotency request expired before execution.','idempotency.expired');}$row=['namespace'=>$namespace,'key_hash'=>$key,'format'=>1,'epoch'=>$this->epoch,'policy'=>$this->policy->fingerprint(),'execution_id'=>$execution,'fingerprint'=>$request->fingerprint(),'status'=>'running','status_code'=>0,'response_bytes'=>0,'response_digest'=>hash('sha256',''),'created_at'=>$created,'expires_at'=>$created+$this->policy->ttl(),'updated_at'=>$now];$state['metadata']=$this->metadata($row,false);
            if(!$this->authorize('execute',$request,$state['metadata'])){throw new SecurityException('Current execution authority required.','idempotency.denied');}
            $row=$this->saveRecord($row,'',true);++$root['entries'];$history=$this->history($namespace);if($history['entries']!==$root['entries']){throw new StorageException('Idempotency key history changed during creation.','idempotency.history');}$root['history_digest']=$history['digest'];$state['root']=$this->saveRoot($this->touch($root));
            $response=$this->unit->invoke($handler,[$this->unit->connection(),$request,$execution],'idempotency.handler');
            if(!$response instanceof Response||strlen($response->body())>$this->policy->maximumResponseBytes()){throw new DependencyException('Handler must return a bounded application Response.','idempotency.handler_response');}
            if($this->record($namespace,$key)!==$row||$this->body($row)!==''){throw new StorageException('Handler changed its idempotency record.','idempotency.corrupt');}
            $row['status']='done';$row['status_code']=$response->status();$row['response_bytes']=strlen($response->body());$row['response_digest']=hash('sha256',$response->body());$row['updated_at']=$this->unit->now();$state['row']=$this->saveRecord($row,$response->body());
            $state['outcome']=new Outcome($execution,$response,false,$row['expires_at']);return $state;
        },function()use($request):bool{return $this->authorize('request',$request);},function(array $state)use($request,$namespace){
            if(!$this->authorize($state['phase']==='execute'?'commit':$state['phase'],$request,$state['metadata'])){throw new SecurityException('Idempotency authority changed during execution.','idempotency.denied');}
            if($this->root($namespace)!==$state['root']){throw new StorageException('Idempotency root changed during execution.','idempotency.corrupt');}
            $row=$state['row'];if($row!==null){if($this->record($namespace,$row['key_hash'])!==$row){throw new StorageException('Idempotency record changed during execution.','idempotency.corrupt');}$this->body($row);}
            $this->saveRoot($this->touch($state['root']));
            if($row!==null){if($this->record($namespace,$row['key_hash'])!==$row){throw new StorageException('Idempotency response changed before commit.','idempotency.corrupt');}$this->body($row);}
        },function(array $state)use($request){
            $allowed=$this->authorize('return',$request,$state['metadata']);
            if($state['outcome']!==null&&$state['outcome']->expiresAt()<=$this->unit->now()){throw new SecurityException('Result expired during completion; do not repeat business work.','idempotency.expired');}
            if(!$allowed){throw new SecurityException('Idempotency authority changed after commit.','idempotency.denied');}
        },$budget);}catch(SecurityException $error){
            if($native===null&&$this->unit->committed()){$this->observeCompletionFailure($namespace,$key,$budget);}throw $error;
        }
        if($result===null){return null;}if($result['error']!==null){throw new SecurityException('Idempotency request cannot be completed.',$result['error']);}return $result['outcome'];
    }
    /** Revoke expired results and persist observed time after a failed completion, within the original I/O budget. */
    private function observeCompletionFailure(string $namespace,string $key,Deadline $budget):void
    {
        $this->unit->run(function()use($namespace,$key):void{
            Schema::verify($this->unit);$root=$this->root($namespace);$row=$this->record($namespace,$key);
            if($row!==null){
                if($row['status']==='running'){throw new StorageException('Committed idempotency history needs reconciliation.','idempotency.uncertain');}
                $this->body($row);
                if($row['status']==='done'&&$row['expires_at']<=$this->unit->now()){$row['status']='expired';$row['status_code']=0;$row['response_bytes']=0;$row['response_digest']=hash('sha256','');$row['updated_at']=$this->unit->now();$row=$this->saveRecord($row,'');}
            }
            $this->saveRoot($this->touch($root));
            if($row!==null){if($this->record($namespace,$key)!==$row){throw new StorageException('Completion history changed before commit.','idempotency.corrupt');}$this->body($row);}
        },null,null,null,$budget);
    }
    public function maintain(string $scope,string $subject,string $operation,int $limit=20,string $afterKey=''):?array{return $this->maintainInternal($scope,$subject,$operation,$limit,$afterKey,null);}
    private function maintainInternal(string $scope,string $subject,string $operation,int $limit,string $afterKey,?Deadline $budget):?array
    {
        $namespace=$this->namespace($scope,$subject,$operation);if($limit<1||$limit>50||($afterKey!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$afterKey))){throw new ConfigurationException('Use bounded idempotency maintenance.','configuration.idempotency');}
        $result=$this->unit->run(function()use($namespace,$limit,$afterKey):array{
            Schema::verify($this->unit);$root=$this->root($namespace);$rows=$this->unit->metadataRows('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash>:after_key ORDER BY '.$this->records.'.key_hash LIMIT '.$limit.$this->lock(),['namespace'=>$namespace,'after_key'=>$afterKey]);
            $cursor=$afterKey;$compacted=0;$rekeyed=0;$changed=[];
            foreach($rows as $raw){$row=State::record($raw,$this->keys,$this->policy,$namespace,$this->epoch,$this->unit->now());$cursor=$row['key_hash'];if($row['status']==='running'){throw new StorageException('Partial execution needs reconciliation.','idempotency.uncertain');}$body=$this->body($row);$dirty=false;
                if($row['status']==='done'&&$row['expires_at']<=$this->unit->now()){$row['status']='expired';$row['status_code']=0;$row['response_bytes']=0;$row['response_digest']=hash('sha256','');$body='';$dirty=true;++$compacted;}
                if($row['seal_key']!==$this->keys->currentId()){$dirty=true;++$rekeyed;}
                if($dirty){$row['updated_at']=$this->unit->now();$row=$this->saveRecord($row,$body);}$changed[$row['key_hash']]=$row;
            }
            return ['root'=>$root,'rows'=>$changed,'result'=>['scanned'=>count($rows),'compacted'=>$compacted,'rekeyed'=>$rekeyed,'next_cursor'=>$cursor,'complete'=>count($rows)<$limit]];
        },function()use($scope,$subject,$operation):bool{return $this->management('maintain',$scope,$subject,$operation);},function(array $state)use($scope,$subject,$operation,$namespace){
            if(!$this->management('maintain',$scope,$subject,$operation)){throw new SecurityException('Maintenance authority changed.','idempotency.denied');}if($this->root($namespace)!==$state['root']){throw new StorageException('Idempotency root changed.','idempotency.corrupt');}$this->saveRoot($this->touch($state['root']));
            foreach($state['rows'] as $key=>$row){if($this->record($namespace,$key)!==$row){throw new StorageException('Idempotency history changed.','idempotency.corrupt');}$this->body($row);}
        },function()use($scope,$subject,$operation){if(!$this->management('maintain',$scope,$subject,$operation)){throw new SecurityException('Maintenance authority changed after commit.','idempotency.denied');}},$budget);
        return $result===null?null:$result['result'];
    }
    private function nativeConfiguration():string{return hash('sha256','SoSecurity.Idempotency.NativeMaintenance.1.'.$this->policy->fingerprint().'.'.$this->keys->currentId());}
    private function nativeState():\SoSecurity\Account\StateAccountConnection
    {
        if($this->state===null){throw new ConfigurationException('Supply the exact idempotency state connection.','configuration.state_connection');}return $this->state;
    }
    public function initializationTarget(string $scope,string $subject,string $operation):string{return $this->nativeState()->idempotencyMaintenanceTarget('initialize',$scope,$subject,$operation,$this->nativeConfiguration());}
    public function maintenanceTarget(string $scope,string $subject,string $operation,int $limit=20,string $afterKey=''):string{return $this->nativeState()->idempotencyMaintenanceTarget('maintain',$scope,$subject,$operation,$this->nativeConfiguration(),$limit,$afterKey);}
    /** @phpstan-impure Current host authority may change between observations. */
    private function nativeManagement(string $action,string $scope,string $subject,string $operation):bool
    {
        if($this->management===null){return false;}$guard=$this->management;
        try{return $guard($action,$scope,$subject,$operation)===true;}catch(\Throwable $error){throw new DependencyException('Idempotency management admission unavailable.','idempotency.management');}
    }
    private function maintenanceObservation(string $action,string $namespace,int $limit,string $afterKey,Deadline $deadline):array
    {
        $original=$this->unit;$unit=SqlTransaction::forObservation($original->connection(),$this->clock,$this->policy->ioMilliseconds());$this->unit=$unit;$this->observing=true;
        try{return $unit->run(function()use($unit,$action,$namespace,$limit,$afterKey):array{
            Schema::verify($unit);$root=$this->root($namespace,$action==='initialize');
            if($root===null){if($this->unit->metadataRows('SELECT 1 FROM '.$this->records.' WHERE namespace=:namespace LIMIT 1',['namespace'=>$namespace])!==[]){throw new StorageException('Orphaned idempotency history cannot be initialized.','idempotency.history');}}
            if($action==='maintain'){
                $rows=$this->unit->metadataRows('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash>:after_key ORDER BY '.$this->records.'.key_hash LIMIT '.$limit,['namespace'=>$namespace,'after_key'=>$afterKey]);
                foreach($rows as $raw){$row=State::record($raw,$this->keys,$this->policy,$namespace,$this->epoch,$this->unit->now());if($row['status']==='running'){throw new StorageException('Unknown execution remains isolated.','idempotency.uncertain');}$this->body($row);}
            }
            $total=$action==='initialize'&&$root===null?$this->entryCount($this->roots):0;
            return ['root'=>$root,'total'=>$total];
        },null,null,null,$deadline);}finally{$this->unit=$original;$this->observing=false;}
    }
    private function nativeTime(Deadline $deadline,int &$seen):void
    {
        $deadline->check('idempotency.timeout');try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Idempotency clock unavailable.','idempotency.clock');}
        if($now<0||$now>PHP_INT_MAX-31536001||$now<$seen){throw new StorageException('Idempotency clock moved backwards or is invalid.','idempotency.clock');}$seen=$now;
    }
    private function nativeMaintenance(string $action,\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $subject,string $operation,int $limit,string $afterKey):?array
    {
        if($this->nativeBusy){throw new ConfigurationException('Enter native idempotency once.','configuration.state_idempotency_nested');}$this->nativeBusy=true;
        try{
        $connection=$this->nativeState();$namespace=$this->namespace($scope,$subject,$operation);$deadline=new Deadline($this->policy->ioMilliseconds());$observation=null;$seen=0;$this->nativeTime($deadline,$seen);
        $result=$connection->idempotencyMaintenance($action,$policy,$permission,$scope,$subject,$operation,$this->nativeConfiguration(),$limit,$afterKey,function(int $maximum)use($action,$scope,$subject,$operation,$namespace,$limit,$afterKey,$deadline,&$observation,&$seen):bool{
            if(!$this->nativeManagement($action,$scope,$subject,$operation)){return false;}$this->nativeTime($deadline,$seen);$observation=$this->maintenanceObservation($action,$namespace,$limit,$afterKey,$deadline);$this->nativeTime($deadline,$seen);
            if(!$this->nativeManagement($action,$scope,$subject,$operation)){return false;}$this->nativeTime($deadline,$seen);
            if($action==='initialize'){if($observation['root']!==null){return false;}if($observation['total']>=$maximum){throw new SecurityException('Idempotency source capacity reached.','idempotency.capacity');}}return true;
        },function()use($action,$scope,$subject,$operation,$limit,$afterKey,$deadline,&$observation,&$seen):array{
            $this->nativeTime($deadline,$seen);$observed=$this->admittedRoot($observation);$this->expectedRoot=$observed['root'];$this->checkRoot=true;
            try{$result=$action==='initialize'?['created'=>$this->initializeInternal($scope,$subject,$operation,$deadline)]:$this->maintainInternal($scope,$subject,$operation,$limit,$afterKey,$deadline);if($result===null||($action==='initialize'&&!$result['created'])){throw new SecurityException('Idempotency management authority changed.','idempotency.denied');}return $result;}
            finally{$this->checkRoot=false;$this->expectedRoot=null;}
        },function()use($action,$scope,$subject,$operation,$deadline,&$seen):void{if(!$this->nativeManagement($action,$scope,$subject,$operation)){throw new SecurityException('Idempotency management changed before return.','idempotency.denied');}$this->nativeTime($deadline,$seen);},$deadline);
        $this->nativeTime($deadline,$seen);return $result;
        }finally{$this->nativeBusy=false;}
    }
    private function admittedRoot(?array $observation):array{if($observation===null){throw new ConfigurationException('Native observation required.','configuration.state_connection');}return $observation;}
    public function initializeFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $subject,string $operation):bool
    {
        $this->initializationTarget($scope,$subject,$operation);$result=$this->nativeMaintenance('initialize',$policy,$permission,$scope,$subject,$operation,20,'');return $result!==null&&$result['created']===true;
    }
    public function maintainFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,string $scope,string $subject,string $operation,int $limit=20,string $afterKey=''):?array
    {
        $this->maintenanceTarget($scope,$subject,$operation,$limit,$afterKey);return $this->nativeMaintenance('maintain',$policy,$permission,$scope,$subject,$operation,$limit,$afterKey);
    }
    private function requestConfiguration(array $businessTables):string{return hash('sha256',$this->nativeConfiguration().'.'.$this->nativeState()->idempotencyBusiness($businessTables));}
    public function executionTarget(Request $request,array $businessTables):string{return $this->nativeState()->idempotencyRequestTarget('execute',$request,$this->requestConfiguration($businessTables));}
    public function lookupTarget(Request $request):string{return $this->nativeState()->idempotencyRequestTarget('lookup',$request,$this->nativeConfiguration());}
    /** @phpstan-impure Current request authority is independent of the described request. */
    private function nativeRequestAuthority(string $phase,Request $request,array $metadata=[]):bool
    {
        $guard=$this->authority;try{return $guard($phase,$request,$metadata)===true;}catch(\Throwable $error){throw new DependencyException('Idempotency request admission unavailable.','idempotency.authority');}
    }
    private function requestObservation(Request $request,Deadline $deadline):array
    {
        $original=$this->unit;$unit=SqlTransaction::forObservation($original->connection(),$this->clock,$this->policy->ioMilliseconds());$this->unit=$unit;$this->observing=true;
        try{return $unit->run(function()use($unit,$request):array{
            Schema::verify($unit);$namespace=$this->namespace($request->scope(),$request->subject(),$request->operation());$root=$this->root($namespace);$row=$this->record($namespace,hash('sha256',$request->key()));
            if($row!==null){if($row['status']==='running'){throw new StorageException('Unknown execution remains isolated.','idempotency.uncertain');}$this->body($row);}
            $total=$row===null?$this->entryCount($this->records):0;
            return ['root'=>$root,'row'=>$row,'total'=>$total,'created'=>$this->unit->now()];
        },null,null,null,$deadline);}finally{$this->unit=$original;$this->observing=false;}
    }
    private function nativeResult(array $result):Outcome
    {
        if(!isset($result['outcome'])||!$result['outcome'] instanceof Outcome){throw new StorageException('Native idempotency result is missing.','idempotency.changed');}return $result['outcome'];
    }
    private function nativeOutcomeTime(Outcome $outcome,Deadline $deadline,int &$seen):void
    {
        $this->nativeTime($deadline,$seen);if($outcome->expiresAt()<=$seen){throw new SecurityException('Idempotency result expired before return.','idempotency.expired');}
    }
    private function nativeRequest(string $action,\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,Request $request,?callable $handler,string $configuration):?Outcome
    {
        if($this->nativeBusy){throw new ConfigurationException('Enter native idempotency once.','configuration.state_idempotency_nested');}$this->nativeBusy=true;
        try{
            $deadline=new Deadline($this->policy->ioMilliseconds());$seen=0;$plan=null;$execution=bin2hex(random_bytes(16));$this->nativeTime($deadline,$seen);
            $result=$this->nativeState()->idempotencyRequest($action,$policy,$permission,$request,$configuration,function(int $maximum)use($request,$handler,$execution,$deadline,&$seen,&$plan):bool{
                if(!$this->nativeRequestAuthority('request',$request)){return false;}$this->nativeTime($deadline,$seen);$plan=$this->requestObservation($request,$deadline);$this->nativeTime($deadline,$seen);$row=$plan['row'];
                if($row===null){
                    if($handler===null){return false;}if($plan['root']['entries']>=$this->policy->maximumEntries()||$plan['total']>=$maximum||$plan['root']['revision']>=PHP_INT_MAX-2){throw new SecurityException('Idempotency capacity reached.','idempotency.capacity');}
                    $plan['execution']=$execution;$plan['metadata']=['execution_id'=>$execution,'fingerprint'=>$request->fingerprint(),'created_at'=>$plan['created'],'expires_at'=>$plan['created']+$this->policy->ttl(),'replayed'=>false];$phase='execute';
                }else{
                    $plan['execution']=$row['execution_id'];$plan['metadata']=$this->metadata($row,true);$phase='replay';
                }
                if(!$this->nativeRequestAuthority($phase,$request,$plan['metadata'])){return false;}$this->nativeTime($deadline,$seen);
                if($row!==null){if($row['fingerprint']!==$request->fingerprint()){throw new SecurityException('Idempotency request conflicts with known history.','idempotency.conflict');}if($row['status']==='expired'||$row['expires_at']<=$seen){throw new SecurityException('Idempotency result expired.','idempotency.expired');}if($plan['root']['revision']>=PHP_INT_MAX-1){throw new SecurityException('Idempotency revision exhausted.','idempotency.capacity');}}
                if($plan['metadata']['expires_at']<=$seen){throw new SecurityException('Idempotency admission expired.','idempotency.expired');}return true;
            },function()use($request,$handler,$deadline,&$seen,&$plan):array{
                $admitted=$this->admittedRoot($plan);$this->nativeTime($deadline,$seen);if($admitted['metadata']['expires_at']<=$seen){throw new SecurityException('Idempotency admission expired.','idempotency.expired');}
                $outcome=$this->operate($request,$handler,$deadline,$admitted);if($outcome===null){throw new SecurityException('Idempotency request authority changed.','idempotency.denied');}$this->nativeOutcomeTime($outcome,$deadline,$seen);return ['outcome'=>$outcome];
            },function(array $result)use($request,$deadline,&$seen,&$plan):void{
                $outcome=$this->nativeResult($result);$this->nativeOutcomeTime($outcome,$deadline,$seen);$admitted=$this->admittedRoot($plan);
                if(!$this->nativeRequestAuthority('return',$request,$admitted['metadata'])){throw new SecurityException('Idempotency request authority changed before return.','idempotency.denied');}$this->nativeOutcomeTime($outcome,$deadline,$seen);
            },$deadline);
            $this->nativeTime($deadline,$seen);if($result===null){return null;}$outcome=$this->nativeResult($result);$this->nativeOutcomeTime($outcome,$deadline,$seen);return $outcome;
        }finally{$this->nativeBusy=false;}
    }
    public function executeFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,Request $request,array $businessTables,callable $handler):?Outcome
    {
        $this->executionTarget($request,$businessTables);return $this->nativeRequest('execute',$policy,$permission,$request,$handler,$this->requestConfiguration($businessTables));
    }
    public function lookupFor(\SoSecurity\Account\StateAccountPolicy $policy,\SoSecurity\Account\StatePermission $permission,Request $request):?Outcome
    {
        $this->lookupTarget($request);return $this->nativeRequest('lookup',$policy,$permission,$request,null,$this->nativeConfiguration());
    }
    public function __debugInfo():array {return ['idempotency'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild SQL executors from trusted configuration.','configuration.idempotency_serialization');}
}
