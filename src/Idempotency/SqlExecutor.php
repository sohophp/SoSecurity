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

    public function __construct(PDO $connection,string $site,string $epoch,HmacKeys $integrityKeys,callable $authority,?Policy $policy=null,?Clock $clock=null,?callable $managementGuard=null)
    {
        Guard::label($site);if(!preg_match('//u',$site)||!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)){throw new ConfigurationException('Use a fixed site and trusted deployment epoch.','configuration.idempotency');}
        $this->policy=$policy ?? new Policy();$this->unit=new SqlTransaction($connection,$clock ?? new SystemClock(),$this->policy->ioMilliseconds());$this->site=$site;$this->epoch=$epoch;$this->keys=$integrityKeys;$this->authority=$authority;$this->management=$managementGuard;$prefix=$this->unit->prefix();$this->roots=$prefix.'sosecurity_idempotency_roots';$this->records=$prefix.'sosecurity_idempotency_records';
    }
    private function namespace(string $scope,string $subject,string $operation):string {return State::namespace($this->site,$scope,$subject,$operation);}
    private function management(string $operation,string $scope,string $subject,string $action):bool
    {
        return $this->management!==null&&$this->unit->invoke($this->management,[$operation,$scope,$subject,$action],'idempotency.management')===true;
    }
    private function authorize(string $phase,Request $request,array $metadata=[]):bool
    {
        return $this->unit->invoke($this->authority,[$phase,$request,$metadata],'idempotency.authority')===true;
    }
    private function root(string $namespace,bool $optional=false):?array
    {
        $row=$this->unit->query('SELECT '.implode(',',State::rootFields()).' FROM '.$this->roots.' WHERE namespace=:namespace'.($this->unit->driver()==='mysql'?' FOR UPDATE':''),['namespace'=>$namespace])->fetch(PDO::FETCH_ASSOC);
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
            $rows=$this->unit->query('SELECT key_hash,execution_id FROM '.$this->records.' WHERE namespace=:namespace'.($cursor===null?'':' AND key_hash>:after_key').' ORDER BY key_hash LIMIT '.$limit.($this->unit->driver()==='mysql'?' FOR UPDATE':''),$parameters)->fetchAll(PDO::FETCH_ASSOC);
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
        $this->unit->query($sql,$root)->closeCursor();$read=$this->root($root['namespace']);if($read!==$root){throw new StorageException('Idempotency root changed during storage.','idempotency.corrupt');}return $root;
    }
    private function bytes():string {return SqlSchema::blobLength($this->unit->driver(),'response_body');}
    private function record(string $namespace,string $key):?array
    {
        $row=$this->unit->query('SELECT '.implode(',',State::recordFields()).','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash'.($this->unit->driver()==='mysql'?' FOR UPDATE':''),['namespace'=>$namespace,'key_hash'=>$key])->fetch(PDO::FETCH_ASSOC);
        return $row===false?null:State::record($row,$this->keys,$this->policy,$namespace,$this->epoch,$this->unit->now());
    }
    private function body(array $row):string
    {
        $stored=$this->unit->query('SELECT response_body,'.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash=:key_hash AND '.$this->bytes().'=:bytes'.($this->unit->driver()==='mysql'?' FOR UPDATE':''),['namespace'=>$row['namespace'],'key_hash'=>$row['key_hash'],'bytes'=>$row['response_bytes']])->fetch(PDO::FETCH_ASSOC);
        if(!is_array($stored)||!array_key_exists('response_body',$stored)||SqlSchema::integer($stored['body_length'])!==$row['response_bytes']){throw new StorageException('Idempotency response row is missing or changed.','idempotency.corrupt');}
        // PDO SQLite 7.2 returns null for a real zero-byte BLOB. The row and SQL length predicate distinguish it from NULL/missing state.
        $body=$stored['response_body']===null&&$row['response_bytes']===0?'':$stored['response_body'];
        if(!is_string($body)||strlen($body)!==$row['response_bytes']||!hash_equals(hash('sha256',$body),$row['response_digest'])){throw new StorageException('Idempotency response bytes changed.','idempotency.corrupt');}return $body;
    }
    private function saveRecord(array $row,string $body,bool $insert=false):array
    {
        unset($row['body_length']);$row=State::seal($row,$this->keys,false);$parameters=$row;$parameters['response_body']=$body;$fields=array_merge(State::recordFields(),['response_body']);
        $sql=$insert?'INSERT INTO '.$this->records.'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->records.' SET '.implode(',',array_map(static function(string $name):string{return $name.'=:'.$name;},array_diff($fields,['namespace','key_hash']))).' WHERE namespace=:namespace AND key_hash=:key_hash';
        $this->unit->query($sql,$parameters,['response_body'])->closeCursor();$row['body_length']=strlen($body);$read=$this->record($row['namespace'],$row['key_hash']);
        if($read!==$row||$this->body($row)!==$body){throw new StorageException('Idempotency response changed during storage.','idempotency.corrupt');}return $row;
    }
    private function metadata(array $row,bool $replayed):array {return ['execution_id'=>$row['execution_id'],'fingerprint'=>$row['fingerprint'],'created_at'=>$row['created_at'],'expires_at'=>$row['expires_at'],'replayed'=>$replayed];}
    public function initialize(string $scope,string $subject,string $operation):bool
    {
        $namespace=$this->namespace($scope,$subject,$operation);
        $result=$this->unit->run(function()use($namespace):array{
            Schema::verify($this->unit);$root=$this->root($namespace,true);if($root!==null){return ['created'=>false,'root'=>$root];}
            if($this->unit->query('SELECT 1 FROM '.$this->records.' WHERE namespace=:namespace LIMIT 1'.($this->unit->driver()==='mysql'?' FOR UPDATE':''),['namespace'=>$namespace])->fetchColumn()!==false){throw new StorageException('Do not initialize an orphaned idempotency history.','idempotency.history');}
            $now=$this->unit->now();$root=State::seal(['namespace'=>$namespace,'format'=>2,'epoch'=>$this->epoch,'policy'=>$this->policy->fingerprint(),'entries'=>0,'history_digest'=>hash('sha256',State::historyPrefix($namespace)),'revision'=>1,'created_at'=>$now,'observed_at'=>$now],$this->keys,true);$this->saveRoot($root,true);return ['created'=>true,'root'=>$root];
        },function()use($scope,$subject,$operation):bool{return $this->management('initialize',$scope,$subject,$operation);},function(array $state)use($scope,$subject,$operation){
            if(!$this->management('initialize',$scope,$subject,$operation)){throw new SecurityException('Idempotency management changed.','idempotency.denied');}
            if($this->root($state['root']['namespace'])!==$state['root']){throw new StorageException('Idempotency root changed.','idempotency.corrupt');}$this->saveRoot($this->touch($state['root']));
        },function()use($scope,$subject,$operation){if(!$this->management('initialize',$scope,$subject,$operation)){throw new SecurityException('Idempotency management changed after commit.','idempotency.denied');}});
        return $result!==null&&$result['created']===true;
    }
    public function execute(Request $request,callable $handler):?Outcome {return $this->operate($request,$handler);}
    public function lookup(Request $request):?Outcome {return $this->operate($request,null);}
    private function operate(Request $request,?callable $handler):?Outcome
    {
        $namespace=$this->namespace($request->scope(),$request->subject(),$request->operation());$key=hash('sha256',$request->key());$execution=bin2hex(random_bytes(16));$budget=new Deadline($this->policy->ioMilliseconds());
        try{$result=$this->unit->run(function()use($request,$handler,$namespace,$key,$execution):array{
            Schema::verify($this->unit);$root=$this->root($namespace);$row=$this->record($namespace,$key);
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
            $state['phase']='execute';$now=$this->unit->now();$row=['namespace'=>$namespace,'key_hash'=>$key,'format'=>1,'epoch'=>$this->epoch,'policy'=>$this->policy->fingerprint(),'execution_id'=>$execution,'fingerprint'=>$request->fingerprint(),'status'=>'running','status_code'=>0,'response_bytes'=>0,'response_digest'=>hash('sha256',''),'created_at'=>$now,'expires_at'=>$now+$this->policy->ttl(),'updated_at'=>$now];$state['metadata']=$this->metadata($row,false);
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
            if($this->unit->committed()){$this->observeCompletionFailure($namespace,$key,$budget);}throw $error;
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
    public function maintain(string $scope,string $subject,string $operation,int $limit=20,string $afterKey=''):?array
    {
        $namespace=$this->namespace($scope,$subject,$operation);if($limit<1||$limit>50||($afterKey!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$afterKey))){throw new ConfigurationException('Use bounded idempotency maintenance.','configuration.idempotency');}
        $result=$this->unit->run(function()use($namespace,$limit,$afterKey):array{
            Schema::verify($this->unit);$root=$this->root($namespace);$rows=$this->unit->query('SELECT '.implode(',',State::recordFields()).','.$this->bytes().' AS body_length FROM '.$this->records.' WHERE namespace=:namespace AND key_hash>:after_key ORDER BY key_hash LIMIT '.$limit.($this->unit->driver()==='mysql'?' FOR UPDATE':''),['namespace'=>$namespace,'after_key'=>$afterKey])->fetchAll(PDO::FETCH_ASSOC);
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
        },function()use($scope,$subject,$operation){if(!$this->management('maintain',$scope,$subject,$operation)){throw new SecurityException('Maintenance authority changed after commit.','idempotency.denied');}});
        return $result===null?null:$result['result'];
    }
    public function __debugInfo():array {return ['idempotency'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild SQL executors from trusted configuration.','configuration.idempotency_serialization');}
}
