<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SystemClock;

/** Processing only authenticated durable receipts. Business SQL and success are committed in one owned transaction. */
final class SqlProcessor
{
    private $pdo;
    private $endpoint;
    private $namespace;
    private $keys;
    private $mapper;
    private $association;
    private $workerGuard;
    private $management;
    private $policy;
    private $clock;
    private $driver;
    private $table;
    private $inbox;
    private $failed=false;
    private $busy=false;
    private $deadline;
    private $observed=0;
    private $completion;
    private $sourceContext;
    private $lostTransaction=false;
    private $transactionGuard;
    private $state;
    private $nativeBusy=false;
    private $observer;
    public function __construct(PDO $connection,string $site,Endpoint $endpoint,HmacKeys $integrityKeys,callable $mapper,callable $associationGuard,callable $workerGuard,?ProcessingPolicy $policy=null,?Clock $clock=null,?callable $managementGuard=null,?\SoSecurity\Account\StateWebhookConnection $state=null)
    {
        Guard::label($site);if(!preg_match('//u',$site)){throw new ConfigurationException('Processing site must be UTF-8.','configuration.webhook_processing');}
        $this->driver=$connection->getAttribute(PDO::ATTR_DRIVER_NAME);
        if(!in_array($this->driver,['sqlite','mysql'],true)||(int)$connection->getAttribute(PDO::ATTR_ERRMODE)!==PDO::ERRMODE_EXCEPTION||($this->driver==='mysql'&&$connection->getAttribute(PDO::ATTR_EMULATE_PREPARES))){throw new ConfigurationException('Processing requires exception-mode SQLite/MySQL and native MySQL prepares.','configuration.webhook_processing');}
        $this->pdo=$connection;$this->endpoint=$endpoint;$this->namespace=hash('sha256',json_encode(['webhook-inbox-v1',$site,$endpoint->scope(),$endpoint->id(),$endpoint->account(),$endpoint->protocol()]));$this->keys=$integrityKeys;$this->mapper=$mapper;$this->association=$associationGuard;$this->workerGuard=$workerGuard;$this->management=$managementGuard;$this->policy=$policy ?? new ProcessingPolicy();$this->clock=$clock ?? new SystemClock();$prefix=$this->driver==='sqlite'?'main.':'';$this->table=$prefix.'sosecurity_webhook_processing';$this->inbox=$prefix.'sosecurity_webhook_inbox';$this->state=$state;if($state!==null){$state->validateProcessing($connection,$site,$endpoint,$integrityKeys,$this->policy);}
    }
    private function tick():int
    {
        $this->deadline->check('webhook.processing_timeout');try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Processing clock unavailable.','webhook.processing_clock');}if($now<0||$now>PHP_INT_MAX-100000||$now<$this->observed){throw new StorageException('Processing clock moved backwards.','webhook.processing_clock');}$this->observed=$now;return $now;
    }
    private function sql(string $sql,array $parameters=[]):\PDOStatement {if($this->observer!==null){return $this->observer->query(preg_replace('/ FOR UPDATE$/D','',$sql),$parameters);}return InboxSchema::statement($this->pdo,$sql,$parameters,$this->deadline);}
    private function command(string $sql):void {if($this->pdo->exec($sql)===false){throw new StorageException('Processing transaction failed.','webhook.processing_unavailable');}}
    /** Detect callback COMMIT/ROLLBACK/implicit DDL, including PDO 7.2 exec-started SQLite transactions. */
    private function checkTransaction():void
    {
        if($this->transactionGuard===null){return;}
        try{$this->command('RELEASE SAVEPOINT '.$this->transactionGuard);}catch(\PDOException $error){
            $code=isset($error->errorInfo[1])?(int)$error->errorInfo[1]:0;
            if(($this->driver==='mysql'&&$code===1305)||($this->driver==='sqlite'&&$code===1)){$this->lostTransaction=true;$this->failed=true;}
            throw new ConfigurationException('A callback ended the owned processing transaction.','configuration.webhook_processing_transaction');
        }
        $this->command('SAVEPOINT '.$this->transactionGuard);$this->tick();
    }
    /** Current host authority can change across SQL and callbacks.
     * @phpstan-impure
     */
    private function guard(string $operation,string $receipt,string $worker,bool $management=false):bool
    {
        $this->tick();$callback=$management?$this->management:$this->workerGuard;if($callback===null){return false;}
        $endpoint=$this->endpoint;$callbackFailed=false;try{$result=$callback($operation,$endpoint,$receipt,$worker);}catch(\Throwable $error){$callbackFailed=true;$result=false;}$this->checkTransaction();if($callbackFailed){throw new DependencyException('Processing authority unavailable.','webhook.processing_authority');}$this->tick();return $result===true;
    }
    private function transaction(string $operation,string $receipt,string $worker,callable $body,bool $management=false,array $input=[])
    {
        if($this->state!==null){return $this->native($operation,$receipt,$worker,$body,$management,$input);}
        return $this->transactionCurrent($operation,$receipt,$worker,$body,$management);
    }
    private function transactionCurrent(string $operation,string $receipt,string $worker,callable $body,bool $management=false,?Deadline $budget=null,int $seen=0)
    {
        \SoSecurity\Support\SqlStateAccess::assertActive($this->pdo);
        if($this->failed||$this->busy){throw new StorageException('Rebuild the failed or busy processing service.','webhook.processing_cleanup');}if($this->pdo->inTransaction()){throw new ConfigurationException('Processing cannot commit a host transaction.','configuration.transaction');}
        if(($receipt!==''&&!preg_match('/\A[a-f0-9]{32}\z/D',$receipt))||!preg_match('/\A[A-Za-z][A-Za-z0-9_.-]{0,63}\z/D',$worker)){throw new ConfigurationException('Use bounded server-owned receipt and worker identifiers.','configuration.webhook_processing');}
        $guardName='sosecurity_work_'.bin2hex(random_bytes(8));
        $this->busy=true;$this->deadline=$budget??new Deadline($this->policy->ioMilliseconds());$this->observed=$seen;$owned=false;$timeout=null;$metadataTimeout=null;$result=null;$completed=false;$this->completion=null;$this->sourceContext=null;$this->lostTransaction=false;$this->transactionGuard=null;
        try{
            if(!$this->guard($operation,$receipt,$worker,$management)){return null;}
            \SoSecurity\Support\SqlTransactionGuard::assertIdle($this->pdo,$this->driver,$this->deadline);
            if($this->driver==='sqlite'){$timeout=InboxSchema::lockTimeout($this->pdo,'PRAGMA busy_timeout',$this->deadline,$this->failed);$this->command('PRAGMA busy_timeout='.min($timeout,max(1,(int)ceil($this->deadline->remaining()*1000))));$this->command('BEGIN IMMEDIATE');$owned=true;}
            else{$timeout=InboxSchema::lockTimeout($this->pdo,'SELECT @@SESSION.innodb_lock_wait_timeout',$this->deadline,$this->failed);$metadataTimeout=InboxSchema::lockTimeout($this->pdo,'SELECT @@SESSION.lock_wait_timeout',$this->deadline,$this->failed);$this->command('SET SESSION innodb_lock_wait_timeout='.max(1,min($timeout,(int)ceil($this->deadline->remaining()))));$this->command('SET SESSION lock_wait_timeout='.min($metadataTimeout,max(1,(int)ceil($this->deadline->remaining()))));if(!$this->pdo->beginTransaction()){throw new StorageException('Cannot start processing transaction.','webhook.processing_unavailable');}$owned=true;InboxSchema::close($this->sql('SELECT receipt_id FROM '.$this->table.' LIMIT 0'));InboxSchema::close($this->sql('SELECT receipt_id FROM '.$this->inbox.' LIMIT 0'));}
            $this->command('SAVEPOINT '.$guardName);$this->transactionGuard=$guardName;
            ProcessingSchema::verify($this->pdo,$this->driver,$this->deadline);$this->tick();$result=$body();
            if(!$this->guard($operation,$receipt,$worker,$management)){$result=null;return null;}$this->tick();if($this->completion!==null){($this->completion)();}
            if($this->driver==='sqlite'){$this->command('COMMIT');}elseif(!$this->pdo->commit()){throw new StorageException('Processing commit was not confirmed.','webhook.processing_commit');}$owned=false;$completed=true;$this->transactionGuard=null;$this->tick();return $result;
        }catch(SecurityException $error){if($error instanceof StorageException&&$error->reason()==='webhook.inbox_cleanup'){$this->failed=true;}throw $error;}
        catch(ConfigurationException $error){throw $error;}
        catch(\Throwable $error){throw new StorageException('Processing transaction unavailable.','webhook.processing_unavailable');}
        finally{
            if($owned&&!$this->lostTransaction){try{if($this->driver==='sqlite'){$this->command('ROLLBACK');}elseif(!$this->pdo->rollBack()){$this->failed=true;}}catch(\Throwable $error){$this->failed=true;}}
            if($metadataTimeout!==null&&!$this->failed){try{$this->command('SET SESSION lock_wait_timeout='.$metadataTimeout);}catch(\Throwable $error){$this->failed=true;}}
            if($timeout!==null&&!$this->failed){try{$this->command(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$timeout);}catch(\Throwable $error){$this->failed=true;}}
            try{if($this->failed){throw new StorageException('Processing cleanup failed; rebuild the connection.','webhook.processing_cleanup');}if($completed){$this->tick();if(!$this->guard($operation,$receipt,$worker,$management)){throw new SecurityException('Processing authority changed during completion.','webhook.processing_denied');}if($this->completion!==null){($this->completion)();}}}finally{$this->busy=false;$this->completion=null;$this->sourceContext=null;$this->transactionGuard=null;}
        }
    }
    /** Admission reads only; host mapping and authority callbacks run after the observation transaction. */
    private function nativeView(string $operation,string $receipt,array $input):array
    {
        $unit=\SoSecurity\Support\SqlTransaction::forObservation($this->pdo,$this->clock,$this->policy->ioMilliseconds());
        try{return $unit->run(function()use($unit,$operation,$receipt,$input):array{
            $this->observer=$unit;
            if($operation==='pending'){return ['pending'=>$this->pendingRows($input['limit'],$input['after'])];}
            $row=$this->row($receipt);$source=null;$payload=null;$count=0;
            if($operation!=='fail'){$source=$this->source($receipt,false);if($source!==null){$payload=$this->payload($source);}}
            if($operation==='claim'&&$row===null&&$source!==null){$q=$this->sql('SELECT COUNT(*) FROM '.$this->table);try{$count=InboxState::integer($q->fetchColumn());}finally{$q->closeCursor();}}
            return ['row'=>$row,'source'=>$source,'payload'=>$payload,'count'=>$count];
        },null,null,null,$this->deadline);}finally{$this->observer=null;}
    }
    private function native(string $operation,string $receipt,string $worker,callable $body,bool $management,array $input)
    {
        if($this->failed||$this->busy||$this->nativeBusy){throw new StorageException('Rebuild the failed or busy processing service.','webhook.processing_cleanup');}
        if(($receipt!==''&&!preg_match('/\A[a-f0-9]{32}\z/D',$receipt))||!preg_match('/\A[A-Za-z][A-Za-z0-9_.-]{0,63}\z/D',$worker)){throw new ConfigurationException('Use bounded server-owned receipt and worker identifiers.','configuration.webhook_processing');}
        $this->nativeBusy=true;$this->deadline=new Deadline($this->policy->ioMilliseconds());$this->observed=0;$this->sourceContext=null;$readResult=null;$budget=$this->deadline;
        try{
            $result=$this->state->process($operation,function(string $expected)use($operation,$receipt,$worker,$management,$input,&$readResult){
                if(!$this->guard($operation,$receipt,$worker,$management)){return false;}
                $view=$this->nativeView($operation,$receipt,$input);
                if($operation==='pending'){
                    if(!$this->guard($operation,$receipt,$worker,$management)){return false;}$readResult=$view['pending'];return false;
                }
                $row=$view['row'];$source=$view['source'];$now=$this->tick();
                if($operation==='claim'){
                    if($source===null){return false;}
                    if($row!==null&&(in_array($row['status'],['succeeded','dead'],true)||($row['status']==='leased'&&$row['lease_until']>$now)||$row['due_at']>$now)){return false;}
                    if($row===null&&$view['count']>=$this->state->processingLimit()){throw new SecurityException('Webhook processing source capacity reached.','webhook.processing_capacity');}
                }else{
                    if($row===null){return false;}
                    if(in_array($operation,['execute','fail'],true)&&!$this->held($row,$input['token'],$worker)){return false;}
                    if($operation==='retry'&&($row['status']!=='dead'||$row['manual_retries']>=$this->policy->maximumManualRetries()||$row['total_attempts']>=100)){return false;}
                }
                if($operation!=='fail'){
                    if($source===null){throw new StorageException('Receive record missing for an existing processing record.','webhook.processing_source');}
                    if($row!==null){$this->bound($row,$source);}list($message)=$this->message($source,$view['payload']);
                    if(!$this->associated($message,$operation)){return false;}
                }
                if(!$this->guard($operation,$receipt,$worker,$management)){return false;}
                if(in_array($operation,['execute','fail'],true)&&!$this->held($row,$input['token'],$worker)){return false;}
                if($operation==='status'){$readResult=ProcessingState::status($row);return false;}
                $now=$this->tick();$request=hash('sha256',json_encode(['SoSecurity.Webhook.Processing.Request.1',$operation,$this->namespace,$receipt,$worker,$input,$expected]));
                return \SoSecurity\Account\StateOperation::webhookProcessing('webhook.processing.'.$operation,$this->endpoint->scope(),hash('sha256',$worker),hash('sha256',$receipt),$request,$this->state->binding(),$now);
            },function()use($operation,$receipt,$worker,$body,$management,$budget){return $this->transactionCurrent($operation,$receipt,$worker,$body,$management,$budget,$this->observed);});
            return in_array($operation,['status','pending'],true)?$readResult:$result;
        }finally{$this->nativeBusy=false;$this->observer=null;$this->sourceContext=null;}
    }
    /** Fixed SQL projections preserve accepted representations while bounding bytes before PDO allocation. */
    private function columns(bool $source):string
    {
        $limits=$source?['endpoint_key'=>64,'event_key'=>64,'receipt_id'=>32,'event_id'=>256,'event_type'=>64,'resource_id'=>256,'descriptor'=>64,'body_digest'=>64,'created_at'=>19,'seen_at'=>19,'source_key'=>32,'source_time'=>19,'seal_key'=>32,'seal'=>64]:['endpoint_key'=>64,'receipt_id'=>32,'event_key'=>64,'body_digest'=>64,'descriptor'=>64,'policy'=>64,'status'=>9,'attempt'=>19,'total_attempts'=>19,'manual_retries'=>19,'revision'=>19,'due_at'=>19,'lease_until'=>19,'claim_digest'=>64,'worker_digest'=>64,'error_code'=>64,'created_at'=>19,'updated_at'=>19,'seal_key'=>32,'seal'=>64];$fields=[];
        foreach($limits as $name=>$maximum){$bytes=$this->driver==='sqlite'?'length(CAST('.$name.' AS BLOB))':'OCTET_LENGTH('.$name.')';$nullable=$source&&$name==='source_time';$fields[]='CASE '.($nullable?'WHEN '.$name.' IS NULL THEN NULL ':'').'WHEN '.$bytes.'<='.$maximum.' THEN '.$name.' ELSE '.($nullable?'-1':'NULL').' END AS '.$name;}
        return implode(',',$fields);
    }
    /** Consume ordinary reads and retain cleanup failure across native/ordinary entry points. @return mixed */
    private function fetched(\PDOStatement $query,string $mode)
    {
        try{return InboxSchema::read($query,$mode);}catch(StorageException $error){if($error->reason()==='webhook.inbox_cleanup'){$this->failed=true;}throw $error;}
    }
    private function row(string $receipt):?array
    {
        $row=$this->fetched($this->sql('SELECT '.$this->columns(false).' FROM '.$this->table.' WHERE endpoint_key=:endpoint AND receipt_id=:receipt'.($this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->namespace,'receipt'=>$receipt]),'row');
        return $row===false?null:ProcessingState::read($row,$this->keys,$this->policy,$this->tick());
    }
    private function source(string $receipt,bool $lock):?array
    {
        $rows=$this->fetched($this->sql('SELECT '.$this->columns(true).','.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').' AS bytes FROM '.$this->inbox.' WHERE endpoint_key=:endpoint AND receipt_id=:receipt LIMIT 2'.($lock&&$this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->namespace,'receipt'=>$receipt]),'all');
        if(!$rows){return null;}if(count($rows)!==1){throw new StorageException('Ambiguous receive record.','webhook.processing_source');}$row=InboxState::read($rows[0],$this->keys,$this->tick());
        if(!hash_equals($this->namespace,$row['endpoint_key'])||!hash_equals($receipt,$row['receipt_id'])||!hash_equals(hash('sha256',$row['event_id']),$row['event_key'])){throw new StorageException('Receive context changed.','webhook.processing_source');}return $row;
    }
    private function payload(array $source):string
    {
        $payload=$this->fetched($this->sql('SELECT payload FROM '.$this->inbox.' WHERE endpoint_key=:endpoint AND event_key=:event AND receipt_id=:receipt AND '.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').'=:bytes'.($this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->namespace,'event'=>$source['event_key'],'receipt'=>$source['receipt_id'],'bytes'=>$source['bytes']]),'column');
        if(!is_string($payload)||strlen($payload)!==$source['bytes']||!hash_equals(hash('sha256',$payload),$source['body_digest'])){throw new StorageException('Received payload changed.','webhook.processing_source');}
        return $payload;
    }
    private function message(array $source,?string $payload=null):array
    {
        if($payload===null){$payload=$this->payload($source);}
        $this->tick();$input=$payload;$endpoint=$this->endpoint;$receipt=$source['receipt_id'];
        $metadata=['message_id'=>$source['event_id'],'type'=>$source['event_type'],'resource'=>$source['resource_id'],'received_at'=>$source['created_at'],'source_key'=>$source['source_key'],'source_time'=>$source['source_time']];
        $callbackFailed=false;try{$message=($this->mapper)($input,$endpoint,$receipt,$metadata);}catch(\Throwable $error){$callbackFailed=true;$message=null;}$this->checkTransaction();if($callbackFailed){throw new DependencyException('Processing message mapper unavailable.','webhook.processing_mapping');}$this->tick();
        if(!$message instanceof Message||$message->id()!==$source['event_id']||$message->type()!==$source['event_type']||$message->resource()!==$source['resource_id']||!hash_equals($message->fingerprint(),$source['descriptor'])){throw new SecurityException('Processing message differs from received association.','webhook.processing_source');}$this->sourceContext=['receipt_id'=>$source['receipt_id'],'received_at'=>$source['created_at'],'source_key'=>$source['source_key'],'source_time'=>$source['source_time']];return [$message,$payload];
    }
    private function associated(Message $message,string $phase):bool
    {
        $this->tick();$endpoint=$this->endpoint;$provenance=$this->sourceContext;$callbackFailed=false;try{$allowed=($this->association)($endpoint,$message,$phase,$provenance);}catch(\Throwable $error){$callbackFailed=true;$allowed=false;}$this->checkTransaction();if($callbackFailed){throw new DependencyException('Processing association unavailable.','webhook.processing_association');}$this->tick();return $allowed===true;
    }
    private function completion(?Message $message,string $phase,int $leaseUntil=0):void
    {
        $this->completion=function()use($message,$phase,$leaseUntil){$now=$this->tick();if(($leaseUntil>0&&$now>=$leaseUntil)||($message!==null&&!$this->associated($message,$phase))){throw new SecurityException('Processing completion denied or expired.','webhook.processing_denied');}};
    }
    private function save(array $row):array
    {
        $row=ProcessingState::seal($row,$this->keys);$assign=[];foreach(ProcessingState::fields() as $name){if(!in_array($name,['endpoint_key','receipt_id'],true)){$assign[]=$name.'=:'.$name;}}
        $this->sql('UPDATE '.$this->table.' SET '.implode(',',$assign).' WHERE endpoint_key=:endpoint_key AND receipt_id=:receipt_id',$row)->closeCursor();$final=$this->row($row['receipt_id']);if($final!==$row){throw new StorageException('Processing record changed.','webhook.processing_corrupt');}return $row;
    }
    private function bound(array $row,array $source):void {foreach(['event_key','body_digest','descriptor'] as $field){if(!hash_equals($row[$field],$source[$field])){throw new SecurityException('Processing source binding changed.','webhook.processing_source');}}}
    private function token(string $token):?array
    {
        if(!preg_match('/\Awc1\.([a-f0-9]{32})\.([1-9][0-9]{0,18})\.([a-f0-9]{64})\z/D',$token,$parts)||(string)(int)$parts[2]!==$parts[2]){return null;}return ['receipt'=>$parts[1],'revision'=>(int)$parts[2],'digest'=>hash('sha256',$parts[3])];
    }
    /** Reads live time; validity must be refreshed after SQL and host callbacks.
     * @phpstan-impure
     */
    private function held(array $row,array $token,string $worker):bool {return $row['status']==='leased'&&$row['revision']===$token['revision']&&$row['lease_until']>$this->tick()&&hash_equals($row['claim_digest'],$token['digest'])&&hash_equals($row['worker_digest'],hash('sha256',$worker));}
    public function claim(string $receiptId,string $worker):?ProcessingClaim
    {
        $secret=bin2hex(random_bytes(32));return $this->transaction('claim',$receiptId,$worker,function()use($receiptId,$worker,$secret){
            // Seed only from authenticated metadata, then lock processing before receive consistently across all mutations.
            $source=$this->source($receiptId,false);if($source===null){return null;}$now=$this->tick();$seed=['endpoint_key'=>$this->namespace,'receipt_id'=>$receiptId,'event_key'=>$source['event_key'],'body_digest'=>$source['body_digest'],'descriptor'=>$source['descriptor'],'policy'=>$this->policy->fingerprint(),'status'=>'ready','attempt'=>0,'total_attempts'=>0,'manual_retries'=>0,'revision'=>1,'due_at'=>$now,'lease_until'=>0,'claim_digest'=>'','worker_digest'=>'','error_code'=>'','created_at'=>$now,'updated_at'=>$now];$seed=ProcessingState::seal($seed,$this->keys);
            $fields=ProcessingState::fields();$sql=($this->driver==='sqlite'?'INSERT OR IGNORE INTO ':'INSERT INTO ').$this->table.'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')';if($this->driver==='mysql'){$sql.=' ON DUPLICATE KEY UPDATE receipt_id=receipt_id';}$this->sql($sql,$seed)->closeCursor();$row=$this->row($receiptId);$source=$this->source($receiptId,true);if($row===null||$source===null){throw new StorageException('Processing source disappeared.','webhook.processing_source');}$this->bound($row,$source);list($message)=$this->message($source);
            if(!$this->associated($message,'claim')){throw new SecurityException('Processing association denied.','webhook.processing_denied');}$now=$this->tick();
            if(in_array($row['status'],['succeeded','dead'],true)||($row['status']==='leased'&&$row['lease_until']>$now)||$row['due_at']>$now){return null;}
            if($row['attempt']>=$this->policy->maximumAttempts()||$row['total_attempts']>=100){$this->save(ProcessingState::release($row,'dead',$now,'processing.exhausted'));return null;}
            $row['status']='leased';++$row['attempt'];++$row['total_attempts'];++$row['revision'];$row['due_at']=0;$row['lease_until']=$now+$this->policy->leaseSeconds();$row['claim_digest']=hash('sha256',$secret);$row['worker_digest']=hash('sha256',$worker);$row['error_code']='';$row['updated_at']=$now;$row=$this->save($row);$this->completion($message,'claim',$row['lease_until']);return new ProcessingClaim('wc1.'.$receiptId.'.'.$row['revision'].'.'.$secret,ProcessingState::status($row));
        });
    }
    public function execute(string $worker,string $claimToken,callable $handler):?ProcessingStatus
    {
        $token=$this->token($claimToken);if($token===null){return null;}return $this->transaction('execute',$token['receipt'],$worker,function()use($worker,$token,$handler){
            $row=$this->row($token['receipt']);if($row===null||!$this->held($row,$token,$worker)){return null;}$source=$this->source($token['receipt'],true);if($source===null){throw new StorageException('Receive record missing.','webhook.processing_source');}$this->bound($row,$source);list($message,$payload)=$this->message($source);if(!$this->associated($message,'execute')||!$this->held($row,$token,$worker)){return null;}
            // Trusted handler: SQL on this PDO only. No own transaction, DDL, network, mail or external side effects.
            $connection=$this->pdo;$workMessage=$message;$workPayload=$payload;$status=ProcessingState::status($row);$callbackFailed=false;
            try{$done=$handler($connection,$workMessage,$workPayload,$status);}catch(\Throwable $error){$callbackFailed=true;$done=false;}
            $this->checkTransaction();if($callbackFailed){throw new DependencyException('Processing handler did not complete.','webhook.processing_handler');}
            $this->tick();$current=$this->source($token['receipt'],true);if($current===null){throw new StorageException('Receive record disappeared during processing.','webhook.processing_source');}$this->bound($row,$current);list($freshMessage,$freshPayload)=$this->message($current);if(!hash_equals($payload,$freshPayload)||$freshMessage->fingerprint()!==$message->fingerprint()){throw new SecurityException('Processing source changed during work.','webhook.processing_source');}
            if($done!==true||!$this->associated($message,'commit')||!$this->held($row,$token,$worker)){throw new SecurityException('Processing completion denied or expired.','webhook.processing_denied');}
            $until=$row['lease_until'];$row=$this->save(ProcessingState::release($row,'succeeded',$this->tick()));$this->completion($message,'commit',$until);return ProcessingState::status($row);
        },false,['token'=>$token]);
    }
    public function fail(string $worker,string $claimToken,string $errorCode,bool $retryable=true):?ProcessingStatus
    {
        if(!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$errorCode)){throw new ConfigurationException('Use a bounded server-defined failure code.','configuration.webhook_processing');}$token=$this->token($claimToken);if($token===null){return null;}
        return $this->transaction('fail',$token['receipt'],$worker,function()use($worker,$token,$errorCode,$retryable){$row=$this->row($token['receipt']);if($row===null||!$this->held($row,$token,$worker)){return null;}$now=$this->tick();$this->completion(null,'fail',$row['lease_until']);$retry=$retryable&&$row['attempt']<$this->policy->maximumAttempts()&&$row['total_attempts']<100;$row=$this->save(ProcessingState::release($row,$retry?'retry':'dead',$now,$errorCode,$retry?$now+$this->policy->retryDelay($row['attempt']):0));return ProcessingState::status($row);},false,['token'=>$token,'error'=>$errorCode,'retryable'=>$retryable]);
    }
    public function retry(string $receiptId,string $operator):?ProcessingStatus
    {
        return $this->transaction('retry',$receiptId,$operator,function()use($receiptId){$row=$this->row($receiptId);if($row===null||$row['status']!=='dead'||$row['manual_retries']>=$this->policy->maximumManualRetries()||$row['total_attempts']>=100){return null;}$source=$this->source($receiptId,true);if($source===null){throw new StorageException('Receive record missing for an existing processing record.','webhook.processing_source');}$this->bound($row,$source);list($message)=$this->message($source);if(!$this->associated($message,'retry')){return null;}$row=ProcessingState::release($row,'retry',$this->tick());$row['due_at']=$row['updated_at'];$row['attempt']=0;++$row['manual_retries'];$this->completion($message,'retry');return ProcessingState::status($this->save($row));},true);
    }
    public function status(string $receiptId,string $worker):?ProcessingStatus
    {
        return $this->transaction('status',$receiptId,$worker,function()use($receiptId){$row=$this->row($receiptId);if($row===null){return null;}$source=$this->source($receiptId,true);if($source===null){throw new StorageException('Receive record missing for an existing processing record.','webhook.processing_source');}$this->bound($row,$source);list($message)=$this->message($source);if(!$this->associated($message,'status')){return null;}$this->completion($message,'status');return ProcessingState::status($row);});
    }
    /** Scan at most limit indexed receipt rows. Advance next_cursor even when no candidate is eligible. */
    public function pending(string $worker,int $limit=20,string $afterReceipt=''):array
    {
        if($limit<1||$limit>50||($afterReceipt!==''&&!preg_match('/\A[a-f0-9]{32}\z/D',$afterReceipt))){throw new ConfigurationException('Pending scans require a bounded limit and canonical cursor.','configuration.webhook_processing');}
        $batch=$this->transaction('pending','',$worker,function()use($limit,$afterReceipt){return $this->pendingRows($limit,$afterReceipt);},false,['limit'=>$limit,'after'=>$afterReceipt]);return $batch ?? ['receipt_ids'=>[],'next_cursor'=>$afterReceipt,'complete'=>true];
    }
    private function pendingRows(int $limit,string $afterReceipt):array
    {
            $fields=[];foreach(['i.receipt_id'=>32,'p.status'=>9,'p.due_at'=>19,'p.lease_until'=>19] as $name=>$maximum){
                $bytes=$this->driver==='sqlite'?'length(CAST('.$name.' AS BLOB))':'OCTET_LENGTH('.$name.')';$status=$name==='p.status';
                // Only an absent LEFT JOIN row may use NULL status; oversized existing status must remain invalid.
                $fields[]='CASE '.($status?'WHEN '.$name.' IS NULL THEN NULL ':'').'WHEN '.$bytes.'<='.$maximum.' THEN '.$name.' ELSE '.($status?"''":'NULL').' END AS '.substr($name,strpos($name,'.')+1);
            }
            $now=$this->tick();$query=$this->sql('SELECT '.implode(',',$fields).' FROM '.$this->inbox.' i LEFT JOIN '.$this->table.' p ON p.endpoint_key=i.endpoint_key AND p.receipt_id=i.receipt_id WHERE i.endpoint_key=:endpoint AND i.receipt_id>:after ORDER BY i.receipt_id LIMIT '.$limit,['endpoint'=>$this->namespace,'after'=>$afterReceipt]);
            $rows=$this->fetched($query,'all');if(count($rows)>$limit){throw new StorageException('Pending row budget exceeded.','webhook.processing_corrupt');}$ids=[];$cursor=$afterReceipt;
            foreach($rows as $row){
                if(!is_array($row)||count($row)!==4){throw new StorageException('Invalid pending row.','webhook.processing_corrupt');}foreach(['receipt_id','status','due_at','lease_until'] as $name){if(!array_key_exists($name,$row)){throw new StorageException('Invalid pending fields.','webhook.processing_corrupt');}}
                $id=$row['receipt_id'];if(!is_string($id)||!preg_match('/\A[a-f0-9]{32}\z/D',$id)||strcmp($id,$cursor)<=0){throw new StorageException('Invalid pending receipt or non-advancing cursor.','webhook.processing_source');}$cursor=$id;
                if($row['status']===null){if($row['due_at']!==null||$row['lease_until']!==null){throw new StorageException('Inconsistent missing processing row.','webhook.processing_corrupt');}$ids[]=$id;continue;}
                if(!in_array($row['status'],['ready','retry','leased','succeeded','dead'],true)){throw new StorageException('Invalid processing candidate state.','webhook.processing_corrupt');}
                $due=InboxState::integer($row['due_at']);$until=InboxState::integer($row['lease_until']);
                if((in_array($row['status'],['ready','retry'],true)&&$due<=$now)||($row['status']==='leased'&&$until<=$now)){$ids[]=$id;}
            }
            return ['receipt_ids'=>$ids,'next_cursor'=>$cursor,'complete'=>count($rows)<$limit];
    }

    public function __debugInfo():array {return ['processing'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild processing services from trusted dependencies.','configuration.webhook_serialization');}
}
