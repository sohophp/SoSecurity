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
    public function __construct(PDO $connection,string $site,Endpoint $endpoint,HmacKeys $integrityKeys,callable $mapper,callable $associationGuard,callable $workerGuard,?ProcessingPolicy $policy=null,?Clock $clock=null,?callable $managementGuard=null)
    {
        Guard::label($site);if(!preg_match('//u',$site)){throw new ConfigurationException('Processing site must be UTF-8.','configuration.webhook_processing');}
        $this->driver=$connection->getAttribute(PDO::ATTR_DRIVER_NAME);
        if(!in_array($this->driver,['sqlite','mysql'],true)||(int)$connection->getAttribute(PDO::ATTR_ERRMODE)!==PDO::ERRMODE_EXCEPTION||($this->driver==='mysql'&&$connection->getAttribute(PDO::ATTR_EMULATE_PREPARES))){throw new ConfigurationException('Processing requires exception-mode SQLite/MySQL and native MySQL prepares.','configuration.webhook_processing');}
        $this->pdo=$connection;$this->endpoint=$endpoint;$this->namespace=hash('sha256',json_encode(['webhook-inbox-v1',$site,$endpoint->scope(),$endpoint->id(),$endpoint->account(),$endpoint->protocol()]));$this->keys=$integrityKeys;$this->mapper=$mapper;$this->association=$associationGuard;$this->workerGuard=$workerGuard;$this->management=$managementGuard;$this->policy=$policy ?? new ProcessingPolicy();$this->clock=$clock ?? new SystemClock();$prefix=$this->driver==='sqlite'?'main.':'';$this->table=$prefix.'sosecurity_webhook_processing';$this->inbox=$prefix.'sosecurity_webhook_inbox';
    }
    private function tick():int
    {
        $this->deadline->check('webhook.processing_timeout');try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Processing clock unavailable.','webhook.processing_clock');}if($now<0||$now>PHP_INT_MAX-100000||$now<$this->observed){throw new StorageException('Processing clock moved backwards.','webhook.processing_clock');}$this->observed=$now;return $now;
    }
    private function sql(string $sql,array $parameters=[]):\PDOStatement {return InboxSchema::statement($this->pdo,$sql,$parameters,$this->deadline);}
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
    private function guard(string $operation,string $receipt,string $worker,bool $management=false):bool
    {
        $this->tick();$callback=$management?$this->management:$this->workerGuard;if($callback===null){return false;}
        $endpoint=$this->endpoint;$callbackFailed=false;try{$result=$callback($operation,$endpoint,$receipt,$worker);}catch(\Throwable $error){$callbackFailed=true;$result=false;}$this->checkTransaction();if($callbackFailed){throw new DependencyException('Processing authority unavailable.','webhook.processing_authority');}$this->tick();return $result===true;
    }
    private function transaction(string $operation,string $receipt,string $worker,callable $body,bool $management=false)
    {
        if($this->failed||$this->busy){throw new StorageException('Rebuild the failed or busy processing service.','webhook.processing_cleanup');}if($this->pdo->inTransaction()){throw new ConfigurationException('Processing cannot commit a host transaction.','configuration.transaction');}
        if(($receipt!==''&&!preg_match('/\A[a-f0-9]{32}\z/D',$receipt))||!preg_match('/\A[A-Za-z][A-Za-z0-9_.-]{0,63}\z/D',$worker)){throw new ConfigurationException('Use bounded server-owned receipt and worker identifiers.','configuration.webhook_processing');}
        $guardName='sosecurity_work_'.bin2hex(random_bytes(8));
        $this->busy=true;$this->deadline=new Deadline($this->policy->ioMilliseconds());$this->observed=0;$owned=false;$timeout=null;$result=null;$completed=false;$this->completion=null;$this->sourceContext=null;$this->lostTransaction=false;$this->transactionGuard=null;
        try{
            if(!$this->guard($operation,$receipt,$worker,$management)){return null;}
            \SoSecurity\Support\SqlTransactionGuard::assertIdle($this->pdo,$this->driver,$this->deadline);
            if($this->driver==='sqlite'){$timeout=InboxState::integer($this->sql('PRAGMA busy_timeout')->fetchColumn());$this->command('PRAGMA busy_timeout='.max(1,min($timeout,(int)ceil($this->deadline->remaining()*1000))));$this->command('BEGIN IMMEDIATE');$owned=true;}
            else{$timeout=InboxState::integer($this->sql('SELECT @@SESSION.innodb_lock_wait_timeout')->fetchColumn());$this->command('SET SESSION innodb_lock_wait_timeout='.max(1,min($timeout,(int)ceil($this->deadline->remaining()))));if(!$this->pdo->beginTransaction()){throw new StorageException('Cannot start processing transaction.','webhook.processing_unavailable');}$owned=true;$this->sql('SELECT receipt_id FROM '.$this->table.' LIMIT 0')->closeCursor();$this->sql('SELECT receipt_id FROM '.$this->inbox.' LIMIT 0')->closeCursor();}
            $this->command('SAVEPOINT '.$guardName);$this->transactionGuard=$guardName;
            ProcessingSchema::verify($this->pdo,$this->driver,$this->deadline);$this->tick();$result=$body();
            if(!$this->guard($operation,$receipt,$worker,$management)){$result=null;return null;}$this->tick();if($this->completion!==null){($this->completion)();}
            if($this->driver==='sqlite'){$this->command('COMMIT');}elseif(!$this->pdo->commit()){throw new StorageException('Processing commit was not confirmed.','webhook.processing_commit');}$owned=false;$completed=true;$this->transactionGuard=null;$this->tick();return $result;
        }catch(SecurityException $error){throw $error;}
        catch(ConfigurationException $error){throw $error;}
        catch(\Throwable $error){throw new StorageException('Processing transaction unavailable.','webhook.processing_unavailable');}
        finally{
            if($owned&&!$this->lostTransaction){try{if($this->driver==='sqlite'){$this->command('ROLLBACK');}elseif(!$this->pdo->rollBack()){$this->failed=true;}}catch(\Throwable $error){$this->failed=true;}}
            if($timeout!==null&&!$this->failed){try{$this->command(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$timeout);}catch(\Throwable $error){$this->failed=true;}}
            try{if($this->failed){throw new StorageException('Processing cleanup failed; rebuild the connection.','webhook.processing_cleanup');}if($completed){$this->tick();if(!$this->guard($operation,$receipt,$worker,$management)){throw new SecurityException('Processing authority changed during completion.','webhook.processing_denied');}if($this->completion!==null){($this->completion)();}}}finally{$this->busy=false;$this->completion=null;$this->sourceContext=null;$this->transactionGuard=null;}
        }
    }
    private function row(string $receipt):?array
    {
        $row=$this->sql('SELECT '.implode(',',ProcessingState::fields()).' FROM '.$this->table.' WHERE endpoint_key=:endpoint AND receipt_id=:receipt'.($this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->namespace,'receipt'=>$receipt])->fetch(PDO::FETCH_ASSOC);
        return $row===false?null:ProcessingState::read($row,$this->keys,$this->policy,$this->tick());
    }
    private function source(string $receipt,bool $lock):?array
    {
        $rows=$this->sql('SELECT endpoint_key,event_key,receipt_id,event_id,event_type,resource_id,descriptor,body_digest,created_at,seen_at,source_key,source_time,seal_key,seal,'.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').' AS bytes FROM '.$this->inbox.' WHERE endpoint_key=:endpoint AND receipt_id=:receipt LIMIT 2'.($lock&&$this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->namespace,'receipt'=>$receipt])->fetchAll(PDO::FETCH_ASSOC);
        if(!$rows){return null;}if(count($rows)!==1){throw new StorageException('Ambiguous receive record.','webhook.processing_source');}$row=InboxState::read($rows[0],$this->keys,$this->tick());
        if(!hash_equals($this->namespace,$row['endpoint_key'])||!hash_equals($receipt,$row['receipt_id'])||!hash_equals(hash('sha256',$row['event_id']),$row['event_key'])){throw new StorageException('Receive context changed.','webhook.processing_source');}return $row;
    }
    private function message(array $source):array
    {
        $payload=$this->sql('SELECT payload FROM '.$this->inbox.' WHERE endpoint_key=:endpoint AND event_key=:event AND receipt_id=:receipt AND '.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').'=:bytes'.($this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->namespace,'event'=>$source['event_key'],'receipt'=>$source['receipt_id'],'bytes'=>$source['bytes']])->fetchColumn();
        if(!is_string($payload)||strlen($payload)!==$source['bytes']||!hash_equals(hash('sha256',$payload),$source['body_digest'])){throw new StorageException('Received payload changed.','webhook.processing_source');}
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
        });
    }
    public function fail(string $worker,string $claimToken,string $errorCode,bool $retryable=true):?ProcessingStatus
    {
        if(!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$errorCode)){throw new ConfigurationException('Use a bounded server-defined failure code.','configuration.webhook_processing');}$token=$this->token($claimToken);if($token===null){return null;}
        return $this->transaction('fail',$token['receipt'],$worker,function()use($worker,$token,$errorCode,$retryable){$row=$this->row($token['receipt']);if($row===null||!$this->held($row,$token,$worker)){return null;}$now=$this->tick();$this->completion(null,'fail',$row['lease_until']);$retry=$retryable&&$row['attempt']<$this->policy->maximumAttempts()&&$row['total_attempts']<100;$row=$this->save(ProcessingState::release($row,$retry?'retry':'dead',$now,$errorCode,$retry?$now+$this->policy->retryDelay($row['attempt']):0));return ProcessingState::status($row);});
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
        $batch=$this->transaction('pending','',$worker,function()use($limit,$afterReceipt){
            $now=$this->tick();$query=$this->sql('SELECT i.receipt_id,p.status,p.due_at,p.lease_until FROM '.$this->inbox.' i LEFT JOIN '.$this->table.' p ON p.endpoint_key=i.endpoint_key AND p.receipt_id=i.receipt_id WHERE i.endpoint_key=:endpoint AND i.receipt_id>:after ORDER BY i.receipt_id LIMIT '.$limit,['endpoint'=>$this->namespace,'after'=>$afterReceipt]);
            $rows=$query->fetchAll(PDO::FETCH_ASSOC);$ids=[];$cursor=$afterReceipt;
            foreach($rows as $row){$id=$row['receipt_id'];if(!is_string($id)||!preg_match('/\A[a-f0-9]{32}\z/D',$id)){throw new StorageException('Invalid pending receipt.','webhook.processing_source');}$cursor=$id;
                if($row['status']===null){$ids[]=$id;continue;}
                if(!in_array($row['status'],['ready','retry','leased','succeeded','dead'],true)){throw new StorageException('Invalid processing candidate state.','webhook.processing_corrupt');}
                $due=InboxState::integer($row['due_at']);$until=InboxState::integer($row['lease_until']);
                if((in_array($row['status'],['ready','retry'],true)&&$due<=$now)||($row['status']==='leased'&&$until<=$now)){$ids[]=$id;}
            }
            return ['receipt_ids'=>$ids,'next_cursor'=>$cursor,'complete'=>count($rows)<$limit];
        });return $batch ?? ['receipt_ids'=>[],'next_cursor'=>$afterReceipt,'complete'=>true];
    }
    public function __debugInfo():array {return ['processing'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild processing services from trusted dependencies.','configuration.webhook_serialization');}
}
