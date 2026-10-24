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
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Durable receive only. Owns its transaction; never retries uncertain commits or executes business side effects. */
final class SqlInbox
{
    private $pdo;
    private $verifier;
    private $seals;
    private $association;
    private $clock;
    private $driver;
    private $table;
    private $endpointKey;
    private $failed=false;
    private $state;
    public function __construct(PDO $connection,string $site,Verifier $verifier,HmacKeys $integrityKeys,callable $associationGuard,?Clock $clock=null,?\SoSecurity\Account\StateWebhookConnection $state=null)
    {
        Guard::label($site);if(!preg_match('//u',$site)){throw new ConfigurationException('Webhook receive site must be UTF-8.','configuration.webhook_inbox');}
        $driver=$connection->getAttribute(PDO::ATTR_DRIVER_NAME);if(!in_array($driver,['sqlite','mysql'],true)||(int)$connection->getAttribute(PDO::ATTR_ERRMODE)!==PDO::ERRMODE_EXCEPTION||($driver==='mysql'&&$connection->getAttribute(PDO::ATTR_EMULATE_PREPARES))){throw new ConfigurationException('Webhook receive requires exception-mode SQLite/MySQL and native MySQL prepares.','configuration.webhook_inbox');}
        $this->pdo=$connection;$this->verifier=$verifier;$this->seals=$integrityKeys;$this->association=$associationGuard;$this->clock=$clock ?? new SystemClock();$this->driver=$driver;$this->table=$driver==='sqlite'?'main.sosecurity_webhook_inbox':'sosecurity_webhook_inbox';$endpoint=$verifier->endpoint();$this->endpointKey=hash('sha256',json_encode(['webhook-inbox-v1',$site,$endpoint->scope(),$endpoint->id(),$endpoint->account(),$endpoint->protocol()]));
        if($state!==null){$state->validateInbox($connection,$site,$verifier,$integrityKeys,$this->clock);}$this->state=$state;
    }
    public function endpointKey():string {return $this->endpointKey;}
    private function tick(Deadline $deadline,int &$seen):int
    {
        $deadline->check('webhook.timeout');try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Webhook clock unavailable.','webhook.clock');}if($now<0||$now>PHP_INT_MAX-1024||$now<$seen){throw new StorageException('Invalid webhook receive clock.','webhook.clock');}$seen=$now;return $now;
    }
    private function current(Request $request,Deadline $deadline,int &$seen):?VerifiedWebhook
    {
        $this->tick($deadline,$seen);
        $proof=$this->verifier->verify($request);$now=$this->tick($deadline,$seen);if($proof!==null&&($proof->verifiedAt()>$now||($proof->expiresAt()!==null&&$proof->expiresAt()<=$now))){return null;}return $proof;
    }
    private function allowed(Message $message,Deadline $deadline,int &$seen):bool
    {
        $this->tick($deadline,$seen);
        try{$allowed=($this->association)($this->verifier->endpoint(),$message);}catch(\Throwable $error){throw new DependencyException('Webhook business association unavailable.','webhook.association_unavailable');}$this->tick($deadline,$seen);return $allowed===true;
    }
    private function mapping(VerifiedWebhook $proof,callable $mapper):?Message
    {
        try{$message=$mapper($proof);if($message!==null&&!$message instanceof Message){throw new \RuntimeException('Invalid webhook mapper result.');}}
        catch(\Throwable $error){throw new DependencyException('Webhook message mapping unavailable.','webhook.mapping_unavailable');}
        if($message===null){return null;}$protocol=$proof->endpoint()->protocol();
        if($proof->messageId()!==null&&!hash_equals($proof->messageId(),$message->id())){return null;}
        if($protocol==='github-sha256'&&!hash_equals('body:'.$proof->bodyDigest(),$message->id())){return null;}
        if($protocol==='stripe-v1'){$body=json_decode($proof->body(),true,32);if(!is_array($body)||!is_string($body['id'] ?? null)||!is_string($body['type'] ?? null)||!hash_equals($body['id'],$message->id())||!hash_equals($body['type'],$message->type())||(array_key_exists('account',$body)&&(!is_string($body['account'])||!hash_equals($proof->endpoint()->account(),$body['account'])))){return null;}}
        return $message;
    }
    private function execute(string $sql):void {if($this->pdo->exec($sql)===false){throw new StorageException('Webhook receive statement failed.','webhook.inbox_unavailable');}}
    /** Bound returned bytes without changing accepted text/BLOB representations or integer normalization. */
    private function columns():string
    {
        $limits=['endpoint_key'=>64,'event_key'=>64,'receipt_id'=>32,'event_id'=>256,'event_type'=>64,'resource_id'=>256,'descriptor'=>64,'body_digest'=>64,'created_at'=>19,'seen_at'=>19,'source_key'=>32,'source_time'=>19,'seal_key'=>32,'seal'=>64];$fields=[];
        foreach($limits as $name=>$maximum){
            $bytes=$this->driver==='sqlite'?'length(CAST('.$name.' AS BLOB))':'OCTET_LENGTH('.$name.')';
            // NULL is authentic for untimed protocols. Never turn an invalid non-NULL value into NULL.
            $null=$name==='source_time'?'WHEN '.$name.' IS NULL THEN NULL ':'';$invalid=$name==='source_time'?'-1':'NULL';
            $fields[]='CASE '.$null.'WHEN '.$bytes.'<='.$maximum.' THEN '.$name.' ELSE '.$invalid.' END AS '.$name;
        }
        return implode(',',$fields);
    }
    private function finish(\PDOStatement $query):void
    {
        try{$closed=$query->closeCursor();}catch(\Throwable $error){$closed=false;}
        if(!$closed){$this->failed=true;throw new StorageException('Webhook receive cursor cleanup failed.','webhook.inbox_cleanup');}
    }
    /** Close outside exception unwinding; a private fetch error must not enter a cleanup exception chain. */
    private function fetched(\PDOStatement $query,bool $column=false)
    {
        $failure=null;$row=false;try{$row=$column?$query->fetchColumn():$query->fetch(PDO::FETCH_ASSOC);}catch(\Throwable $error){$failure=$error;}
        $this->finish($query);if($failure!==null){throw $failure;}return $row;
    }
    private function completed(\PDOStatement $query,int $maximum):void
    {
        $valid=true;$count=0;try{$count=InboxState::integer($query->rowCount());}catch(\Throwable $error){$valid=false;}
        $this->finish($query);if(!$valid){$this->failed=true;throw new StorageException('Webhook receive write result unavailable.','webhook.inbox_unavailable');}
        if($count>$maximum){throw new StorageException('Unexpected webhook receive write result.','webhook.inbox_corrupt');}
    }
    /** Read-only admission: no mapper, business action, or unknown receipt continuation runs here. */
    private function observation(string $eventKey,Deadline $deadline):array
    {
        $unit=\SoSecurity\Support\SqlTransaction::forObservation($this->pdo,$this->clock,$this->verifier->endpoint()->ioMilliseconds());
        try{return $unit->run(function()use($unit,$eventKey):array{
            $rows=$unit->metadataRows('SELECT '.$this->columns().','.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').' AS bytes FROM '.$this->table.' WHERE endpoint_key=:endpoint AND event_key=:event LIMIT 1',['endpoint'=>$this->endpointKey,'event'=>$eventKey]);
            if(count($rows)>1){throw new StorageException('Invalid webhook receive observation.','webhook.inbox_corrupt');}$row=$rows[0]??false;$count=0;
            if($row===false){$rows=$unit->metadataRows('SELECT COUNT(*) FROM '.$this->table);if(count($rows)!==1||!isset($rows[0])||!is_array($rows[0])||count($rows[0])!==1){throw new StorageException('Invalid webhook receive capacity.','webhook.inbox_corrupt');}$count=InboxState::integer(reset($rows[0]));}
            return ['row'=>$row,'count'=>$count];
        },null,null,null,$deadline);}catch(StorageException $error){if($error->reason()==='sql.cleanup'){$this->failed=true;}throw $error;}catch(SecurityException $error){throw $error;}catch(ConfigurationException $error){throw $error;}catch(\Throwable $error){throw new StorageException('Webhook receive observation unavailable.','webhook.inbox_unavailable');}
    }
    private function read(string $eventKey,int $now,Deadline $deadline):array
    {
        $query=InboxSchema::statement($this->pdo,'SELECT '.$this->columns().','.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').' AS bytes FROM '.$this->table.' WHERE endpoint_key=:endpoint AND event_key=:event LIMIT 1'.($this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->endpointKey,'event'=>$eventKey],$deadline);return InboxState::read($this->fetched($query),$this->seals,$now);
    }
    private function same(array $row,Message $message,VerifiedWebhook $proof,string $eventKey):void
    {
        foreach(['endpoint_key'=>$this->endpointKey,'event_key'=>$eventKey,'event_id'=>$message->id(),'event_type'=>$message->type(),'resource_id'=>$message->resource(),'descriptor'=>$message->fingerprint(),'body_digest'=>$proof->bodyDigest()] as $name=>$expected){if(!hash_equals($expected,$row[$name])){throw new SecurityException('Webhook event conflicts with a previously received message.','webhook.inbox_conflict');}}
        if($row['bytes']!==strlen($proof->body())){throw new SecurityException('Webhook payload conflicts with a previously received message.','webhook.inbox_conflict');}
    }
    public function accept(Request $request,callable $mapper):?Receipt
    {
        if($this->failed){throw new StorageException('Rebuild the failed webhook receive connection.','webhook.inbox_cleanup');}
        if($this->state===null){return $this->acceptCurrent($request,$mapper);}
        $deadline=new Deadline($this->verifier->endpoint()->ioMilliseconds());$seen=0;$admitted=null;
        return $this->state->receive(function(string $expected)use($request,$mapper,$deadline,&$seen,&$admitted){
            $proof=$this->current($request,$deadline,$seen);if($proof===null){return false;}$message=$this->mapping($proof,$mapper);$this->tick($deadline,$seen);
            if($message===null||!$this->allowed($message,$deadline,$seen)){return false;}$now=$this->tick($deadline,$seen);
            if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){return false;}
            $eventKey=hash('sha256',$message->id());$view=$this->observation($eventKey,$deadline);
            $now=$this->tick($deadline,$seen);
            if($view['row']!==false){$this->same(InboxState::read($view['row'],$this->seals,$now),$message,$proof,$eventKey);}
            elseif($view['count']>=$this->state->inboxLimit()){throw new SecurityException('Webhook receive source capacity reached.','webhook.inbox_capacity');}
            if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){return false;}$admitted=$message;
            $binding=hash('sha256',json_encode(['SoSecurity.Webhook.Receive.Request.1',$this->endpointKey,$message->fingerprint(),$proof->bodyDigest(),$proof->keyId(),$expected]));
            return \SoSecurity\Account\StateOperation::webhook($this->verifier->endpoint()->scope(),$this->endpointKey,$message->fingerprint(),$binding,$this->state->binding(),$now);
        },function()use($request,$mapper,$deadline,&$seen,&$admitted){
            // The preceding admission closure sets this reference before effects can run.
            /** @var Message|null $admitted */
            $checked=function(VerifiedWebhook $proof)use($mapper,&$admitted):Message{$message=$mapper($proof);if(!$message instanceof Message||!$admitted instanceof Message||!hash_equals($admitted->fingerprint(),$message->fingerprint())){throw new SecurityException('Admitted Webhook mapping changed.','webhook.mapping_changed');}return $message;};
            return $this->acceptCurrent($request,$checked,$deadline,$seen);
        });
    }
    private function acceptCurrent(Request $request,callable $mapper,?Deadline $budget=null,int $initialSeen=0):?Receipt
    {
        \SoSecurity\Support\SqlStateAccess::assertActive($this->pdo);
        if($this->failed){throw new StorageException('Rebuild the failed webhook receive connection.','webhook.inbox_cleanup');}if($this->pdo->inTransaction()){throw new ConfigurationException('Webhook receive cannot commit a host transaction.','configuration.transaction');}
        $deadline=$budget??new Deadline($this->verifier->endpoint()->ioMilliseconds());$seen=$initialSeen;$this->tick($deadline,$seen);$proof=$this->current($request,$deadline,$seen);if($proof===null){return null;}$message=$this->mapping($proof,$mapper);$this->tick($deadline,$seen);if($message===null||!$this->allowed($message,$deadline,$seen)){return null;}
        $proof=$this->current($request,$deadline,$seen);if($proof===null){return null;}$now=$this->tick($deadline,$seen);$eventKey=hash('sha256',$message->id());$newId=bin2hex(random_bytes(16));$owned=false;$originalTimeout=null;$metadataTimeout=null;$result=null;
        try{
            \SoSecurity\Support\SqlTransactionGuard::assertIdle($this->pdo,$this->driver,$deadline);
            if($this->driver==='sqlite'){
                $originalTimeout=InboxSchema::lockTimeout($this->pdo,'PRAGMA busy_timeout',$deadline,$this->failed);$this->execute('PRAGMA busy_timeout='.min($originalTimeout,max(1,(int)ceil($deadline->remaining()*1000))));
                // PDO 7.2 does not report an exec-started SQLite transaction; track ownership and use SQL end commands.
                $this->execute('BEGIN IMMEDIATE');$owned=true;
            }else{
                $originalTimeout=InboxSchema::lockTimeout($this->pdo,'SELECT @@SESSION.innodb_lock_wait_timeout',$deadline,$this->failed);$metadataTimeout=InboxSchema::lockTimeout($this->pdo,'SELECT @@SESSION.lock_wait_timeout',$deadline,$this->failed);$this->execute('SET SESSION innodb_lock_wait_timeout='.max(1,min($originalTimeout,(int)ceil($deadline->remaining()))));
                $this->execute('SET SESSION lock_wait_timeout='.min($metadataTimeout,max(1,(int)ceil($deadline->remaining()))));
                if(!$this->pdo->beginTransaction()){throw new StorageException('Cannot begin webhook receive transaction.','webhook.inbox_unavailable');}$owned=true;
                // Hold table metadata for this transaction without first gap-locking a missing event key.
                $this->finish(InboxSchema::statement($this->pdo,'SELECT receipt_id FROM '.$this->table.' LIMIT 0',[],$deadline));
            }
            InboxSchema::verify($this->pdo,$this->driver,$deadline);$now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){return null;}
            $row=InboxState::seal(['endpoint_key'=>$this->endpointKey,'event_key'=>$eventKey,'receipt_id'=>$newId,'event_id'=>$message->id(),'event_type'=>$message->type(),'resource_id'=>$message->resource(),'descriptor'=>$message->fingerprint(),'body_digest'=>$proof->bodyDigest(),'created_at'=>$now,'seen_at'=>$now,'source_key'=>$proof->keyId(),'source_time'=>$proof->timestamp(),'bytes'=>strlen($proof->body())],$this->seals);
            $columns=['endpoint_key','event_key','receipt_id','event_id','event_type','resource_id','descriptor','body_digest','created_at','seen_at','source_key','source_time','seal_key','seal','payload'];$parameters=$row;unset($parameters['bytes']);$parameters['payload']=$proof->body();$sql=($this->driver==='sqlite'?'INSERT OR IGNORE INTO ':'INSERT INTO ').$this->table.'('.implode(',',$columns).') VALUES(:'.implode(',:',$columns).')';if($this->driver==='mysql'){$sql.=' ON DUPLICATE KEY UPDATE event_key=event_key';}$this->completed(InboxSchema::statement($this->pdo,$sql,$parameters,$deadline),2);
            $now=$this->tick($deadline,$seen);$stored=$this->read($eventKey,$now,$deadline);$this->same($stored,$message,$proof,$eventKey);
            $proof=$this->current($request,$deadline,$seen);if($proof===null||!$this->allowed($message,$deadline,$seen)){if($this->driver==='sqlite'){$this->execute('ROLLBACK');}elseif(!$this->pdo->rollBack()){throw new StorageException('Cannot roll back webhook receive.','webhook.inbox_cleanup');}$owned=false;return null;}
            $now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){return null;}$stored['seen_at']=$now;if(hash_equals($newId,$stored['receipt_id'])){$stored['source_key']=$proof->keyId();$stored['source_time']=$proof->timestamp();}$stored=InboxState::seal($stored,$this->seals);
            $this->completed(InboxSchema::statement($this->pdo,'UPDATE '.$this->table.' SET seen_at=:seen,source_key=:source_key,source_time=:source_time,seal_key=:key,seal=:seal WHERE endpoint_key=:endpoint AND event_key=:event AND receipt_id=:receipt',['seen'=>$now,'source_key'=>$stored['source_key'],'source_time'=>$stored['source_time'],'key'=>$stored['seal_key'],'seal'=>$stored['seal'],'endpoint'=>$this->endpointKey,'event'=>$eventKey,'receipt'=>$stored['receipt_id']],$deadline),1);
            $now=$this->tick($deadline,$seen);$final=$this->read($eventKey,$now,$deadline);$this->same($final,$message,$proof,$eventKey);
            $valid=$this->fetched(InboxSchema::statement($this->pdo,'SELECT 1 FROM '.$this->table.' WHERE endpoint_key=:endpoint AND event_key=:event AND receipt_id=:receipt AND '.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').'=:bytes AND payload=:payload'.($this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->endpointKey,'event'=>$eventKey,'receipt'=>$stored['receipt_id'],'bytes'=>strlen($proof->body()),'payload'=>$proof->body()],$deadline),true);
            if($valid===false||!hash_equals($final['receipt_id'],$stored['receipt_id'])||$final['seen_at']!==$stored['seen_at']){throw new StorageException('Webhook receive payload or record changed.','webhook.inbox_corrupt');}
            $proof=$this->current($request,$deadline,$seen);if($proof===null||!$this->allowed($message,$deadline,$seen)){throw new SecurityException('Webhook authority changed before receive commit.','webhook.completion_denied');}
            $now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){throw new SecurityException('Webhook expired before receive commit.','webhook.expired');}
            if($this->driver==='sqlite'){$this->execute('COMMIT');}elseif(!$this->pdo->commit()){throw new StorageException('Webhook receive commit was not confirmed.','webhook.inbox_commit');}$owned=false;
            $now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){throw new SecurityException('Webhook expired during receive commit.','webhook.expired');}
            $result=new Receipt($final['receipt_id'],$this->endpointKey,$message->id(),$proof->bodyDigest(),$final['created_at'],!hash_equals($newId,$final['receipt_id']));return $result;
        }catch(SecurityException $error){if($error instanceof StorageException&&$error->reason()==='webhook.inbox_cleanup'){$this->failed=true;}throw $error;}
        catch(ConfigurationException $error){throw $error;}
        catch(\Throwable $error){throw new StorageException('Webhook receive database unavailable.','webhook.inbox_unavailable');}
        finally{
            if($owned){try{if($this->driver==='sqlite'){$this->execute('ROLLBACK');}elseif(!$this->pdo->rollBack()){$this->failed=true;}}catch(\Throwable $error){$this->failed=true;}}
            if($metadataTimeout!==null&&!$this->failed){try{$this->execute('SET SESSION lock_wait_timeout='.$metadataTimeout);}catch(\Throwable $error){$this->failed=true;}}
            if($originalTimeout!==null&&!$this->failed){try{$this->execute(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$originalTimeout);}catch(\Throwable $error){$this->failed=true;}}
            if($this->failed){throw new StorageException('Webhook receive cleanup failed; rebuild the connection.','webhook.inbox_cleanup');}
            if($result!==null){$proof=$this->current($request,$deadline,$seen);if($proof===null||!$this->allowed($message,$deadline,$seen)){throw new SecurityException('Webhook authority changed during receive completion.','webhook.completion_denied');}$now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){throw new SecurityException('Webhook expired during receive cleanup.','webhook.expired');}}
        }
    }
    public function __debugInfo():array {return ['endpoint'=>$this->verifier->endpoint()->id(),'inbox'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild webhook receive services from trusted dependencies.','configuration.webhook_serialization');}
}
