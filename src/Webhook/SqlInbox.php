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
    public function __construct(PDO $connection,string $site,Verifier $verifier,HmacKeys $integrityKeys,callable $associationGuard,?Clock $clock=null)
    {
        Guard::label($site);if(!preg_match('//u',$site)){throw new ConfigurationException('Webhook receive site must be UTF-8.','configuration.webhook_inbox');}
        $driver=$connection->getAttribute(PDO::ATTR_DRIVER_NAME);if(!in_array($driver,['sqlite','mysql'],true)||(int)$connection->getAttribute(PDO::ATTR_ERRMODE)!==PDO::ERRMODE_EXCEPTION||($driver==='mysql'&&$connection->getAttribute(PDO::ATTR_EMULATE_PREPARES))){throw new ConfigurationException('Webhook receive requires exception-mode SQLite/MySQL and native MySQL prepares.','configuration.webhook_inbox');}
        $this->pdo=$connection;$this->verifier=$verifier;$this->seals=$integrityKeys;$this->association=$associationGuard;$this->clock=$clock ?? new SystemClock();$this->driver=$driver;$this->table=$driver==='sqlite'?'main.sosecurity_webhook_inbox':'sosecurity_webhook_inbox';$endpoint=$verifier->endpoint();$this->endpointKey=hash('sha256',json_encode(['webhook-inbox-v1',$site,$endpoint->scope(),$endpoint->id(),$endpoint->account(),$endpoint->protocol()]));
    }
    public function endpointKey():string {return $this->endpointKey;}
    private function tick(Deadline $deadline,int &$seen):int
    {
        $deadline->check('webhook.timeout');$now=$this->clock->now();if($now<0||$now>PHP_INT_MAX-1024||$now<$seen){throw new StorageException('Invalid webhook receive clock.','webhook.clock');}$seen=$now;return $now;
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
    private function read(string $eventKey,int $now,Deadline $deadline):array
    {
        $query=InboxSchema::statement($this->pdo,'SELECT endpoint_key,event_key,receipt_id,event_id,event_type,resource_id,descriptor,body_digest,created_at,seen_at,source_key,source_time,seal_key,seal,'.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').' AS bytes FROM '.$this->table.' WHERE endpoint_key=:endpoint AND event_key=:event'.($this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->endpointKey,'event'=>$eventKey],$deadline);return InboxState::read($query->fetch(PDO::FETCH_ASSOC),$this->seals,$now);
    }
    private function same(array $row,Message $message,VerifiedWebhook $proof,string $eventKey):void
    {
        foreach(['endpoint_key'=>$this->endpointKey,'event_key'=>$eventKey,'event_id'=>$message->id(),'event_type'=>$message->type(),'resource_id'=>$message->resource(),'descriptor'=>$message->fingerprint(),'body_digest'=>$proof->bodyDigest()] as $name=>$expected){if(!hash_equals($expected,$row[$name])){throw new SecurityException('Webhook event conflicts with a previously received message.','webhook.inbox_conflict');}}
        if($row['bytes']!==strlen($proof->body())){throw new SecurityException('Webhook payload conflicts with a previously received message.','webhook.inbox_conflict');}
    }
    public function accept(Request $request,callable $mapper):?Receipt
    {
        if($this->failed){throw new StorageException('Rebuild the failed webhook receive connection.','webhook.inbox_cleanup');}if($this->pdo->inTransaction()){throw new ConfigurationException('Webhook receive cannot commit a host transaction.','configuration.transaction');}
        $deadline=new Deadline($this->verifier->endpoint()->ioMilliseconds());$seen=0;$this->tick($deadline,$seen);$proof=$this->current($request,$deadline,$seen);if($proof===null){return null;}$message=$this->mapping($proof,$mapper);$this->tick($deadline,$seen);if($message===null||!$this->allowed($message,$deadline,$seen)){return null;}
        $proof=$this->current($request,$deadline,$seen);if($proof===null){return null;}$now=$this->tick($deadline,$seen);$eventKey=hash('sha256',$message->id());$newId=bin2hex(random_bytes(16));$owned=false;$originalTimeout=null;$result=null;
        try{
            \SoSecurity\Support\SqlTransactionGuard::assertIdle($this->pdo,$this->driver,$deadline);
            if($this->driver==='sqlite'){
                $originalTimeout=InboxState::integer(InboxSchema::statement($this->pdo,'PRAGMA busy_timeout',[],$deadline)->fetchColumn());$this->execute('PRAGMA busy_timeout='.max(1,min($originalTimeout,(int)ceil($deadline->remaining()*1000))));
                // PDO 7.2 does not report an exec-started SQLite transaction; track ownership and use SQL end commands.
                $this->execute('BEGIN IMMEDIATE');$owned=true;
            }else{
                $originalTimeout=InboxState::integer(InboxSchema::statement($this->pdo,'SELECT @@SESSION.innodb_lock_wait_timeout',[],$deadline)->fetchColumn());$this->execute('SET SESSION innodb_lock_wait_timeout='.max(1,min($originalTimeout,(int)ceil($deadline->remaining()))));
                if(!$this->pdo->beginTransaction()){throw new StorageException('Cannot begin webhook receive transaction.','webhook.inbox_unavailable');}$owned=true;
                // Hold table metadata for this transaction without first gap-locking a missing event key.
                InboxSchema::statement($this->pdo,'SELECT receipt_id FROM '.$this->table.' LIMIT 0',[],$deadline)->closeCursor();
            }
            InboxSchema::verify($this->pdo,$this->driver,$deadline);$now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){return null;}
            $row=InboxState::seal(['endpoint_key'=>$this->endpointKey,'event_key'=>$eventKey,'receipt_id'=>$newId,'event_id'=>$message->id(),'event_type'=>$message->type(),'resource_id'=>$message->resource(),'descriptor'=>$message->fingerprint(),'body_digest'=>$proof->bodyDigest(),'created_at'=>$now,'seen_at'=>$now,'source_key'=>$proof->keyId(),'source_time'=>$proof->timestamp(),'bytes'=>strlen($proof->body())],$this->seals);
            $columns=['endpoint_key','event_key','receipt_id','event_id','event_type','resource_id','descriptor','body_digest','created_at','seen_at','source_key','source_time','seal_key','seal','payload'];$parameters=$row;unset($parameters['bytes']);$parameters['payload']=$proof->body();$sql=($this->driver==='sqlite'?'INSERT OR IGNORE INTO ':'INSERT INTO ').$this->table.'('.implode(',',$columns).') VALUES(:'.implode(',:',$columns).')';if($this->driver==='mysql'){$sql.=' ON DUPLICATE KEY UPDATE event_key=event_key';}InboxSchema::statement($this->pdo,$sql,$parameters,$deadline)->closeCursor();
            $now=$this->tick($deadline,$seen);$stored=$this->read($eventKey,$now,$deadline);$this->same($stored,$message,$proof,$eventKey);
            $proof=$this->current($request,$deadline,$seen);if($proof===null||!$this->allowed($message,$deadline,$seen)){if($this->driver==='sqlite'){$this->execute('ROLLBACK');}elseif(!$this->pdo->rollBack()){throw new StorageException('Cannot roll back webhook receive.','webhook.inbox_cleanup');}$owned=false;return null;}
            $now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){return null;}$stored['seen_at']=$now;if(hash_equals($newId,$stored['receipt_id'])){$stored['source_key']=$proof->keyId();$stored['source_time']=$proof->timestamp();}$stored=InboxState::seal($stored,$this->seals);
            InboxSchema::statement($this->pdo,'UPDATE '.$this->table.' SET seen_at=:seen,source_key=:source_key,source_time=:source_time,seal_key=:key,seal=:seal WHERE endpoint_key=:endpoint AND event_key=:event AND receipt_id=:receipt',['seen'=>$now,'source_key'=>$stored['source_key'],'source_time'=>$stored['source_time'],'key'=>$stored['seal_key'],'seal'=>$stored['seal'],'endpoint'=>$this->endpointKey,'event'=>$eventKey,'receipt'=>$stored['receipt_id']],$deadline)->closeCursor();
            $now=$this->tick($deadline,$seen);$final=$this->read($eventKey,$now,$deadline);$this->same($final,$message,$proof,$eventKey);
            $valid=InboxSchema::statement($this->pdo,'SELECT 1 FROM '.$this->table.' WHERE endpoint_key=:endpoint AND event_key=:event AND receipt_id=:receipt AND '.\SoSecurity\Support\SqlSchema::blobLength($this->driver,'payload').'=:bytes AND payload=:payload'.($this->driver==='mysql'?' FOR UPDATE':''),['endpoint'=>$this->endpointKey,'event'=>$eventKey,'receipt'=>$stored['receipt_id'],'bytes'=>strlen($proof->body()),'payload'=>$proof->body()],$deadline)->fetchColumn();
            if($valid===false||!hash_equals($final['receipt_id'],$stored['receipt_id'])||$final['seen_at']!==$stored['seen_at']){throw new StorageException('Webhook receive payload or record changed.','webhook.inbox_corrupt');}
            $now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){throw new SecurityException('Webhook expired before receive commit.','webhook.expired');}
            if($this->driver==='sqlite'){$this->execute('COMMIT');}elseif(!$this->pdo->commit()){throw new StorageException('Webhook receive commit was not confirmed.','webhook.inbox_commit');}$owned=false;
            $now=$this->tick($deadline,$seen);if($proof->expiresAt()!==null&&$proof->expiresAt()<=$now){throw new SecurityException('Webhook expired during receive commit.','webhook.expired');}
            $result=new Receipt($final['receipt_id'],$this->endpointKey,$message->id(),$proof->bodyDigest(),$final['created_at'],!hash_equals($newId,$final['receipt_id']));return $result;
        }catch(SecurityException $error){throw $error;}
        catch(ConfigurationException $error){throw $error;}
        catch(\Throwable $error){throw new StorageException('Webhook receive database unavailable.','webhook.inbox_unavailable');}
        finally{
            if($owned){try{if($this->driver==='sqlite'){$this->execute('ROLLBACK');}elseif(!$this->pdo->rollBack()){$this->failed=true;}}catch(\Throwable $error){$this->failed=true;}}
            if($originalTimeout!==null&&!$this->failed){try{$this->execute(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$originalTimeout);}catch(\Throwable $error){$this->failed=true;}}
            if($this->failed){throw new StorageException('Webhook receive cleanup failed; rebuild the connection.','webhook.inbox_cleanup');}
            if($result!==null){$now=$this->tick($deadline,$seen);if($proof!==null&&$proof->expiresAt()!==null&&$proof->expiresAt()<=$now){throw new SecurityException('Webhook expired during receive cleanup.','webhook.expired');}}
        }
    }
    public function __debugInfo():array {return ['endpoint'=>$this->verifier->endpoint()->id(),'inbox'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild webhook receive services from trusted dependencies.','configuration.webhook_serialization');}
}
