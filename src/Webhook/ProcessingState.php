<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;

/** Internal sealed processing state. Fields and counters are checked before returning any authority. */
final class ProcessingState
{
    public static function claims(array $row):string
    {
        $values=[];foreach(self::fields() as $name){if($name!=='seal'){$values[]=$row[$name];}}return json_encode(['webhook-processing-seal-v1',$values]);
    }
    public static function fields():array {return ['endpoint_key','receipt_id','event_key','body_digest','descriptor','policy','status','attempt','total_attempts','manual_retries','revision','due_at','lease_until','claim_digest','worker_digest','error_code','created_at','updated_at','seal_key','seal'];}
    public static function seal(array $row,HmacKeys $keys):array {$row['seal_key']=$keys->currentId();$row['seal']=bin2hex($keys->sign(self::claims($row)));return $row;}
    public static function read($row,HmacKeys $keys,ProcessingPolicy $policy,int $now):array
    {
        $fields=self::fields();$actual=is_array($row)?array_keys($row):[];sort($fields);sort($actual);if($actual!==$fields){throw new StorageException('Corrupt processing fields.','webhook.processing_corrupt');}
        foreach(['endpoint_key'=>64,'receipt_id'=>32,'event_key'=>64,'body_digest'=>64,'descriptor'=>64,'policy'=>64,'seal'=>64] as $name=>$length){if(!is_string($row[$name])||strlen($row[$name])!==$length||!preg_match('/\A[a-f0-9]+\z/D',$row[$name])){throw new StorageException('Corrupt processing digest.','webhook.processing_corrupt');}}
        foreach(['attempt','total_attempts','manual_retries','revision','due_at','lease_until','created_at','updated_at'] as $name){$row[$name]=InboxState::integer($row[$name]);if($row[$name]>PHP_INT_MAX-100000){throw new StorageException('Processing counter overflow.','webhook.processing_corrupt');}}
        if(!hash_equals($row['policy'],$policy->fingerprint())||!is_string($row['seal_key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$row['seal_key'])||!is_string($row['error_code'])||($row['error_code']!==''&&!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$row['error_code']))||!in_array($row['status'],['ready','leased','retry','succeeded','dead'],true)||$row['attempt']>$policy->maximumAttempts()||$row['total_attempts']<$row['attempt']||$row['total_attempts']>100||$row['manual_retries']>$policy->maximumManualRetries()||$row['revision']<1||$row['created_at']>$row['updated_at']||$row['updated_at']>$now){throw new StorageException('Invalid processing policy, metadata or clock.','webhook.processing_corrupt');}
        foreach(['claim_digest','worker_digest'] as $name){if(!is_string($row[$name])||($row['status']==='leased'?!preg_match('/\A[a-f0-9]{64}\z/D',$row[$name]):$row[$name]!=='')){throw new StorageException('Corrupt processing ownership.','webhook.processing_corrupt');}}
        if(($row['status']==='leased'&&($row['attempt']<1||$row['due_at']!==0||$row['lease_until']<=$row['updated_at']))||($row['status']!=='leased'&&$row['lease_until']!==0)||!$keys->verify($row['seal_key'],self::claims($row),hex2bin($row['seal']))){throw new StorageException('Processing provenance cannot be verified.','webhook.processing_corrupt');}return $row;
    }
    public static function status(array $row):ProcessingStatus {return new ProcessingStatus($row['receipt_id'],$row['status'],$row['attempt'],$row['total_attempts'],$row['manual_retries'],$row['revision'],$row['due_at'],$row['lease_until'],$row['updated_at'],$row['error_code']);}
    public static function release(array $row,string $status,int $now,string $reason='',int $due=0):array {$row['status']=$status;$row['updated_at']=$now;$row['lease_until']=0;$row['claim_digest']='';$row['worker_digest']='';$row['error_code']=$reason;$row['due_at']=$due;++$row['revision'];return $row;}
}
