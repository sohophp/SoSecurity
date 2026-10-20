<?php
declare(strict_types=1);
namespace SoSecurity\Outbox;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlSchema;

/** Internal signed metadata. Root history binds every row seal, including state hidden by candidate predicates. */
final class State
{
    public static function group(string $scope,string $producer):void
    {
        foreach([$scope,$producer] as $label){Guard::label($label);if(!preg_match('//u',$label)){throw new ConfigurationException('Use UTF-8 server identities.','configuration.outbox');}}
    }
    public static function actor(string $actor):void {Guard::label($actor);if(!preg_match('//u',$actor)){throw new ConfigurationException('Use a UTF-8 server identity.','configuration.outbox');}}
    public static function idTime(string $id):int
    {
        if(!preg_match('/\Ao1\.((?:0|[1-9][0-9]{0,18}))\.[a-f0-9]{64}\z/D',$id,$parts)||(string)(int)$parts[1]!==$parts[1]||(int)$parts[1]>PHP_INT_MAX-31536001){throw new ValidationException('Use a canonical timestamp-bound event ID.','outbox.message');}return (int)$parts[1];
    }
    public static function namespace(string $site,string $scope,string $producer):string {self::group($scope,$producer);return hash('sha256',json_encode(['outbox-v1',$site,$scope,$producer]));}
    public static function delivery(string $namespace,string $id):string {return hash('sha256','SoSecurity.Outbox.Delivery.1.'.$namespace.'.'.$id);}
    public static function aggregate(string $aggregate):string {return hash('sha256','SoSecurity.Outbox.Aggregate.1.'.$aggregate);}
    public static function fingerprint(string $scope,string $producer,string $id,string $destination,string $topic,string $aggregate,int $bytes,string $digest):string {return hash('sha256','SoSecurity.Outbox.Message.1.'.json_encode([$scope,$producer,$id,$destination,$topic,$aggregate,$bytes,$digest]));}
    public static function rootFields():array {return ['namespace','format','epoch','policy','entries','history_digest','last_order','revision','created_at','observed_at','seal_key','seal'];}
    public static function recordFields():array {return ['namespace','key_hash','message_id','format','epoch','policy','delivery_id','order_no','fingerprint','destination','topic','aggregate_id','aggregate_hash','payload_bytes','payload_digest','payload_present','status','attempts','cycle_attempts','manual_retries','created_at','admit_until','deliver_until','available_at','lease_until','generation','worker_hash','token_digest','last_error','updated_at','sent_at','seal_key','seal'];}
    public static function historyPrefix(string $namespace):string {return 'SoSecurity.Outbox.History.1.'.$namespace;}
    private static function encoded(array $row,bool $root):string
    {
        $values=[];foreach($root?self::rootFields():self::recordFields() as $field){if($field!=='seal'){$values[$field]=$row[$field];}}return ($root?'SoSecurity.Outbox.Root.1.':'SoSecurity.Outbox.Record.1.').json_encode($values);
    }
    public static function seal(array $row,HmacKeys $keys,bool $root):array {$row['seal_key']=$keys->currentId();$row['seal']=bin2hex($keys->sign(self::encoded($row,$root)));return $row;}
    /** @return never */
    private static function bad():void {throw new StorageException('Outbox state is invalid or cannot be authenticated.','outbox.corrupt');}
    private static function read(array $row,HmacKeys $keys,bool $root):array
    {
        $fields=$root?self::rootFields():self::recordFields();$extra=$root?[]:['body_length'];
        if(count($row)!==count($fields)+count($extra)||array_diff(array_keys($row),array_merge($fields,$extra))){self::bad();}
        foreach($root?['format','entries','last_order','revision','created_at','observed_at']:['format','order_no','payload_bytes','payload_present','attempts','cycle_attempts','manual_retries','created_at','admit_until','deliver_until','available_at','lease_until','generation','updated_at','sent_at','body_length'] as $field){$row[$field]=SqlSchema::integer($row[$field]);}
        foreach($root?['namespace','epoch','policy','history_digest','seal']:['namespace','key_hash','epoch','policy','delivery_id','fingerprint','aggregate_hash','payload_digest','worker_hash','token_digest','seal'] as $field){if(!is_string($row[$field])||!preg_match('/\A[a-f0-9]{64}\z/D',$row[$field])){self::bad();}}
        if(!in_array($row['format'],[1,2],true)||!is_string($row['seal_key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$row['seal_key'])||!$keys->verify($row['seal_key'],self::encoded($row,$root),hex2bin($row['seal']))){self::bad();}return $row;
    }
    public static function root(array $raw,HmacKeys $keys,Policy $policy,string $namespace,string $epoch,int $now):array
    {
        $row=self::read($raw,$keys,true);
        if($row['namespace']!==$namespace||$row['epoch']!==$epoch||$row['policy']!==$policy->fingerprint()){throw new ConfigurationException('Reconcile outbox identity, epoch and policy changes explicitly.','configuration.outbox_state');}
        if($row['entries']>$policy->maximumEntries()||$row['last_order']<$row['entries']||$row['last_order']>=PHP_INT_MAX||$row['revision']<1||$row['revision']>=PHP_INT_MAX||$row['created_at']>$row['observed_at']){self::bad();}
        if($row['observed_at']>$now){throw new StorageException('Outbox clock moved backwards.','outbox.clock');}return $row;
    }
    public static function record(array $raw,HmacKeys $keys,Policy $policy,string $namespace,string $epoch,string $scope,string $producer,int $now):array
    {
        $row=self::read($raw,$keys,false);
        if($row['namespace']!==$namespace||$row['epoch']!==$epoch||$row['policy']!==$policy->fingerprint()){throw new ConfigurationException('Outbox record identity/policy changed.','configuration.outbox_state');}
        foreach(['message_id','destination','topic','aggregate_id','status','last_error'] as $field){if(!is_string($row[$field])){self::bad();}}
        try{$created=self::idTime($row['message_id']);Guard::label($row['aggregate_id']);}catch(\Throwable $error){self::bad();}
        foreach(['destination','topic'] as $field){if(!preg_match('/\A[a-z][a-z0-9_.:-]{0,63}\z/D',$row[$field])){self::bad();}}
        if(!preg_match('//u',$row['aggregate_id'])||!in_array($row['status'],['pending','leased','sent','dead','resolved'],true)||($row['last_error']!==''&&!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$row['last_error']))){self::bad();}
        if(($row['status']==='resolved')!==($row['format']===2)){self::bad();}
        if($row['status']==='resolved'&&($row['payload_present']!==0||$row['updated_at']<$row['created_at']+$policy->recoveryAge()||!in_array($row['last_error'],['reconcile.received','reconcile.cancelled'],true))){self::bad();}
        if($created!==$row['created_at']||$row['created_at']>PHP_INT_MAX-$policy->recoveryAge()||$row['admit_until']!==$row['created_at']+$policy->messageAge()||$row['deliver_until']<$row['admit_until']||$row['deliver_until']>$row['created_at']+$policy->recoveryAge()||$row['updated_at']<$row['created_at']||$row['updated_at']>$now||$row['available_at']<$row['created_at']||$row['lease_until']>$row['deliver_until']||$row['order_no']<1||$row['order_no']>=PHP_INT_MAX||$row['attempts']>100||$row['generation']!==$row['attempts']||$row['cycle_attempts']>$row['attempts']||$row['cycle_attempts']>$policy->maximumAttempts()||$row['manual_retries']>$policy->maximumManualRetries()){self::bad();}
        if($row['key_hash']!==hash('sha256',$row['message_id'])||$row['delivery_id']!==self::delivery($namespace,$row['message_id'])||$row['aggregate_hash']!==self::aggregate($row['aggregate_id'])||$row['fingerprint']!==self::fingerprint($scope,$producer,$row['message_id'],$row['destination'],$row['topic'],$row['aggregate_id'],$row['payload_bytes'],$row['payload_digest'])){self::bad();}
        if(!in_array($row['payload_present'],[0,1],true)||$row['payload_bytes']>$policy->maximumPayloadBytes()||$row['body_length']!==($row['payload_present']===1?$row['payload_bytes']:0)){self::bad();}
        if($row['status']==='leased'){
            if($row['attempts']<1||$row['cycle_attempts']<1||$row['lease_until']<=$row['updated_at']||$row['payload_present']!==1){self::bad();}
        }elseif($row['lease_until']!==0){self::bad();}
        if($row['status']==='sent'){
            if($row['attempts']<1||$row['sent_at']<$row['created_at']||$row['sent_at']>$row['updated_at']||$row['payload_present']!==0){self::bad();}
        }elseif($row['sent_at']!==0){self::bad();}
        if($row['payload_present']===0&&$row['status']!=='sent'&&(!in_array($row['status'],['dead','resolved'],true)||$row['updated_at']<$row['created_at']+$policy->recoveryAge())){self::bad();}
        if($row['attempts']===0&&($row['cycle_attempts']!==0||$row['generation']!==0||$row['worker_hash']!==str_repeat('0',64)||($row['status']!=='resolved'&&$row['token_digest']!==str_repeat('0',64)))){self::bad();}
        return $row;
    }
    public static function status(array $row):Status
    {
        return new Status(['id'=>$row['message_id'],'delivery_id'=>$row['delivery_id'],'order'=>$row['order_no'],'state'=>$row['status'],'destination'=>$row['destination'],'topic'=>$row['topic'],'aggregate'=>$row['aggregate_id'],'attempts'=>$row['attempts'],'manual_retries'=>$row['manual_retries'],'available_at'=>$row['available_at'],'lease_until'=>$row['lease_until'],'deliver_until'=>$row['deliver_until'],'sent_at'=>$row['sent_at'],'last_error'=>$row['last_error']]);
    }
}
