<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;

/** Internal durable provenance. A changed payload/association cannot be made authentic by editing ordinary digests. */
final class InboxState
{
    public static function integer($value):int
    {
        if(is_int($value)&&$value>=0){return $value;}if(is_string($value)&&preg_match('/\A(?:0|[1-9][0-9]{0,18})\z/D',$value)&&(string)(int)$value===$value){return (int)$value;}throw new StorageException('Corrupt webhook receive integer.','webhook.inbox_corrupt');
    }
    public static function claims(array $row):string
    {
        return json_encode(['webhook-inbox-seal-v1',$row['endpoint_key'],$row['event_key'],$row['receipt_id'],$row['event_id'],$row['event_type'],$row['resource_id'],$row['descriptor'],$row['body_digest'],$row['created_at'],$row['seen_at'],$row['source_key'],$row['source_time'],$row['seal_key'],$row['bytes']]);
    }
    public static function seal(array $row,HmacKeys $keys):array
    {
        $row['seal_key']=$keys->currentId();$row['seal']=bin2hex($keys->sign(self::claims($row)));return $row;
    }
    public static function read($row,HmacKeys $keys,int $now):array
    {
        if(!is_array($row)){throw new StorageException('Webhook receive record missing.','webhook.inbox_corrupt');}
        $fields=['endpoint_key','event_key','receipt_id','event_id','event_type','resource_id','descriptor','body_digest','created_at','seen_at','source_key','source_time','seal_key','seal','bytes'];$actual=array_keys($row);sort($actual);sort($fields);if($fields!==$actual){throw new StorageException('Corrupt webhook receive fields.','webhook.inbox_corrupt');}
        foreach(['endpoint_key'=>64,'event_key'=>64,'receipt_id'=>32,'descriptor'=>64,'body_digest'=>64,'seal'=>64] as $name=>$length){if(!is_string($row[$name])||strlen($row[$name])!==$length||!preg_match('/\A[a-f0-9]+\z/D',$row[$name])){throw new StorageException('Corrupt webhook receive digest.','webhook.inbox_corrupt');}}
        foreach(['created_at','seen_at','bytes'] as $name){$row[$name]=self::integer($row[$name]);}
        if(!is_string($row['source_key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$row['source_key'])){throw new StorageException('Corrupt webhook source key.','webhook.inbox_corrupt');}if($row['source_time']!==null){$row['source_time']=self::integer($row['source_time']);if($row['source_time']>PHP_INT_MAX-1024||$row['source_time']>$row['created_at']+120){throw new StorageException('Corrupt signed webhook time.','webhook.inbox_corrupt');}}
        if(!is_string($row['event_id'])||!preg_match('/\A[!-~]{1,256}\z/D',$row['event_id'])||!is_string($row['event_type'])||!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$row['event_type'])||!is_string($row['resource_id'])||$row['resource_id']===''||strlen($row['resource_id'])>256||!preg_match('//u',$row['resource_id'])||preg_match('/[\x00-\x1f\x7f]/',$row['resource_id'])||!is_string($row['seal_key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$row['seal_key'])||$row['created_at']>$row['seen_at']||$row['seen_at']>PHP_INT_MAX-1024||$row['bytes']>1048576){throw new StorageException('Corrupt webhook receive metadata.','webhook.inbox_corrupt');}
        if($row['seen_at']>$now){throw new StorageException('Webhook receive clock moved backwards.','webhook.clock');}
        if(!$keys->verify($row['seal_key'],self::claims($row),hex2bin($row['seal']))){throw new StorageException('Webhook receive provenance cannot be verified.','webhook.inbox_corrupt');}
        return $row;
    }
}
