<?php
declare(strict_types=1);
namespace SoSecurity\Outbox;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;

final class Schema
{
    public static function rootTypes():array {return ['namespace'=>'digest','format'=>'int','epoch'=>'digest','policy'=>'digest','entries'=>'int','history_digest'=>'digest','last_order'=>'int','revision'=>'int','created_at'=>'int','observed_at'=>'int','seal_key'=>'bytes:32','seal'=>'digest'];}
    public static function recordTypes():array
    {
        return ['namespace'=>'digest','key_hash'=>'digest','message_id'=>'bytes:96','format'=>'int','epoch'=>'digest','policy'=>'digest','delivery_id'=>'digest','order_no'=>'int','fingerprint'=>'digest','destination'=>'bytes:64','topic'=>'bytes:64','aggregate_id'=>'bytes:256','aggregate_hash'=>'digest','payload_bytes'=>'int','payload_digest'=>'digest','payload_present'=>'int','payload_body'=>'blob','status'=>'bytes:16','attempts'=>'int','cycle_attempts'=>'int','manual_retries'=>'int','created_at'=>'int','admit_until'=>'int','deliver_until'=>'int','available_at'=>'int','lease_until'=>'int','generation'=>'int','worker_hash'=>'digest','token_digest'=>'digest','last_error'=>'bytes:64','updated_at'=>'int','sent_at'=>'int','seal_key'=>'bytes:32','seal'=>'digest'];
    }
    public static function indexes():array
    {
        return ['sosecurity_outbox_order'=>['unique'=>true,'columns'=>['namespace','order_no']],'sosecurity_outbox_aggregate'=>['unique'=>false,'columns'=>['namespace','aggregate_hash','order_no']],'sosecurity_outbox_due'=>['unique'=>false,'columns'=>['namespace','status','available_at','order_no']]];
    }
    public static function verify(SqlTransaction $unit):void
    {
        SqlSchema::durable($unit);SqlSchema::table($unit,'sosecurity_outbox_roots',self::rootTypes(),['namespace']);SqlSchema::table($unit,'sosecurity_outbox_records',self::recordTypes(),['namespace','key_hash'],self::indexes());
    }
}
