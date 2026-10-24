<?php
declare(strict_types=1);
namespace SoSecurity\Idempotency;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;

final class Schema
{
    public static function rootTypes():array {return ['namespace'=>'digest','format'=>'int','epoch'=>'digest','policy'=>'digest','entries'=>'int','history_digest'=>'digest','revision'=>'int','created_at'=>'int','observed_at'=>'int','seal_key'=>'bytes:32','seal'=>'digest'];}
    public static function recordTypes():array {return ['namespace'=>'digest','key_hash'=>'digest','format'=>'int','epoch'=>'digest','policy'=>'digest','execution_id'=>'id','fingerprint'=>'digest','status'=>'bytes:16','status_code'=>'int','response_bytes'=>'int','response_digest'=>'digest','response_body'=>'blob','created_at'=>'int','expires_at'=>'int','updated_at'=>'int','seal_key'=>'bytes:32','seal'=>'digest'];}
    public static function verify(SqlTransaction $unit):void
    {
        SqlSchema::durable($unit);
        SqlSchema::table($unit,'sosecurity_idempotency_roots',self::rootTypes(),['namespace']);
        SqlSchema::table($unit,'sosecurity_idempotency_records',self::recordTypes(),['namespace','key_hash'],[
            'sosecurity_idempotency_execution'=>['unique'=>true,'columns'=>['execution_id']],
            'sosecurity_idempotency_retention'=>['unique'=>false,'columns'=>['namespace','expires_at','key_hash']],
        ]);
    }
}
