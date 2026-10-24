<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use PDO;
use SoSecurity\Support\Deadline;
use SoSecurity\Exception\ConfigurationException;

/** Internal schema checks. No runtime DDL, durability weakening or automatic schema repair. */
final class ProcessingSchema
{
    public static function verify(PDO $pdo,string $driver,Deadline $deadline):void
    {
        InboxSchema::verify($pdo,$driver,$deadline);
        $query=static function(string $sql,array $args=[])use($pdo,$deadline):\PDOStatement{return InboxSchema::statement($pdo,$sql,$args,$deadline);};
        $integers=['attempt','total_attempts','manual_retries','revision','due_at','lease_until','created_at','updated_at'];
        $digests=['endpoint_key'=>64,'receipt_id'=>32,'event_key'=>64,'body_digest'=>64,'descriptor'=>64,'policy'=>64,'seal'=>64];$binary=['status'=>16,'claim_digest'=>64,'worker_digest'=>64,'error_code'=>64,'seal_key'=>32];
        $indexes=['sosecurity_webhook_processed_event'=>['endpoint_key','event_key'],'sosecurity_webhook_pending'=>['endpoint_key','status','due_at','receipt_id'],'sosecurity_webhook_expired'=>['endpoint_key','status','lease_until','receipt_id']];
        if($driver==='sqlite'){
            $columns=InboxSchema::metadata($pdo,$driver,$deadline,'sosecurity_webhook_processing','configuration.webhook_processing_schema');$map=array_column($columns,null,'name');
            if(count($map)!==count(ProcessingState::fields())){throw new ConfigurationException('Install the explicit processing schema.','configuration.webhook_processing_schema');}
            foreach(ProcessingState::fields() as $name){if(!isset($map[$name])||strtoupper($map[$name]['type'])!==(in_array($name,$integers,true)?'INTEGER':'TEXT')||(int)$map[$name]['notnull']!==1||(int)$map[$name]['pk']!==($name==='endpoint_key'?1:($name==='receipt_id'?2:0))){throw new ConfigurationException('Incompatible processing column.','configuration.webhook_processing_schema');}}
            $indexes['sosecurity_webhook_receipt']=['endpoint_key','receipt_id','event_key'];
            foreach($indexes as $name=>$expected){$owner=$name==='sosecurity_webhook_receipt'?'sosecurity_webhook_inbox':'sosecurity_webhook_processing';InboxSchema::index($pdo,$driver,$deadline,$owner,$name,$expected,$name==='sosecurity_webhook_processed_event','configuration.webhook_processing_schema');}return;
        }
        $engine=InboxSchema::read($query("SELECT CASE WHEN OCTET_LENGTH(ENGINE)<=32 THEN ENGINE ELSE NULL END AS ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_processing'"),'column');if(!is_string($engine)||strtolower($engine)!=='innodb'){throw new ConfigurationException('Processing requires InnoDB.','configuration.webhook_processing_schema');}
        $map=array_column(InboxSchema::metadata($pdo,$driver,$deadline,'sosecurity_webhook_processing','configuration.webhook_processing_schema'),null,'COLUMN_NAME');
        if(count($map)!==count(ProcessingState::fields())){throw new ConfigurationException('Install the explicit processing schema.','configuration.webhook_processing_schema');}
        foreach(ProcessingState::fields() as $name){if(!isset($map[$name])||$map[$name]['IS_NULLABLE']!=='NO'){throw new ConfigurationException('Incompatible processing column.','configuration.webhook_processing_schema');}$column=$map[$name];
            if(in_array($name,$integers,true)){$valid=$column['DATA_TYPE']==='bigint'&&strpos($column['COLUMN_TYPE'],'unsigned')!==false;}
            elseif(isset($digests[$name])){$valid=$column['DATA_TYPE']==='char'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===$digests[$name]&&$column['COLLATION_NAME']==='ascii_bin';}
            else{$valid=$column['DATA_TYPE']==='varbinary'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===$binary[$name];}
            if(!$valid){throw new ConfigurationException('Incompatible processing column type.','configuration.webhook_processing_schema');}
        }
        $indexes['PRIMARY']=['endpoint_key','receipt_id'];
        foreach($indexes as $name=>$expected){InboxSchema::index($pdo,$driver,$deadline,'sosecurity_webhook_processing',$name,$expected,in_array($name,['PRIMARY','sosecurity_webhook_processed_event'],true),'configuration.webhook_processing_schema');}
        InboxSchema::index($pdo,$driver,$deadline,'sosecurity_webhook_inbox','sosecurity_webhook_receipt',['endpoint_key','receipt_id','event_key'],false,'configuration.webhook_processing_schema');
    }
}
