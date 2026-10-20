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
        foreach(\SoSecurity\Support\SqlSchema::foreignKeyChecks($driver,'sosecurity_webhook_processing') as $check){$q=$query($check['sql'],$check['parameters']);$related=$q->fetchColumn()!==false;$q->closeCursor();if($related){throw new ConfigurationException('Private security tables must not have foreign-key dependencies.','configuration.webhook_processing_schema');}}
        $integers=['attempt','total_attempts','manual_retries','revision','due_at','lease_until','created_at','updated_at'];
        $digests=['endpoint_key'=>64,'receipt_id'=>32,'event_key'=>64,'body_digest'=>64,'descriptor'=>64,'policy'=>64,'seal'=>64];$binary=['status'=>16,'claim_digest'=>64,'worker_digest'=>64,'error_code'=>64,'seal_key'=>32];
        $indexes=['sosecurity_webhook_processed_event'=>['endpoint_key','event_key'],'sosecurity_webhook_pending'=>['endpoint_key','status','due_at','receipt_id'],'sosecurity_webhook_expired'=>['endpoint_key','status','lease_until','receipt_id']];
        if($driver==='sqlite'){
            $columns=$query("PRAGMA main.table_info('sosecurity_webhook_processing')")->fetchAll(PDO::FETCH_ASSOC);$map=array_column($columns,null,'name');
            if(count($map)!==count(ProcessingState::fields())){throw new ConfigurationException('Install the explicit processing schema.','configuration.webhook_processing_schema');}
            foreach(ProcessingState::fields() as $name){if(!isset($map[$name])||strtoupper($map[$name]['type'])!==(in_array($name,$integers,true)?'INTEGER':'TEXT')||(int)$map[$name]['notnull']!==1||(int)$map[$name]['pk']!==($name==='endpoint_key'?1:($name==='receipt_id'?2:0))){throw new ConfigurationException('Incompatible processing column.','configuration.webhook_processing_schema');}}
            $indexes['sosecurity_webhook_receipt']=['endpoint_key','receipt_id','event_key'];
            foreach($indexes as $name=>$expected){$owner=$name==='sosecurity_webhook_receipt'?'sosecurity_webhook_inbox':'sosecurity_webhook_processing';$owned=array_column($query("PRAGMA main.index_list('".$owner."')")->fetchAll(PDO::FETCH_ASSOC),null,'name');if(!isset($owned[$name])||($name==='sosecurity_webhook_processed_event'&&(int)$owned[$name]['unique']!==1)||array_column($query("PRAGMA main.index_info('".$name."')")->fetchAll(PDO::FETCH_ASSOC),'name')!==$expected){throw new ConfigurationException('Processing indexes are required.','configuration.webhook_processing_schema');}}return;
        }
        $engine=$query("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_processing'")->fetchColumn();if(!is_string($engine)||strtolower($engine)!=='innodb'){throw new ConfigurationException('Processing requires InnoDB.','configuration.webhook_processing_schema');}
        $map=array_column($query("SELECT COLUMN_NAME,DATA_TYPE,COLUMN_TYPE,IS_NULLABLE,CHARACTER_MAXIMUM_LENGTH,COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_processing'")->fetchAll(PDO::FETCH_ASSOC),null,'COLUMN_NAME');
        if(count($map)!==count(ProcessingState::fields())){throw new ConfigurationException('Install the explicit processing schema.','configuration.webhook_processing_schema');}
        foreach(ProcessingState::fields() as $name){if(!isset($map[$name])||$map[$name]['IS_NULLABLE']!=='NO'){throw new ConfigurationException('Incompatible processing column.','configuration.webhook_processing_schema');}$column=$map[$name];
            if(in_array($name,$integers,true)){$valid=$column['DATA_TYPE']==='bigint'&&strpos($column['COLUMN_TYPE'],'unsigned')!==false;}
            elseif(isset($digests[$name])){$valid=$column['DATA_TYPE']==='char'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===$digests[$name]&&$column['COLLATION_NAME']==='ascii_bin';}
            else{$valid=$column['DATA_TYPE']==='varbinary'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===$binary[$name];}
            if(!$valid){throw new ConfigurationException('Incompatible processing column type.','configuration.webhook_processing_schema');}
        }
        $indexes['PRIMARY']=['endpoint_key','receipt_id'];
        foreach($indexes as $name=>$expected){$actual=$query("SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_processing' AND INDEX_NAME=:name ORDER BY SEQ_IN_INDEX",['name'=>$name])->fetchAll(PDO::FETCH_COLUMN);if($actual!==$expected){throw new ConfigurationException('Processing indexes are required.','configuration.webhook_processing_schema');}}
        $unique=$query("SELECT NON_UNIQUE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_processing' AND INDEX_NAME='sosecurity_webhook_processed_event'")->fetchAll(PDO::FETCH_COLUMN);if(count($unique)!==2||array_filter($unique,static function($value):bool{return (string)$value!=='0';})){throw new ConfigurationException('Stable event uniqueness is required.','configuration.webhook_processing_schema');}
        $actual=$query("SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_inbox' AND INDEX_NAME='sosecurity_webhook_receipt' ORDER BY SEQ_IN_INDEX")->fetchAll(PDO::FETCH_COLUMN);if($actual!==['endpoint_key','receipt_id','event_key']){throw new ConfigurationException('Receive lookup index is required.','configuration.webhook_processing_schema');}
    }
}
