<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;

/** Internal read-only schema/durability checks. Deployment installs the explicit SQL artifact. */
final class InboxSchema
{
    public static function statement(PDO $pdo,string $sql,array $parameters=[],?Deadline $deadline=null):\PDOStatement
    {
        if($deadline!==null){$deadline->check('webhook.timeout');}
        $statement=$pdo->prepare($sql);if($statement===false){throw new StorageException('Cannot prepare webhook receive statement.','webhook.inbox_unavailable');}
        if($deadline!==null){$deadline->check('webhook.timeout');}
        foreach($parameters as $name=>$value){$type=$value===null?PDO::PARAM_NULL:($name==='payload'?PDO::PARAM_LOB:(is_int($value)?PDO::PARAM_INT:PDO::PARAM_STR));if(!$statement->bindValue(':'.$name,$value,$type)){throw new StorageException('Cannot bind webhook receive statement.','webhook.inbox_unavailable');}}
        if($deadline!==null){$deadline->check('webhook.timeout');}if(!$statement->execute()){throw new StorageException('Cannot execute webhook receive statement.','webhook.inbox_unavailable');}if($deadline!==null){$deadline->check('webhook.timeout');}return $statement;
    }
    public static function verify(PDO $pdo,string $driver,Deadline $deadline):void
    {
        $query=static function(string $sql,array $parameters=[])use($pdo,$deadline):\PDOStatement{return self::statement($pdo,$sql,$parameters,$deadline);};
        foreach(\SoSecurity\Support\SqlSchema::foreignKeyChecks($driver,'sosecurity_webhook_inbox') as $check){$q=$query($check['sql'],$check['parameters']);$related=$q->fetchColumn()!==false;$q->closeCursor();if($related){throw new ConfigurationException('Private security tables must not have foreign-key dependencies.','configuration.webhook_inbox_schema');}}
        $types=['endpoint_key'=>'TEXT','event_key'=>'TEXT','receipt_id'=>'TEXT','event_id'=>'TEXT','event_type'=>'TEXT','resource_id'=>'TEXT','descriptor'=>'TEXT','body_digest'=>'TEXT','payload'=>'BLOB','created_at'=>'INTEGER','seen_at'=>'INTEGER','source_key'=>'TEXT','source_time'=>'INTEGER','seal_key'=>'TEXT','seal'=>'TEXT'];
        if($driver==='sqlite'){
            $main=null;foreach($query('PRAGMA database_list')->fetchAll(PDO::FETCH_ASSOC) as $row){if($row['name']==='main'){$main=$row['file'];}}
            $mode=$query('PRAGMA main.journal_mode')->fetchColumn();$sync=$query('PRAGMA main.synchronous')->fetchColumn();
            if(!is_string($main)||$main===''||!is_file($main)||!is_string($mode)||!in_array(strtolower($mode),['delete','truncate','persist','wal'],true)||InboxState::integer($sync)<2){throw new ConfigurationException('Webhook receive needs a persistent SQLite file, journaling and FULL/EXTRA synchronization.','configuration.webhook_inbox_durability');}
            $columns=$query("PRAGMA main.table_info('sosecurity_webhook_inbox')")->fetchAll(PDO::FETCH_ASSOC);$map=array_column($columns,null,'name');if(count($map)!==count($types)){throw new ConfigurationException('Install the explicit webhook receive schema.','configuration.webhook_inbox_schema');}
            foreach($types as $name=>$type){if(!isset($map[$name])||strtoupper($map[$name]['type'])!==$type||(int)$map[$name]['notnull']!==($name==='source_time'?0:1)||(int)$map[$name]['pk']!==($name==='endpoint_key'?1:($name==='event_key'?2:0))){throw new ConfigurationException('Webhook receive schema differs from the contract.','configuration.webhook_inbox_schema');}}
            $index=$query("PRAGMA main.index_info('sosecurity_webhook_retention')")->fetchAll(PDO::FETCH_ASSOC);if(array_column($index,'name')!==['endpoint_key','created_at','event_key']){throw new ConfigurationException('Webhook receive retention index is required.','configuration.webhook_inbox_schema');}return;
        }
        $engine=$query("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_inbox'")->fetchColumn();
        if(!is_string($engine)||strtolower($engine)!=='innodb'||(string)$query('SELECT @@GLOBAL.innodb_flush_log_at_trx_commit')->fetchColumn()!=='1'){throw new ConfigurationException('Webhook receive requires InnoDB with durable commit flushing.','configuration.webhook_inbox_durability');}
        $columns=$query("SELECT COLUMN_NAME,DATA_TYPE,COLUMN_TYPE,IS_NULLABLE,CHARACTER_MAXIMUM_LENGTH,COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_inbox'")->fetchAll(PDO::FETCH_ASSOC);$map=array_column($columns,null,'COLUMN_NAME');if(count($map)!==count($types)){throw new ConfigurationException('Install the explicit webhook receive schema.','configuration.webhook_inbox_schema');}
        foreach($types as $name=>$unused){
            if(!isset($map[$name])||$map[$name]['IS_NULLABLE']!==($name==='source_time'?'YES':'NO')){throw new ConfigurationException('Incompatible webhook receive columns.','configuration.webhook_inbox_schema');}$column=$map[$name];
            if(in_array($name,['created_at','seen_at','source_time'],true)){$valid=$column['DATA_TYPE']==='bigint'&&strpos($column['COLUMN_TYPE'],'unsigned')!==false;}
            elseif($name==='payload'){$valid=$column['DATA_TYPE']==='mediumblob';}
            elseif(in_array($name,['event_id','event_type','resource_id','seal_key','source_key'],true)){$valid=$column['DATA_TYPE']==='varbinary'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===(in_array($name,['seal_key','source_key'],true)?32:($name==='event_type'?64:256));}
            else{$valid=$column['DATA_TYPE']==='char'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===($name==='receipt_id'?32:64)&&$column['COLLATION_NAME']==='ascii_bin';}
            if(!$valid){throw new ConfigurationException('Incompatible webhook receive column type.','configuration.webhook_inbox_schema');}
        }
        foreach(['PRIMARY'=>['endpoint_key','event_key'],'sosecurity_webhook_retention'=>['endpoint_key','created_at','event_key']] as $index=>$expected){$actual=$query("SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_inbox' AND INDEX_NAME=:index ORDER BY SEQ_IN_INDEX",['index'=>$index])->fetchAll(PDO::FETCH_COLUMN);if($actual!==$expected){throw new ConfigurationException('Incompatible webhook receive index.','configuration.webhook_inbox_schema');}}
    }
}
