<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;

/** Internal read-only schema/durability checks. Deployment installs the explicit SQL artifact. */
final class InboxSchema
{
    /** Internal fixed policy reads; cursor cleanup cannot be skipped by an expired deadline. */
    public static function lockTimeout(PDO $pdo,string $sql,Deadline $deadline,bool &$failed):int
    {
        if(!in_array($sql,['PRAGMA busy_timeout','SELECT @@SESSION.innodb_lock_wait_timeout','SELECT @@SESSION.lock_wait_timeout'],true)){throw new ConfigurationException('Use a fixed SQL lock policy query.','configuration.webhook_inbox');}
        $deadline->check('webhook.timeout');
        try{$query=$pdo->prepare($sql);}catch(\Throwable $error){throw new StorageException('Webhook SQL lock policy unavailable.','webhook.inbox_unavailable');}
        if($query===false){throw new StorageException('Webhook SQL lock policy unavailable.','webhook.inbox_unavailable');}
        try{
            $deadline->check('webhook.timeout');
            try{$executed=$query->execute();}catch(\Throwable $error){throw new StorageException('Webhook SQL lock policy unavailable.','webhook.inbox_unavailable');}
            if(!$executed){throw new StorageException('Webhook SQL lock policy unavailable.','webhook.inbox_unavailable');}
            $deadline->check('webhook.timeout');
            try{$rows=$query->fetchAll(PDO::FETCH_NUM);}catch(\Throwable $error){throw new StorageException('Webhook SQL lock policy unavailable.','webhook.inbox_unavailable');}
        }finally{
            try{$closed=$query->closeCursor();}catch(\Throwable $error){$closed=false;}
            if(!$closed){$failed=true;throw new StorageException('Webhook SQL policy cursor cleanup failed.','webhook.inbox_cleanup');}
        }
        $deadline->check('webhook.timeout');
        if(count($rows)!==1||!is_array($rows[0])||count($rows[0])!==1){throw new StorageException('Corrupt webhook SQL lock policy.','webhook.inbox_corrupt');}
        $value=InboxState::integer(reset($rows[0]));
        if(($sql!=='PRAGMA busy_timeout'&&$value<1)||($sql==='SELECT @@SESSION.lock_wait_timeout'&&$value>31536000)){throw new StorageException('Corrupt webhook SQL lock policy.','webhook.inbox_corrupt');}
        return $value;
    }
    /** Always close an unsuccessful statement, including post-execute deadline failures. */
    public static function statement(PDO $pdo,string $sql,array $parameters=[],?Deadline $deadline=null):\PDOStatement
    {
        if($deadline!==null){$deadline->check('webhook.timeout');}$statement=null;$failure=null;
        try{
            $statement=$pdo->prepare($sql);if(!$statement instanceof \PDOStatement){throw new StorageException('Cannot prepare webhook receive statement.','webhook.inbox_unavailable');}
            if($deadline!==null){$deadline->check('webhook.timeout');}
            foreach($parameters as $name=>$value){$type=$value===null?PDO::PARAM_NULL:($name==='payload'?PDO::PARAM_LOB:(is_int($value)?PDO::PARAM_INT:PDO::PARAM_STR));if(!$statement->bindValue(':'.$name,$value,$type)){throw new StorageException('Cannot bind webhook receive statement.','webhook.inbox_unavailable');}}
            if($deadline!==null){$deadline->check('webhook.timeout');}if(!$statement->execute()){throw new StorageException('Cannot execute webhook receive statement.','webhook.inbox_unavailable');}if($deadline!==null){$deadline->check('webhook.timeout');}
        }catch(\Throwable $error){$failure=$error;}
        if($failure!==null){if($statement instanceof \PDOStatement){self::close($statement);}self::unavailable($failure);}
        return $statement;
    }
    /** Internal owner completion, also used for fixed zero-row metadata locks. */
    public static function close(\PDOStatement $query):void
    {
        try{$closed=$query->closeCursor();}catch(\Throwable $error){$closed=false;}
        if(!$closed){throw new StorageException('Webhook schema cursor cleanup failed.','webhook.inbox_cleanup');}
    }
    /** @return never */
    private static function unavailable(\Throwable $error):void
    {
        if($error instanceof SecurityException||$error instanceof ConfigurationException){throw $error;}
        throw new StorageException('Webhook schema read unavailable.','webhook.inbox_unavailable');
    }
    /** Internal consumption preserves the original fetching protocol and callback opportunities. @return mixed */
    public static function read(\PDOStatement $query,string $mode='all')
    {
        $failure=null;$value=null;
        try{if($mode==='all'){$value=$query->fetchAll(PDO::FETCH_ASSOC);}elseif($mode==='column'){$value=$query->fetchColumn();}elseif($mode==='row'){$value=$query->fetch(PDO::FETCH_ASSOC);}else{throw new ConfigurationException('Use a fixed metadata fetching mode.','configuration.webhook_inbox');}}
        catch(\Throwable $error){$failure=$error;}
        self::close($query);if($failure!==null){self::unavailable($failure);}return $value;
    }
    public static function verify(PDO $pdo,string $driver,Deadline $deadline):void
    {
        $query=static function(string $sql,array $parameters=[])use($pdo,$deadline):\PDOStatement{return self::statement($pdo,$sql,$parameters,$deadline);};
        $types=['endpoint_key'=>'TEXT','event_key'=>'TEXT','receipt_id'=>'TEXT','event_id'=>'TEXT','event_type'=>'TEXT','resource_id'=>'TEXT','descriptor'=>'TEXT','body_digest'=>'TEXT','payload'=>'BLOB','created_at'=>'INTEGER','seen_at'=>'INTEGER','source_key'=>'TEXT','source_time'=>'INTEGER','seal_key'=>'TEXT','seal'=>'TEXT'];
        if($driver==='sqlite'){
            $main=null;foreach(self::read($query('PRAGMA database_list'),'all') as $row){if($row['name']==='main'){$main=$row['file'];}}
            $mode=self::read($query('PRAGMA main.journal_mode'),'column');$sync=self::read($query('PRAGMA main.synchronous'),'column');
            if(!is_string($main)||$main===''||!is_file($main)||!is_string($mode)||!in_array(strtolower($mode),['delete','truncate','persist','wal'],true)||InboxState::integer($sync)<2){throw new ConfigurationException('Webhook receive needs a persistent SQLite file, journaling and FULL/EXTRA synchronization.','configuration.webhook_inbox_durability');}
            $columns=self::metadata($pdo,$driver,$deadline,'sosecurity_webhook_inbox','configuration.webhook_inbox_schema');$map=array_column($columns,null,'name');if(count($map)!==count($types)){throw new ConfigurationException('Install the explicit webhook receive schema.','configuration.webhook_inbox_schema');}
            foreach($types as $name=>$type){if(!isset($map[$name])||strtoupper($map[$name]['type'])!==$type||(int)$map[$name]['notnull']!==($name==='source_time'?0:1)||(int)$map[$name]['pk']!==($name==='endpoint_key'?1:($name==='event_key'?2:0))){throw new ConfigurationException('Webhook receive schema differs from the contract.','configuration.webhook_inbox_schema');}}
            self::index($pdo,$driver,$deadline,'sosecurity_webhook_inbox','sosecurity_webhook_retention',['endpoint_key','created_at','event_key'],false,'configuration.webhook_inbox_schema');return;
        }
        $engine=self::read($query("SELECT CASE WHEN OCTET_LENGTH(ENGINE)<=32 THEN ENGINE ELSE NULL END AS ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_webhook_inbox'"),'column');
        if(!is_string($engine)||strtolower($engine)!=='innodb'||(string)self::read($query('SELECT @@GLOBAL.innodb_flush_log_at_trx_commit'),'column')!=='1'){throw new ConfigurationException('Webhook receive requires InnoDB with durable commit flushing.','configuration.webhook_inbox_durability');}
        $columns=self::metadata($pdo,$driver,$deadline,'sosecurity_webhook_inbox','configuration.webhook_inbox_schema');$map=array_column($columns,null,'COLUMN_NAME');if(count($map)!==count($types)){throw new ConfigurationException('Install the explicit webhook receive schema.','configuration.webhook_inbox_schema');}
        foreach($types as $name=>$unused){
            if(!isset($map[$name])||$map[$name]['IS_NULLABLE']!==($name==='source_time'?'YES':'NO')){throw new ConfigurationException('Incompatible webhook receive columns.','configuration.webhook_inbox_schema');}$column=$map[$name];
            if(in_array($name,['created_at','seen_at','source_time'],true)){$valid=$column['DATA_TYPE']==='bigint'&&strpos($column['COLUMN_TYPE'],'unsigned')!==false;}
            elseif($name==='payload'){$valid=$column['DATA_TYPE']==='mediumblob';}
            elseif(in_array($name,['event_id','event_type','resource_id','seal_key','source_key'],true)){$valid=$column['DATA_TYPE']==='varbinary'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===(in_array($name,['seal_key','source_key'],true)?32:($name==='event_type'?64:256));}
            else{$valid=$column['DATA_TYPE']==='char'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===($name==='receipt_id'?32:64)&&$column['COLLATION_NAME']==='ascii_bin';}
            if(!$valid){throw new ConfigurationException('Incompatible webhook receive column type.','configuration.webhook_inbox_schema');}
        }
        foreach(['PRIMARY'=>['endpoint_key','event_key'],'sosecurity_webhook_retention'=>['endpoint_key','created_at','event_key']] as $index=>$expected){self::index($pdo,$driver,$deadline,'sosecurity_webhook_inbox',$index,$expected,$index==='PRIMARY','configuration.webhook_inbox_schema');}
    }
    /** Internal bounded metadata shared by the two fixed Webhook tables. */
    public static function metadata(PDO $pdo,string $driver,Deadline $deadline,string $table,string $reason):array
    {
        if(!in_array($table,['sosecurity_webhook_inbox','sosecurity_webhook_processing'],true)||!in_array($driver,['sqlite','mysql'],true)){throw new ConfigurationException('Use a fixed Webhook schema.',$reason);}
        $query=static function(string $sql,array $args=[])use($pdo,$deadline):\PDOStatement{return self::statement($pdo,$sql,$args,$deadline);};
        foreach(\SoSecurity\Support\SqlSchema::foreignKeyChecks($driver,$table) as $check){$q=$query($check['sql'],$check['parameters']);$found=self::read($q,'column')!==false;if($found){throw new ConfigurationException('Private Webhook tables must not have foreign-key dependencies.',$reason);}}
        if($driver==='sqlite'){
            foreach(['main','temp'] as $scope){
                if(self::read($query("SELECT 1 FROM ".$scope.".sqlite_master WHERE name COLLATE NOCASE IN ('pragma_table_info','pragma_index_list','pragma_index_info') OR (type='trigger' AND tbl_name COLLATE NOCASE=:table) LIMIT 1",['table'=>$table]),'column')!==false){throw new ConfigurationException('Webhook metadata modules must not be shadowed and tables must not have triggers.',$reason);}
            }
            $rows=self::read($query('SELECT CASE WHEN length(CAST(name AS BLOB))<=64 THEN name ELSE NULL END AS name,CASE WHEN length(CAST(type AS BLOB))<=128 THEN type ELSE NULL END AS type,"notnull",pk FROM main.pragma_table_info(:table,\'main\') ORDER BY cid LIMIT 65',['table'=>$table]),'all');
            foreach($rows as $row){if(!is_string($row['name'])||!is_string($row['type'])){throw new ConfigurationException('Webhook column metadata exceeds its bound.',$reason);}}
        }else{
            // An empty TRIGGERS result is not evidence when MySQL filters metadata by privilege.
            // Read grant evidence and trigger presence in one statement: table privileges can change between queries.
            // Prove a direct current-account grant on this table/schema, or an unrestricted global grant.
            $identity=self::read($query('SELECT CASE WHEN OCTET_LENGTH(CURRENT_USER())<=288 THEN CURRENT_USER() ELSE NULL END'),'column');
            if(!is_string($identity)||!preg_match('/\A([A-Za-z0-9_.-]{1,32})@([A-Za-z0-9_.:%\/-]{1,255})\z/D',$identity,$match)){throw new ConfigurationException('Cannot prove Webhook metadata visibility.',$reason);}
            $grantee="'".$match[1]."'@'".$match[2]."'";
            $visible=self::read($query("SELECT (EXISTS(SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE BINARY GRANTEE=:schema_grantee AND BINARY TABLE_SCHEMA=BINARY DATABASE() AND PRIVILEGE_TYPE='TRIGGER') OR EXISTS(SELECT 1 FROM information_schema.TABLE_PRIVILEGES WHERE BINARY GRANTEE=:table_grantee AND BINARY TABLE_SCHEMA=BINARY DATABASE() AND BINARY TABLE_NAME=:table AND PRIVILEGE_TYPE='TRIGGER')) AS scoped,EXISTS(SELECT 1 FROM information_schema.USER_PRIVILEGES WHERE BINARY GRANTEE=:global_grantee AND PRIVILEGE_TYPE='TRIGGER') AS unrestricted,EXISTS(SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE=:trigger_table) AS has_trigger",['schema_grantee'=>$grantee,'table_grantee'=>$grantee,'global_grantee'=>$grantee,'table'=>$table,'trigger_table'=>$table]),'row');
            if(!is_array($visible)||((string)$visible['scoped']!=='1'&&((string)$visible['unrestricted']!=='1'||(string)self::read($query('SELECT @@GLOBAL.partial_revokes'),'column')!=='0'))){throw new ConfigurationException('Direct Webhook trigger metadata visibility is required.',$reason);}
            if((string)$visible['has_trigger']!=='0'){throw new ConfigurationException('Private Webhook tables must not have triggers.',$reason);}
            $rows=self::read($query('SELECT CASE WHEN OCTET_LENGTH(COLUMN_NAME)<=64 THEN COLUMN_NAME ELSE NULL END AS COLUMN_NAME,CASE WHEN OCTET_LENGTH(DATA_TYPE)<=64 THEN DATA_TYPE ELSE NULL END AS DATA_TYPE,CASE WHEN OCTET_LENGTH(COLUMN_TYPE)<=128 THEN COLUMN_TYPE ELSE NULL END AS COLUMN_TYPE,IS_NULLABLE,CHARACTER_MAXIMUM_LENGTH,CASE WHEN OCTET_LENGTH(COLLATION_NAME)<=128 THEN COLLATION_NAME ELSE NULL END AS COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table ORDER BY ORDINAL_POSITION LIMIT 65',['table'=>$table]),'all');
            foreach($rows as $row){if(!is_string($row['COLUMN_NAME'])||!is_string($row['DATA_TYPE'])||!is_string($row['COLUMN_TYPE'])){throw new ConfigurationException('Webhook column metadata exceeds its bound.',$reason);}}
        }
        if(count($rows)>64){throw new ConfigurationException('Webhook column count exceeds its bound.',$reason);}return $rows;
    }
    /** Internal exact required index: ownership, full columns, uniqueness and non-partial coverage. */
    public static function index(PDO $pdo,string $driver,Deadline $deadline,string $table,string $name,array $expected,bool $unique,string $reason):void
    {
        if(!in_array($table,['sosecurity_webhook_inbox','sosecurity_webhook_processing'],true)||!in_array($driver,['sqlite','mysql'],true)||strlen($name)>256||count($expected)<1||count($expected)>4){throw new ConfigurationException('Use a fixed Webhook index.',$reason);}
        $query=static function(string $sql,array $args=[])use($pdo,$deadline):\PDOStatement{return self::statement($pdo,$sql,$args,$deadline);};
        if($driver==='sqlite'){
            $rows=self::read($query('SELECT CASE WHEN length(CAST(name AS BLOB))<=256 THEN name ELSE NULL END AS name,"unique",partial FROM main.pragma_index_list(:table,\'main\') LIMIT 129',['table'=>$table]),'all');
            if(count($rows)>128){throw new ConfigurationException('Webhook index count exceeds its bound.',$reason);}
            foreach($rows as $row){if(!is_string($row['name'])){throw new ConfigurationException('Webhook index name exceeds its bound.',$reason);}}
            $owned=array_column($rows,null,'name');
            if(!isset($owned[$name])||(int)$owned[$name]['unique']!==($unique?1:0)||(int)$owned[$name]['partial']!==0){throw new ConfigurationException('Webhook index coverage differs from its contract.',$reason);}
            $rows=self::read($query('SELECT CASE WHEN length(CAST(name AS BLOB))<=64 THEN name ELSE NULL END AS name FROM main.pragma_index_info(:name,\'main\') ORDER BY seqno LIMIT 5',['name'=>$name]),'all');
            if(array_column($rows,'name')!==$expected){throw new ConfigurationException('Webhook index columns differ from their contract.',$reason);}return;
        }
        $rows=self::read($query('SELECT CASE WHEN OCTET_LENGTH(COLUMN_NAME)<=64 THEN COLUMN_NAME ELSE NULL END AS name,NON_UNIQUE,SUB_PART,CASE WHEN OCTET_LENGTH(INDEX_TYPE)<=16 THEN INDEX_TYPE ELSE NULL END AS INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table AND INDEX_NAME=:name ORDER BY SEQ_IN_INDEX LIMIT 5',['table'=>$table,'name'=>$name]),'all');
        if(array_column($rows,'name')!==$expected){throw new ConfigurationException('Webhook index columns differ from their contract.',$reason);}
        foreach($rows as $row){if((string)$row['NON_UNIQUE']!==($unique?'0':'1')||$row['SUB_PART']!==null||$row['INDEX_TYPE']!=='BTREE'){throw new ConfigurationException('Webhook index coverage differs from its contract.',$reason);}}
    }
}
