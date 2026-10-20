<?php
declare(strict_types=1);
namespace SoSecurity\Support;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

/** Internal read-only deployment contract. No migrations or session/durability changes. */
final class SqlSchema
{
    /** SQL-side guard for binary payload columns. SQLite affinity alone does not prohibit TEXT, including NUL prefixes. */
    public static function blobLength(string $driver,string $column):string
    {
        if(!in_array($driver,['sqlite','mysql'],true)||!preg_match('/\A[a-z][a-z_]*\z/D',$column)){throw new ConfigurationException('Use a fixed binary SQL column.','configuration.sql_schema');}
        return $driver==='sqlite'?"CASE WHEN typeof(".$column.")='blob' THEN length(".$column.") ELSE -1 END":'length('.$column.')';
    }
    /** Bounded metadata projection: malformed/oversized fields become NULL, which strict state readers reject. */
    public static function boundedProjection(string $driver,array $types):string
    {
        if(!in_array($driver,['sqlite','mysql'],true)||count($types)<1||count($types)>64){throw new ConfigurationException('Use bounded internal SQL metadata.','configuration.sql_schema');}
        $fields=[];
        foreach($types as $name=>$type){
            if(!is_string($name)||!preg_match('/\A[a-z][a-z_]*\z/D',$name)){throw new ConfigurationException('Use fixed SQL metadata columns.','configuration.sql_schema');}
            if($type==='int'){$predicate=$driver==='sqlite'?"typeof(".$name.")='integer' AND ".$name.'>=0':$name.'>=0 AND '.$name.'<=9223372036854775807';}
            else{
                $limit=$type==='digest'?64:($type==='id'?32:(is_string($type)&&preg_match('/\Abytes:([1-9][0-9]{0,3})\z/D',$type,$match)?(int)$match[1]:0));
                if($limit<1||$limit>4096){throw new ConfigurationException('Binary payloads require a separate SQL length guard.','configuration.sql_schema');}
                $predicate=$driver==='sqlite'?"typeof(".$name.")='text' AND length(CAST(".$name.' AS BLOB))<='.$limit:'octet_length('.$name.')<='.$limit;
            }
            $fields[]='CASE WHEN '.$predicate.' THEN '.$name.' ELSE NULL END AS '.$name;
        }
        return implode(',',$fields);
    }
    /** Private ledger DDL has no foreign-key dependencies; inspect declarations even when enforcement is off. */
    public static function foreignKeyChecks(string $driver,string $table):array
    {
        if(!in_array($driver,['sqlite','mysql'],true)||!preg_match('/\Asosecurity_[a-z_]+\z/D',$table)){throw new ConfigurationException('Use a fixed private security table.','configuration.sql_schema');}
        if($driver==='mysql'){
            // INFORMATION_SCHEMA name matching follows the server's identifier case mode.
            $outgoing='LOWER(TABLE_SCHEMA)=LOWER(DATABASE()) AND LOWER(TABLE_NAME)=:outgoing AND (@@lower_case_table_names<>0 OR (BINARY TABLE_SCHEMA=BINARY DATABASE() AND BINARY TABLE_NAME=:outgoing_exact))';
            $incoming='LOWER(REFERENCED_TABLE_SCHEMA)=LOWER(DATABASE()) AND LOWER(REFERENCED_TABLE_NAME)=:incoming AND (@@lower_case_table_names<>0 OR (BINARY REFERENCED_TABLE_SCHEMA=BINARY DATABASE() AND BINARY REFERENCED_TABLE_NAME=:incoming_exact))';
            return [['sql'=>'SELECT 1 FROM information_schema.KEY_COLUMN_USAGE WHERE REFERENCED_TABLE_NAME IS NOT NULL AND (('.$outgoing.') OR ('.$incoming.')) LIMIT 1','parameters'=>['outgoing'=>$table,'outgoing_exact'=>$table,'incoming'=>$table,'incoming_exact'=>$table]]];
        }
        return [
            ['sql'=>"SELECT 1 FROM main.sqlite_master WHERE name COLLATE NOCASE='pragma_foreign_key_list' LIMIT 1",'parameters'=>[]],
            ['sql'=>"SELECT 1 FROM main.sqlite_master m JOIN main.pragma_foreign_key_list(m.name,'main') f WHERE m.type='table' AND (m.name COLLATE NOCASE=:outgoing OR f.\"table\" COLLATE NOCASE=:incoming) LIMIT 1",'parameters'=>['outgoing'=>$table,'incoming'=>$table]],
        ];
    }
    public static function integer($value):int
    {
        if(is_int($value)&&$value>=0){return $value;}
        if(is_string($value)&&preg_match('/\A(?:0|[1-9][0-9]{0,18})\z/D',$value)&&(string)(int)$value===$value&&(int)$value>=0){return (int)$value;}
        throw new StorageException('Invalid numeric security state.','sql.corrupt');
    }
    public static function durable(SqlTransaction $unit):void
    {
        if($unit->driver()==='mysql'){
            if((string)$unit->query('SELECT @@GLOBAL.innodb_flush_log_at_trx_commit')->fetchColumn()!=='1'){throw new ConfigurationException('Security SQL requires durable InnoDB commit flushing.','configuration.sql_durability');}return;
        }
        $main=null;foreach($unit->query('PRAGMA database_list')->fetchAll(PDO::FETCH_ASSOC) as $row){if($row['name']==='main'){$main=$row['file'];}}
        $mode=$unit->query('PRAGMA main.journal_mode')->fetchColumn();$sync=self::integer($unit->query('PRAGMA main.synchronous')->fetchColumn());
        if(!is_string($main)||$main===''||!is_file($main)||!is_string($mode)||!in_array(strtolower($mode),['delete','truncate','persist','wal'],true)||$sync<2){throw new ConfigurationException('Use a persistent SQLite file with journaling and FULL/EXTRA synchronization.','configuration.sql_durability');}
    }
    /** Types: int, digest(64), id(32), bytes:N, blob. Names and definitions are internal constants. */
    public static function table(SqlTransaction $unit,string $table,array $types,array $primary,array $indexes=[]):void
    {
        if(!preg_match('/\Asosecurity_[a-z_]+\z/D',$table)){throw new ConfigurationException('Invalid internal SQL table.','configuration.sql_schema');}
        $unit->query('SELECT 1 FROM '.$unit->prefix().$table.' LIMIT 0')->closeCursor();
        foreach(self::foreignKeyChecks($unit->driver(),$table) as $check){$q=$unit->query($check['sql'],$check['parameters']);$related=$q->fetchColumn()!==false;$q->closeCursor();if($related){throw new ConfigurationException('Private security tables must not have foreign-key dependencies.','configuration.sql_schema');}}
        if($unit->driver()==='sqlite'){
            $rows=$unit->query("PRAGMA main.table_info('".$table."')")->fetchAll(PDO::FETCH_ASSOC);$columns=array_column($rows,null,'name');
            if(count($columns)!==count($types)){throw new ConfigurationException('Install the explicit security SQL schema.','configuration.sql_schema');}
            foreach($types as $name=>$type){$column=$columns[$name] ?? null;$expected=$type==='int'?'INTEGER':($type==='blob'?'BLOB':'TEXT');$position=array_search($name,$primary,true);if(!is_array($column)||strtoupper($column['type'])!==$expected||(int)$column['notnull']!==1||(int)$column['pk']!==($position===false?0:$position+1)){throw new ConfigurationException('Security SQL column differs from its contract.','configuration.sql_schema');}}
            $owned=array_column($unit->query("PRAGMA main.index_list('".$table."')")->fetchAll(PDO::FETCH_ASSOC),null,'name');
            foreach($indexes as $name=>$definition){if(!isset($owned[$name])||(int)$owned[$name]['unique']!==($definition['unique']?1:0)||(int)($owned[$name]['partial'] ?? 0)!==0||array_column($unit->query("PRAGMA main.index_info('".$name."')")->fetchAll(PDO::FETCH_ASSOC),'name')!==$definition['columns']){throw new ConfigurationException('Security SQL index differs from its contract.','configuration.sql_schema');}}
            foreach(['main','temp'] as $schema){if($unit->query("SELECT 1 FROM ".$schema.".sqlite_master WHERE type='trigger' AND tbl_name=:table LIMIT 1",['table'=>$table])->fetchColumn()!==false){throw new ConfigurationException('Security state tables must not have triggers.','configuration.sql_schema');}}return;
        }
        $engine=$unit->query('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table',['table'=>$table])->fetchColumn();
        if(!is_string($engine)||strtolower($engine)!=='innodb'){throw new ConfigurationException('Security state tables require InnoDB.','configuration.sql_schema');}
        $columns=array_column($unit->query('SELECT COLUMN_NAME,DATA_TYPE,COLUMN_TYPE,IS_NULLABLE,CHARACTER_MAXIMUM_LENGTH,COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table',['table'=>$table])->fetchAll(PDO::FETCH_ASSOC),null,'COLUMN_NAME');
        if(count($columns)!==count($types)){throw new ConfigurationException('Install the explicit security SQL schema.','configuration.sql_schema');}
        foreach($types as $name=>$type){$column=$columns[$name] ?? null;$valid=is_array($column)&&$column['IS_NULLABLE']==='NO';if($valid){
            if($type==='int'){$valid=$column['DATA_TYPE']==='bigint'&&strpos($column['COLUMN_TYPE'],'unsigned')!==false;}
            elseif($type==='blob'){$valid=$column['DATA_TYPE']==='mediumblob';}
            elseif(strpos($type,'bytes:')===0){$valid=$column['DATA_TYPE']==='varbinary'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===(int)substr($type,6);}
            else{$valid=$column['DATA_TYPE']==='char'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===($type==='id'?32:64)&&$column['COLLATION_NAME']==='ascii_bin';}
        }if(!$valid){throw new ConfigurationException('Security SQL column differs from its contract.','configuration.sql_schema');}}
        $indexes['PRIMARY']=['unique'=>true,'columns'=>$primary];
        foreach($indexes as $name=>$definition){$rows=$unit->query('SELECT COLUMN_NAME,NON_UNIQUE,SUB_PART,INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table AND INDEX_NAME=:name ORDER BY SEQ_IN_INDEX',['table'=>$table,'name'=>$name])->fetchAll(PDO::FETCH_ASSOC);if(array_column($rows,'COLUMN_NAME')!==$definition['columns']||array_filter($rows,static function(array $row)use($definition):bool{return (string)$row['NON_UNIQUE']!==($definition['unique']?'0':'1')||$row['SUB_PART']!==null||$row['INDEX_TYPE']!=='BTREE';})){throw new ConfigurationException('Security SQL index differs from its contract.','configuration.sql_schema');}}
        if($unit->query('SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE=:table LIMIT 1',['table'=>$table])->fetchColumn()!==false){throw new ConfigurationException('Security state tables must not have triggers.','configuration.sql_schema');}
    }
}
