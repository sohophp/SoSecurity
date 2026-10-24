<?php
declare(strict_types=1);
namespace SoSecurity\Support;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

/** Internal read-only deployment contract. No migrations or session/durability changes. */
final class SqlSchema
{
    /** SQL-side guard for binary payload columns. SQLite affinity alone does not prohibit TEXT, including NUL prefixes. */
    public static function blobLength(string $driver,string $column,?string $alias=null):string
    {
        if(!in_array($driver,['sqlite','mysql'],true)||!preg_match('/\A[a-z][a-z_]*\z/D',$column)){throw new ConfigurationException('Use a fixed binary SQL column.','configuration.sql_schema');}
        if($alias!==null){if(!preg_match('/\A[a-z][a-z_]{0,15}\z/D',$alias)){throw new ConfigurationException('Use a fixed SQL alias.','configuration.sql_schema');}$column=$alias.'.'.$column;}
        return $driver==='sqlite'?"CASE WHEN typeof(".$column.")='blob' THEN length(".$column.") ELSE -1 END":'length('.$column.')';
    }
    /** Bounded metadata projection: malformed/oversized fields become NULL, which strict state readers reject. */
    public static function boundedProjection(string $driver,array $types,?string $alias=null,string $prefix='',bool $textIntegers=false):string
    {
        if(!in_array($driver,['sqlite','mysql'],true)||count($types)<1||count($types)>64||($textIntegers&&$driver!=='mysql')){throw new ConfigurationException('Use bounded internal SQL metadata.','configuration.sql_schema');}
        if(($alias!==null&&!preg_match('/\A[a-z][a-z_]{0,15}\z/D',$alias))||($prefix!==''&&!preg_match('/\A[a-z][a-z_]{0,15}_\z/D',$prefix))){throw new ConfigurationException('Use fixed bounded SQL aliases.','configuration.sql_schema');}
        $fields=[];
        foreach($types as $name=>$type){
            if(!is_string($name)||!preg_match('/\A[a-z][a-z_]*\z/D',$name)){throw new ConfigurationException('Use fixed SQL metadata columns.','configuration.sql_schema');}
            $column=$alias===null?$name:$alias.'.'.$name;
            if($type==='int'){$predicate=$driver==='sqlite'?"typeof(".$column.")='integer' AND ".$column.'>=0':$column.'>=0 AND '.$column.'<=9223372036854775807';}
            else{
                $limit=$type==='digest'?64:($type==='id'?32:(is_string($type)&&preg_match('/\Abytes:([1-9][0-9]{0,3})\z/D',$type,$match)?(int)$match[1]:0));
                if($limit<1||$limit>4096){throw new ConfigurationException('Binary payloads require a separate SQL length guard.','configuration.sql_schema');}
                $predicate=$driver==='sqlite'?"typeof(".$column.")='text' AND length(CAST(".$column.' AS BLOB))<='.$limit:'octet_length('.$column.')<='.$limit;
            }
            $value=$textIntegers&&$type==='int'?'CAST('.$column.' AS CHAR)':$column;
            $fields[]='CASE WHEN '.$predicate.' THEN '.$value.' ELSE NULL END AS '.$prefix.$name;
        }
        return implode(',',$fields);
    }
    /** Private ledger DDL has no foreign-key dependencies; inspect declarations even when enforcement is off. */
    public static function foreignKeyChecks(string $driver,string $table):array
    {
        if(!in_array($driver,['sqlite','mysql'],true)||!preg_match('/\Asosecurity_[a-z_]+\z/D',$table)){throw new ConfigurationException('Use a fixed private security table.','configuration.sql_schema');}
        if($driver==='mysql'){
            // INFORMATION_SCHEMA name matching follows the server's identifier case mode.
            // One row per declared constraint avoids expanding every key column.
            // Keep both directions (including foreign schemas), case mode, and disabled-FK visibility.
            $outgoing='LOWER(CONSTRAINT_SCHEMA)=LOWER(DATABASE()) AND LOWER(TABLE_NAME)=:outgoing AND (@@lower_case_table_names<>0 OR (BINARY CONSTRAINT_SCHEMA=BINARY DATABASE() AND BINARY TABLE_NAME=:outgoing_exact))';
            $incoming='LOWER(UNIQUE_CONSTRAINT_SCHEMA)=LOWER(DATABASE()) AND LOWER(REFERENCED_TABLE_NAME)=:incoming AND (@@lower_case_table_names<>0 OR (BINARY UNIQUE_CONSTRAINT_SCHEMA=BINARY DATABASE() AND BINARY REFERENCED_TABLE_NAME=:incoming_exact))';
            return [['sql'=>'SELECT 1 FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE ('.$outgoing.') OR ('.$incoming.') LIMIT 1','parameters'=>['outgoing'=>$table,'outgoing_exact'=>$table,'incoming'=>$table,'incoming_exact'=>$table]]];
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
            $rows=$unit->metadataRows('SELECT @@GLOBAL.innodb_flush_log_at_trx_commit');
            if(count($rows)!==1||!is_array($rows[0])||count($rows[0])!==1||(string)reset($rows[0])!=='1'){throw new ConfigurationException('Security SQL requires durable InnoDB commit flushing.','configuration.sql_durability');}return;
        }
        $main=null;foreach($unit->metadataRows('PRAGMA database_list') as $row){if($row['name']==='main'){$main=$row['file'];}}
        $rows=$unit->metadataRows('PRAGMA main.journal_mode');$mode=count($rows)===1&&is_array($rows[0])&&count($rows[0])===1?reset($rows[0]):null;
        $rows=$unit->metadataRows('PRAGMA main.synchronous');$sync=self::integer(count($rows)===1&&is_array($rows[0])&&count($rows[0])===1?reset($rows[0]):null);
        if(!is_string($main)||$main===''||!is_file($main)||!is_string($mode)||!in_array(strtolower($mode),['delete','truncate','persist','wal'],true)||$sync<2){throw new ConfigurationException('Use a persistent SQLite file with journaling and FULL/EXTRA synchronization.','configuration.sql_durability');}
    }
    /** MySQL resolves both references before execution, rejecting temporary table shadowing with zero rows. */
    public static function tableResolution(string $table):string
    {
        if(!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$table)){throw new ConfigurationException('Use a fixed SQL table identifier.','configuration.sql_schema');}
        return 'SELECT 1 FROM `'.$table.'` AS _sosecurity_left JOIN `'.$table.'` AS _sosecurity_right ON 1=0 LIMIT 0';
    }
    /** Types: int, digest(64), id(32), bytes:N, blob. Names and definitions are internal constants. */
    public static function table(SqlTransaction $unit,string $table,array $types,array $primary,array $indexes=[]):void
    {
        if(!preg_match('/\Asosecurity_[a-z_]+\z/D',$table)){throw new ConfigurationException('Invalid internal SQL table.','configuration.sql_schema');}
        if($unit->metadataRows($unit->driver()==='mysql'?self::tableResolution($table):'SELECT 1 FROM '.$unit->prefix().$table.' LIMIT 0')!==[]){throw new ConfigurationException('Cannot prove private SQL table resolution.','configuration.sql_schema');}
        if($unit->driver()==='sqlite'){
            foreach(self::foreignKeyChecks($unit->driver(),$table) as $check){$related=$unit->metadataRows($check['sql'],$check['parameters'])!==[];if($related){throw new ConfigurationException('Private security tables must not have foreign-key dependencies.','configuration.sql_schema');}}
            // Table-valued metadata is read-only, including inside observation units.
            // Reject shadow objects before resolving SQLite's built-in metadata modules.
            foreach(['main','temp'] as $schema){if($unit->metadataRows("SELECT 1 FROM ".$schema.".sqlite_master WHERE name COLLATE NOCASE IN ('pragma_table_info','pragma_index_list','pragma_index_info') LIMIT 1")!==[]){throw new ConfigurationException('SQLite metadata modules must not be shadowed.','configuration.sql_schema');}}
            $rows=$unit->metadataRows('SELECT CASE WHEN length(CAST(name AS BLOB))<=64 THEN name ELSE NULL END AS name,CASE WHEN length(CAST(type AS BLOB))<=128 THEN type ELSE NULL END AS type,"notnull",pk FROM main.pragma_table_info(:table,\'main\') ORDER BY cid LIMIT 65',['table'=>$table]);$columns=array_column($rows,null,'name');
            if(count($columns)!==count($types)){throw new ConfigurationException('Install the explicit security SQL schema.','configuration.sql_schema');}
            foreach($types as $name=>$type){$column=$columns[$name] ?? null;$expected=$type==='int'?'INTEGER':($type==='blob'?'BLOB':'TEXT');$position=array_search($name,$primary,true);if(!is_array($column)||!is_string($column['type'])||strtoupper($column['type'])!==$expected||(int)$column['notnull']!==1||(int)$column['pk']!==($position===false?0:$position+1)){throw new ConfigurationException('Security SQL column differs from its contract.','configuration.sql_schema');}}
            $ownedRows=$unit->metadataRows('SELECT CASE WHEN length(CAST(name AS BLOB))<=256 THEN name ELSE NULL END AS name,"unique",partial,CASE WHEN origin IN (\'c\',\'u\',\'pk\') THEN origin ELSE NULL END AS origin FROM main.pragma_index_list(:table,\'main\') LIMIT 129',['table'=>$table]);
            if(count($ownedRows)>128){throw new ConfigurationException('Security SQL index metadata exceeds its bound.','configuration.sql_schema');}foreach($ownedRows as $index){if(!is_string($index['name'])||!is_string($index['origin'])){throw new ConfigurationException('Invalid security SQL index metadata.','configuration.sql_schema');}if((int)$index['unique']===1&&$index['origin']!=='pk'&&(!isset($indexes[$index['name']])||!$indexes[$index['name']]['unique'])){throw new ConfigurationException('Private SQL tables must not have undeclared unique constraints.','configuration.sql_schema');}}$owned=array_column($ownedRows,null,'name');
            foreach($indexes as $name=>$definition){if(!isset($owned[$name])||(int)$owned[$name]['unique']!==($definition['unique']?1:0)||(int)($owned[$name]['partial'] ?? 0)!==0||array_column($unit->metadataRows('SELECT CASE WHEN length(CAST(name AS BLOB))<=64 THEN name ELSE NULL END AS name FROM main.pragma_index_info(:index,\'main\') ORDER BY seqno LIMIT 65',['index'=>$name]),'name')!==$definition['columns']){throw new ConfigurationException('Security SQL index differs from its contract.','configuration.sql_schema');}}
            foreach(['main','temp'] as $schema){if($unit->metadataRows("SELECT 1 FROM ".$schema.".sqlite_master WHERE type='trigger' AND tbl_name COLLATE NOCASE=:table LIMIT 1",['table'=>$table])!==[]){throw new ConfigurationException('Security state tables must not have triggers.','configuration.sql_schema');}}return;
        }
        self::mysqlTables($unit,[$table=>['types'=>$types,'primary'=>$primary,'indexes'=>$indexes]]);
    }
    /** Internal bounded pair. Each table keeps its complete independent contract and row limits. */
    public static function tables(SqlTransaction $unit,array $tables):void
    {
        if(count($tables)<1||count($tables)>2){throw new ConfigurationException('Use at most two fixed private SQL contracts.','configuration.sql_schema');}
        foreach($tables as $table=>$spec){
            $shape=is_array($spec)?array_keys($spec):[];sort($shape);
            if(!is_string($table)||($unit->driver()==='mysql'&&strlen($table)>64)||!preg_match('/\Asosecurity_[a-z_]+\z/D',$table)||$shape!==['indexes','primary','types']||!is_array($spec['types'])||count($spec['types'])<1||count($spec['types'])>64||!is_array($spec['primary'])||count($spec['primary'])<1||count($spec['primary'])>4||!is_array($spec['indexes'])||count($spec['indexes'])>16){throw new ConfigurationException('Use fixed bounded private SQL contracts.','configuration.sql_schema');}
        }
        if($unit->driver()==='sqlite'){foreach($tables as $table=>$spec){self::table($unit,$table,$spec['types'],$spec['primary'],$spec['indexes']);}return;}
        // Acquire each real table's metadata lock before the single fresh metadata statement.
        $references=[];$position=0;
        foreach($tables as $table=>$spec){
            $references[]='`'.$table.'` AS _sosecurity_left_'.$position;
            $references[]='`'.$table.'` AS _sosecurity_right_'.$position;++$position;
        }
        // Resolve every table twice in one zero-row statement; temporary shadowing still fails at prepare.
        $first=array_shift($references);
        if($unit->metadataRows('SELECT 1 FROM '.$first.' JOIN '.implode(' ON 1=0 JOIN ',$references).' ON 1=0 LIMIT 0')!==[]){throw new ConfigurationException('Cannot prove private SQL table resolution.','configuration.sql_schema');}
        self::mysqlTables($unit,$tables);
    }
    private static function mysqlTables(SqlTransaction $unit,array $tables):void
    {
        $queries=[];$branches=[];$parameters=[];$data=[];$paired=count($tables)>1;
        foreach($tables as $table=>$spec){
            $query=self::mysqlTableQuery($table,$spec['primary'],$spec['indexes']);$queries[$table]=$query;$offset=count($branches);$data[$table]=['columns'=>[],'indexes'=>[]];
            if(!$paired){$branches[]=$query['sql'];$parameters=$query['parameters'];continue;}
            $prefix='table_'.$offset.'_';
            $sql=preg_replace_callback('/:([a-z][a-z0-9_]*)\b/',static function(array $match)use($prefix):string{return ':'.$prefix.$match[1];},$query['sql']);
            $branches[]='SELECT '.$offset.' AS __table,m.* FROM ('.$sql.') m';
            foreach($query['parameters'] as $key=>$value){$parameters[$prefix.$key]=$value;}
        }
        $sql=implode(' UNION ALL ',$branches).($paired?' ORDER BY __table,section,INDEX_NAME,__position':'');$names=array_keys($tables);
        foreach($unit->metadataRows($sql,$parameters) as $row){
            $offset=$paired?($row['__table']??null):0;
            if((!is_string($offset)&&!is_int($offset))||!in_array((string)$offset,$paired?['0','1']:['0'],true)){throw new ConfigurationException('Invalid private SQL table metadata section.','configuration.sql_schema');}
            $table=$names[(int)$offset];
            if(!in_array($row['section']??null,['columns','indexes'],true)){throw new ConfigurationException('Invalid private SQL metadata section.','configuration.sql_schema');}
            $data[$table][$row['section']][]=$row;
            if(count($data[$table]['columns'])>65||count($data[$table]['indexes'])>260){throw new ConfigurationException('Private SQL metadata exceeds its bound.','configuration.sql_schema');}
        }
        foreach($tables as $table=>$spec){
            $types=$spec['types'];$primary=$spec['primary'];$indexes=$spec['indexes'];$indexes['PRIMARY']=['unique'=>true,'columns'=>$primary];$groups=$queries[$table]['groups'];$rows=$data[$table]['columns'];$indexRows=$data[$table]['indexes'];
            if(!$rows||count($rows)>64){throw new ConfigurationException('Install the explicit bounded security SQL schema.','configuration.sql_schema');}
            // Keep observed principal metadata local: exception trace arguments must not expose it.
            $visible=$rows[0];
            if(!is_string($visible['identity']??null)||!preg_match('/\A([A-Za-z0-9_.-]{1,32})@([A-Za-z0-9_.:%\/-]{1,255})\z/D',$visible['identity'])){throw new ConfigurationException('Cannot prove private SQL metadata visibility.','configuration.sql_schema');}
            if((string)$visible['scoped']!=='1'&&((string)$visible['unrestricted']!=='1'||!self::mysqlPartialRevokesDisabled($unit))){throw new ConfigurationException('Direct private SQL trigger metadata visibility is required.','configuration.sql_schema');}
            if((string)$visible['has_trigger']!=='0'){throw new ConfigurationException('Private SQL tables must not have triggers.','configuration.sql_schema');}
            // Required indexes are still checked below; their exact unique count rules out hidden extra constraints.
            $uniqueCount=count(array_filter($indexes,static function(array $definition):bool{return (bool)$definition['unique'];}));
            if(!isset($visible['unique_indexes'])||!is_scalar($visible['unique_indexes'])||(string)$visible['unique_indexes']!==(string)$uniqueCount){throw new ConfigurationException('Private SQL tables must not have undeclared unique constraints.','configuration.sql_schema');}
            foreach($rows as $row){if((string)$row['foreign_dependency']!=='0'||(string)$row['trigger_dependency']!=='0'){throw new ConfigurationException('Private security tables must not have foreign-key dependencies or triggers.','configuration.sql_schema');}if(!is_string($row['ENGINE'])||strtolower($row['ENGINE'])!=='innodb'){throw new ConfigurationException('Security state tables require InnoDB.','configuration.sql_schema');}if(!is_string($row['COLUMN_NAME'])||!is_string($row['DATA_TYPE'])||!is_string($row['COLUMN_TYPE'])){throw new ConfigurationException('Security SQL column exceeds its contract.','configuration.sql_schema');}}
            $columns=array_column($rows,null,'COLUMN_NAME');
            if(count($columns)!==count($types)){throw new ConfigurationException('Install the explicit security SQL schema.','configuration.sql_schema');}
            foreach($types as $name=>$type){$column=$columns[$name] ?? null;$valid=is_array($column)&&$column['IS_NULLABLE']==='NO';if($valid){
                if($type==='int'){$valid=$column['DATA_TYPE']==='bigint'&&strpos($column['COLUMN_TYPE'],'unsigned')!==false;}
                elseif($type==='blob'){$valid=$column['DATA_TYPE']==='mediumblob';}
                elseif(strpos($type,'bytes:')===0){$valid=$column['DATA_TYPE']==='varbinary'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===(int)substr($type,6);}
                else{$valid=$column['DATA_TYPE']==='char'&&(int)$column['CHARACTER_MAXIMUM_LENGTH']===($type==='id'?32:64)&&$column['COLLATION_NAME']==='ascii_bin';}
            }if(!$valid){throw new ConfigurationException('Security SQL column differs from its contract.','configuration.sql_schema');}}
            // Later groups keep independent bounded reads; all original index validations still apply.
            foreach($groups as $offset=>$group){
                $observed=[];foreach($group as $name=>$definition){$observed[strtolower($name)]=[];}
                if($offset===0){$rows=$indexRows;}
                else{$next=self::mysqlIndexQuery($table,$group);$rows=$unit->metadataRows($next['sql'],$next['parameters']);}
                foreach($rows as $row){
                    if(!is_string($row['INDEX_NAME'])||!is_string($row['COLUMN_NAME'])){throw new ConfigurationException('Invalid security SQL index metadata.','configuration.sql_schema');}$name=strtolower($row['INDEX_NAME']);
                    if(!isset($observed[$name])||count($observed[$name])>=64){throw new ConfigurationException('Security SQL index metadata exceeds its bound.','configuration.sql_schema');}$observed[$name][]=$row;
                }
                foreach($group as $name=>$definition){$rows=$observed[strtolower($name)];if(array_column($rows,'COLUMN_NAME')!==$definition['columns']||array_filter($rows,static function(array $row)use($definition):bool{return (string)$row['NON_UNIQUE']!==($definition['unique']?'0':'1')||$row['SUB_PART']!==null||$row['INDEX_TYPE']!=='BTREE';})){throw new ConfigurationException('Security SQL index differs from its contract.','configuration.sql_schema');}}
            }
        }
    }
    /** Fixed bounded snapshot catalog SQL; retains only eight code templates, never names or rows. */
    public static function snapshotMetadataStatement(array $tables,bool $text=false):array
    {
        $count=count($tables);if($count<1||$count>4||array_keys($tables)!==range(0,$count-1)){throw new ConfigurationException('Use one to four fixed snapshot table names.','configuration.sql_schema');}
        foreach($tables as $table){if(!is_string($table)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$table)){throw new ConfigurationException('Use fixed snapshot table identifiers.','configuration.sql_schema');}}
        if(count(array_unique($tables))!==$count){throw new ConfigurationException('Use distinct snapshot tables.','configuration.sql_schema');}
        $parameters=[];$names=[];foreach($tables as $table){$key='table_'.count($names);$names[]=':'.$key;$parameters[$key]=$table;}
        $keyParameters=[];foreach($parameters as $key=>$value){$keyParameters['key_'.$key]=$value;}
        static $templates=[];$templateKey=$count.($text?'text':'native');
        if(!isset($templates[$templateKey])){
            $in=implode(',',$names);
            $columnSql="SELECT CASE WHEN OCTET_LENGTH(t.TABLE_NAME)<=64 THEN t.TABLE_NAME ELSE NULL END AS table_name,CASE WHEN OCTET_LENGTH(t.ENGINE)<=32 THEN t.ENGINE ELSE NULL END AS engine,t.TABLE_TYPE AS table_type,CASE WHEN OCTET_LENGTH(c.COLUMN_NAME)<=64 THEN c.COLUMN_NAME ELSE NULL END AS name,CASE WHEN OCTET_LENGTH(c.DATA_TYPE)<=64 THEN c.DATA_TYPE ELSE NULL END AS storage_type,CASE WHEN OCTET_LENGTH(c.COLUMN_TYPE)<=128 THEN c.COLUMN_TYPE ELSE NULL END AS declaration,CASE WHEN OCTET_LENGTH(c.COLLATION_NAME)<=128 THEN c.COLLATION_NAME ELSE NULL END AS collation_name,c.ORDINAL_POSITION AS ordinal,c.IS_NULLABLE AS nullable FROM information_schema.TABLES t INNER JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA=t.TABLE_SCHEMA AND c.TABLE_NAME=t.TABLE_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME IN (".$in.") ORDER BY t.TABLE_NAME,c.ORDINAL_POSITION LIMIT ".(count($tables)*65);
            $keySql="SELECT CASE WHEN OCTET_LENGTH(TABLE_NAME)<=64 THEN TABLE_NAME ELSE NULL END AS table_name,CASE WHEN OCTET_LENGTH(COLUMN_NAME)<=64 THEN COLUMN_NAME ELSE NULL END AS name,SEQ_IN_INDEX AS position,SUB_PART,NON_UNIQUE,INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (".$in.") AND INDEX_NAME='PRIMARY' ORDER BY TABLE_NAME,SEQ_IN_INDEX LIMIT ".(count($tables)*5);
            // Preserve the independent column/key row bounds, then order the tagged result explicitly.
            // Native MySQL prepares require distinct placeholders in the two branches.
            foreach(array_keys($parameters) as $key){$keySql=str_replace(':'.$key,':key_'.$key,$keySql);}
            $sql="SELECT 'columns' AS section,c.*,NULL AS position,NULL AS SUB_PART,NULL AS NON_UNIQUE,NULL AS INDEX_TYPE FROM (".$columnSql.") c UNION ALL SELECT 'keys',k.table_name,NULL,NULL,k.name,NULL,NULL,NULL,NULL,NULL,k.position,k.SUB_PART,k.NON_UNIQUE,k.INDEX_TYPE FROM (".$keySql.") k ORDER BY section,table_name,ordinal,position";
            if($text){
                $fields=[];foreach(['section','table_name','engine','table_type','name','storage_type','declaration','collation_name','ordinal','nullable','position','SUB_PART','NON_UNIQUE','INDEX_TYPE'] as $field){
                    $value='_sosecurity_snapshot_schema.'.$field;$fields[]=(in_array($field,['ordinal','position','SUB_PART','NON_UNIQUE'],true)?'CAST('.$value.' AS CHAR)':$value).' AS '.$field;
                }
                $sql='SELECT '.implode(',',$fields).' FROM ('.$sql.') AS _sosecurity_snapshot_schema ORDER BY _sosecurity_snapshot_schema.section,_sosecurity_snapshot_schema.table_name,_sosecurity_snapshot_schema.ordinal,_sosecurity_snapshot_schema.position';
            }
            $templates[$templateKey]=$sql;
        }
        return ['sql'=>$templates[$templateKey],'parameters'=>$parameters+$keyParameters];
    }
    /** Concrete current access proof for the fixed account ledger; never returns cached authorization. */
    public static function ledgerSchemaContext(SqlTransaction $unit):array
    {
        if($unit->driver()!=='mysql'){throw new ConfigurationException('Use MySQL ledger context.', 'configuration.sql_schema');}
        $native=$unit->canBatchLedgerReads();
        if(!$native){
            try{self::durable($unit);}
            catch(\SoSecurity\Exception\SecurityException|ConfigurationException $error){throw $error;}
            catch(\Throwable $error){throw new StorageException('Ledger durability observation unavailable.','sql.unavailable');}
        }
        if($native){$query=self::ledgerContextStatement();$sql=$query['sql'];$parameters=$query['parameters'];}
        else{
            $references=[];$branches=[];$parameters=[];
            foreach(['sosecurity_account_roots','sosecurity_account_records'] as $index=>$table){
                $references[]='`'.$table.'` AS _sosecurity_left_'.$index;$references[]='`'.$table.'` AS _sosecurity_right_'.$index;
                $prefix='context_'.$index.'_';
                $visibility=preg_replace_callback('/:([a-z][a-z0-9_]*)\b/',static function(array $match)use($prefix):string{return ':'.$prefix.$match[1];},self::mysqlVisibilitySql());
                $branches[]='SELECT '.$index.' AS position,CASE WHEN OCTET_LENGTH(DATABASE())<=256 THEN CAST(DATABASE() AS BINARY) ELSE NULL END AS database_name,v.* FROM ('.$visibility.' LIMIT 1) v';
                $parameters[$prefix.'visibility_table']=$table;$parameters[$prefix.'visibility_trigger_table']=$table;
            }
            $first=array_shift($references);$resolution='SELECT 1 FROM '.$first.' JOIN '.implode(' ON 1=0 JOIN ',$references).' ON 1=0 LIMIT 0';$visibility=implode(' UNION ALL ',$branches);
            $unit->metadataRows($resolution);$sql=$visibility.' ORDER BY position';
        }
        // Consume and close through the unit: uncertain cleanup must poison it, even when a caller catches the error.
        $rows=$unit->metadataRows($sql,$parameters);
        if(count($rows)!==2){throw new ConfigurationException('Cannot prove current ledger access.','configuration.sql_schema');}
        $database=null;
        foreach($rows as $index=>$row){
            if($native&&(string)($row['ledger_durable']??'')!=='1'){throw new ConfigurationException('Security SQL requires durable InnoDB commit flushing.','configuration.sql_durability');}
            if((string)($row['position']??'')!==(string)$index||!is_string($row['database_name']??null)||$row['database_name']===''||strlen($row['database_name'])>256
                ||!is_string($row['identity']??null)||!preg_match('/\A([A-Za-z0-9_.-]{1,32})@([A-Za-z0-9_.:%\/-]{1,255})\z/D',$row['identity'])){throw new ConfigurationException('Cannot prove current ledger access.','configuration.sql_schema');}
            if($database!==null&&$database!==$row['database_name']){throw new ConfigurationException('Ledger database changed.','configuration.sql_schema');}$database=$row['database_name'];
            if((string)$row['scoped']!=='1'&&((string)$row['unrestricted']!=='1'||!self::mysqlPartialRevokesDisabled($unit))){throw new ConfigurationException('Direct private SQL trigger metadata visibility is required.','configuration.sql_schema');}
            if((string)$row['has_trigger']!=='0'){throw new ConfigurationException('Private SQL tables must not have triggers.','configuration.sql_schema');}
        }
        return ['database'=>$database];
    }
    /** Check the fresh global setting through the unit so failed cleanup cannot be caught and ignored.
     * @phpstan-impure
     */
    private static function mysqlPartialRevokesDisabled(SqlTransaction $unit):bool
    {
        try{$rows=$unit->metadataRows('SELECT @@GLOBAL.partial_revokes');}
        catch(\SoSecurity\Exception\SecurityException|ConfigurationException $error){throw $error;}
        catch(\Throwable $error){throw new StorageException('SQL trigger visibility observation unavailable.','sql.unavailable');}
        return count($rows)===1&&is_array($rows[0])&&count($rows[0])===1&&in_array(reset($rows[0]),[0,'0'],true);
    }
    /** The two fixed tables share one principal/schema observation within this SQL statement only. */
    /** Fixed code and parameters only. Never retains a database name, row or authorization decision. */
    public static function ledgerContextStatement():array
    {
        static $query=null;
        if($query===null){
            $references=[];$parameters=[];
            foreach(['sosecurity_account_roots','sosecurity_account_records'] as $index=>$table){
                $references[]='`'.$table.'` AS _sosecurity_left_'.$index;$references[]='`'.$table.'` AS _sosecurity_right_'.$index;
                $parameters['context_'.$index.'_visibility_table']=$table;$parameters['context_'.$index.'_visibility_trigger_table']=$table;
            }
            $first=array_shift($references);$resolution='SELECT 1 FROM '.$first.' JOIN '.implode(' ON 1=0 JOIN ',$references).' ON 1=0 LIMIT 0';
            // All output is text/NULL, independent of STRINGIFY_FETCHES, including old PDO drivers.
            $fields=[];foreach(['position','database_name','identity','ledger_durable','scoped','unrestricted','has_trigger'] as $field){
                $fields[]=(in_array($field,['database_name','identity'],true)?'v.'.$field:'CAST(v.'.$field.' AS CHAR)').' AS '.$field;
            }
            $visibility='SELECT '.implode(',',$fields).' FROM ('.self::mysqlLedgerVisibilitySql().') v';
            $sql='SELECT _sosecurity_context.* FROM ('.$visibility.') AS _sosecurity_context LEFT JOIN ('.$resolution.') AS _sosecurity_resolution ON 1=0 ORDER BY _sosecurity_context.position';
            $query=['sql'=>$sql,'parameters'=>$parameters];
        }
        return $query;
    }
    private static function mysqlLedgerVisibilitySql():string
    {
        $principal="SELECT CASE WHEN OCTET_LENGTH(CURRENT_USER())<=288 THEN CURRENT_USER() ELSE NULL END AS identity LIMIT 1";
        $grantee="CONCAT(CHAR(39),SUBSTRING_INDEX(principal.identity,'@',1),CHAR(39),'@',CHAR(39),SUBSTRING_INDEX(principal.identity,'@',-1),CHAR(39))";
        $shared="SELECT principal.identity,@@GLOBAL.innodb_flush_log_at_trx_commit AS ledger_durable,CASE WHEN OCTET_LENGTH(DATABASE())<=256 THEN CAST(DATABASE() AS BINARY) ELSE NULL END AS database_name,EXISTS(SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE BINARY GRANTEE=".$grantee." AND BINARY TABLE_SCHEMA=BINARY DATABASE() AND PRIVILEGE_TYPE='TRIGGER') AS schema_scoped,EXISTS(SELECT 1 FROM information_schema.USER_PRIVILEGES WHERE BINARY GRANTEE=".$grantee." AND PRIVILEGE_TYPE='TRIGGER') AS unrestricted FROM (".$principal.") principal LIMIT 1";
        $grantee=str_replace('principal.identity','_sosecurity_shared.identity',$grantee);
        $tables="SELECT 0 AS position,:context_0_visibility_table AS visibility_table,:context_0_visibility_trigger_table AS trigger_table UNION ALL SELECT 1,:context_1_visibility_table,:context_1_visibility_trigger_table";
        return "SELECT _sosecurity_tables.position,_sosecurity_shared.database_name,_sosecurity_shared.identity,_sosecurity_shared.ledger_durable,(_sosecurity_shared.schema_scoped OR EXISTS(SELECT 1 FROM information_schema.TABLE_PRIVILEGES WHERE BINARY GRANTEE=".$grantee." AND BINARY TABLE_SCHEMA=BINARY DATABASE() AND BINARY TABLE_NAME=_sosecurity_tables.visibility_table AND PRIVILEGE_TYPE='TRIGGER')) AS scoped,_sosecurity_shared.unrestricted,EXISTS(SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE=_sosecurity_tables.trigger_table) AS has_trigger FROM (".$shared.") _sosecurity_shared CROSS JOIN (".$tables.") _sosecurity_tables";
    }
    private static function mysqlVisibilitySql():string
    {
        return "SELECT principal.identity,(EXISTS(SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE BINARY GRANTEE=CONCAT(CHAR(39),SUBSTRING_INDEX(principal.identity,'@',1),CHAR(39),'@',CHAR(39),SUBSTRING_INDEX(principal.identity,'@',-1),CHAR(39)) AND BINARY TABLE_SCHEMA=BINARY DATABASE() AND PRIVILEGE_TYPE='TRIGGER') OR EXISTS(SELECT 1 FROM information_schema.TABLE_PRIVILEGES WHERE BINARY GRANTEE=CONCAT(CHAR(39),SUBSTRING_INDEX(principal.identity,'@',1),CHAR(39),'@',CHAR(39),SUBSTRING_INDEX(principal.identity,'@',-1),CHAR(39)) AND BINARY TABLE_SCHEMA=BINARY DATABASE() AND BINARY TABLE_NAME=:visibility_table AND PRIVILEGE_TYPE='TRIGGER')) AS scoped,EXISTS(SELECT 1 FROM information_schema.USER_PRIVILEGES WHERE BINARY GRANTEE=CONCAT(CHAR(39),SUBSTRING_INDEX(principal.identity,'@',1),CHAR(39),'@',CHAR(39),SUBSTRING_INDEX(principal.identity,'@',-1),CHAR(39)) AND PRIVILEGE_TYPE='TRIGGER') AS unrestricted,EXISTS(SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE=:visibility_trigger_table) AS has_trigger FROM (SELECT CASE WHEN OCTET_LENGTH(CURRENT_USER())<=288 THEN CURRENT_USER() ELSE NULL END AS identity LIMIT 1) principal";
    }
    /** Fixed expected contracts only; never receives observed account metadata. */
    private static function mysqlTableQuery(string $table,array $primary,array $indexes):array
    {
        // Read engine and bounded columns together, without retaining metadata across observations.
        // LIMIT materializes the uncacheable foreign-key check once, rather than once per column.
        $visibility=self::mysqlVisibilitySql();
        $foreign=self::foreignKeyChecks('mysql',$table)[0];$parameters=['table'=>$table,'unique_table'=>$table]+$foreign['parameters']+['visibility_table'=>$table,'visibility_trigger_table'=>$table];
        // The same statement's materialized visibility proof already reads trigger presence.
        $columnSql='SELECT c.ORDINAL_POSITION AS __position,visibility.identity,visibility.scoped,visibility.unrestricted,visibility.has_trigger,dependency.foreign_dependency,dependency.unique_indexes,visibility.has_trigger AS trigger_dependency,CASE WHEN octet_length(t.ENGINE)<=32 THEN t.ENGINE ELSE NULL END AS ENGINE,CASE WHEN octet_length(c.COLUMN_NAME)<=64 THEN c.COLUMN_NAME ELSE NULL END AS COLUMN_NAME,CASE WHEN octet_length(c.DATA_TYPE)<=64 THEN c.DATA_TYPE ELSE NULL END AS DATA_TYPE,CASE WHEN octet_length(c.COLUMN_TYPE)<=128 THEN c.COLUMN_TYPE ELSE NULL END AS COLUMN_TYPE,c.IS_NULLABLE,c.CHARACTER_MAXIMUM_LENGTH,CASE WHEN octet_length(c.COLLATION_NAME)<=128 THEN c.COLLATION_NAME ELSE NULL END AS COLLATION_NAME FROM information_schema.TABLES t JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA=t.TABLE_SCHEMA AND c.TABLE_NAME=t.TABLE_NAME CROSS JOIN (SELECT EXISTS ('.$foreign['sql'].') AS foreign_dependency,(SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:unique_table AND NON_UNIQUE=0) AS unique_indexes LIMIT 1) dependency CROSS JOIN ('.$visibility.' LIMIT 1) visibility WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME=:table ORDER BY c.ORDINAL_POSITION LIMIT 65';
        $indexes['PRIMARY']=['unique'=>true,'columns'=>$primary];$groups=array_chunk($indexes,4,true);
        $first=self::mysqlIndexQuery($table,$groups[0]);
        // Each branch retains its own row/field bounds. Only the first index group shares the column read.
        $columnFields=['identity','scoped','unrestricted','has_trigger','foreign_dependency','unique_indexes','trigger_dependency','ENGINE','COLUMN_NAME','DATA_TYPE','COLUMN_TYPE','IS_NULLABLE','CHARACTER_MAXIMUM_LENGTH','COLLATION_NAME'];
        $indexFields=['INDEX_NAME','COLUMN_NAME','NON_UNIQUE','SUB_PART','INDEX_TYPE'];$left=[];$right=[];
        foreach(array_unique(array_merge($columnFields,$indexFields)) as $field){$left[]=(in_array($field,$columnFields,true)?'c.'.$field:'NULL').' AS '.$field;$right[]=in_array($field,$indexFields,true)?'i.'.$field:'NULL';}
        $sql="SELECT 'columns' AS section,c.__position,".implode(',',$left).' FROM ('.$columnSql.") c UNION ALL SELECT 'indexes',i.__position,".implode(',',$right).' FROM ('.$first['sql'].') i ORDER BY section,INDEX_NAME,__position';
        return ['sql'=>$sql,'parameters'=>$parameters+$first['parameters'],'groups'=>$groups];
    }
    /** Fixed internal identifiers only; no observed account or schema values cross this helper boundary. */
    private static function mysqlIndexQuery(string $table,array $group):array
    {
        $parameters=['index_table'=>$table];$placeholders=[];
        foreach($group as $name=>$definition){$parameter='index_'.count($placeholders);$parameters[$parameter]=$name;$placeholders[]=':'.$parameter;}
        return ['sql'=>'SELECT SEQ_IN_INDEX AS __position,CASE WHEN octet_length(INDEX_NAME)<=64 THEN INDEX_NAME ELSE NULL END AS INDEX_NAME,CASE WHEN octet_length(COLUMN_NAME)<=64 THEN COLUMN_NAME ELSE NULL END AS COLUMN_NAME,NON_UNIQUE,SUB_PART,CASE WHEN octet_length(INDEX_TYPE)<=16 THEN INDEX_TYPE ELSE NULL END AS INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:index_table AND INDEX_NAME IN ('.implode(',',$placeholders).') ORDER BY INDEX_NAME,SEQ_IN_INDEX LIMIT '.(count($group)*65),'parameters'=>$parameters];
    }

}
