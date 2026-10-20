<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Fixed complete-column projections; bounded buffering and keyset pages. */
final class SqlStateSnapshot implements StateSnapshot
{
    private $dependencies;
    private $tables;
    private $fingerprint;
    private $milliseconds;
    public function __construct(PDO $pdo,string $profile,array $tables,int $milliseconds=10000)
    {
        Guard::label($profile);if(preg_match('//u',$profile)!==1||count($tables)<1||count($tables)>32){self::configuration();}
        new SqlTransaction($pdo,new SystemClock(),$milliseconds);$this->milliseconds=$milliseconds;$copy=[];
        foreach($tables as $table=>$spec){
            self::name($table);if(!is_array($spec)){self::configuration();}$shape=$spec;unset($shape['sqlite_declarations']);$keys=array_keys($shape);sort($keys);
            if($keys!==['columns','maximum_rows','primary','where']||!is_array($spec['columns'])||!is_array($spec['primary'])||!is_array($spec['where'])||count($spec['columns'])<1||count($spec['columns'])>64||count($spec['primary'])<1||count($spec['primary'])>4||count($spec['where'])>8||!is_int($spec['maximum_rows'])||$spec['maximum_rows']<1||$spec['maximum_rows']>1000000){self::configuration();}
            $columns=[];$budget=0;
            foreach($spec['columns'] as $name=>$type){self::name($name);$t=self::type($type);$columns[$name]=$type;$budget+=$t['maximum'];}
            if($budget>2097152){self::configuration();}ksort($columns);$primary=[];
            foreach($spec['primary'] as $name){self::name($name);if(!isset($columns[$name])||in_array($name,$primary,true)){self::configuration();}$t=self::type($columns[$name]);if($t['nullable']||$t['kind']==='blob'){self::configuration();}$primary[]=$name;}
            $where=[];
            foreach($spec['where'] as $name=>$value){self::name($name);if(!isset($columns[$name])){self::configuration();}$t=self::type($columns[$name]);
                if($value===null){if(!$t['nullable']){self::configuration();}}
                elseif($t['kind']==='int'){if(!is_int($value)||$value<0){self::configuration();}}
                elseif(!is_string($value)||strlen($value)>$t['maximum']||($t['kind']==='digest'&&!preg_match('/\A[a-f0-9]{64}\z/D',$value))||($t['kind']==='id'&&!preg_match('/\A[a-f0-9]{32}\z/D',$value))){self::configuration();}
                $where[$name]=$value;
            }ksort($where);
            $copy[$table]=['columns'=>$columns,'primary'=>$primary,'where'=>$where,'maximum_rows'=>$spec['maximum_rows'],'page'=>max(1,min(64,intdiv(1048576,max(1,$budget))))];
            if(array_key_exists('sqlite_declarations',$spec)){
                if($pdo->getAttribute(PDO::ATTR_DRIVER_NAME)!=='sqlite'||!is_array($spec['sqlite_declarations'])||count($spec['sqlite_declarations'])!==count($columns)){self::configuration();}$declarations=[];
                foreach($spec['sqlite_declarations'] as $name=>$declaration){if(!isset($columns[$name])){self::configuration();}$t=self::type($columns[$name]);
                    if(!is_string($declaration)||strlen($declaration)>64){self::configuration();}
                    $valid=$t['kind']==='int'?preg_match('/\A(?:INTEGER|INT|BIGINT|SMALLINT|TINYINT)\z/D',$declaration):($t['kind']==='blob'?$declaration==='BLOB':preg_match('/\A(?:TEXT|(?:CHAR|VARCHAR)\([1-9][0-9]{0,5}\))\z/D',$declaration));
                    if(!$valid){self::configuration();}$declarations[$name]=$declaration;
                }ksort($declarations);$copy[$table]['sqlite_declarations']=$declarations;
            }
        }ksort($copy);$canonical=$copy;
        foreach($canonical as &$spec){foreach($spec['where'] as &$value){if(is_string($value)){$value=['binary'=>base64_encode($value)];}}unset($value);}unset($spec);
        $this->tables=static function()use($copy):array{return $copy;};$this->fingerprint=hash('sha256','SoSecurity.State.SqlSnapshot.Profile.1.'.json_encode([$profile,$pdo->getAttribute(PDO::ATTR_DRIVER_NAME),$canonical],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        $this->dependencies=static function()use($pdo):PDO{return $pdo;};
    }
    /** @return never */
    private static function configuration():void{throw new ConfigurationException('Use exact bounded SQL snapshot declarations.','configuration.state_snapshot');}
    private static function name($value):void{if(!is_string($value)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$value)){self::configuration();}}
    private static function type($type):array
    {
        if(!is_string($type)){self::configuration();}$nullable=strpos($type,'nullable_')===0;$kind=$nullable?substr($type,9):$type;
        if($kind==='int'){return ['kind'=>'int','maximum'=>19,'nullable'=>$nullable];}
        if(in_array($kind,['digest','id'],true)){return ['kind'=>$kind,'maximum'=>$kind==='digest'?64:32,'nullable'=>$nullable];}
        if(!preg_match('/\A(bytes|blob):([1-9][0-9]{0,6})\z/D',$kind,$m)){self::configuration();}$limit=(int)$m[2];if($limit>($m[1]==='blob'?1048576:65536)){self::configuration();}return ['kind'=>$m[1],'maximum'=>$limit,'nullable'=>$nullable];
    }
    public function storageDomains():array{return [StateStorageDomain::sql($this->connection(),$this->milliseconds)];}
    /** Exact read-only profile coverage for the fixed destructive containment operation. */
    public function containsDefinition(string $table,array $columns,array $primary,array $scopeFilter):bool
    {
        $tables=($this->tables)();if(!isset($tables[$table])){return false;}$spec=$tables[$table];ksort($columns);return $spec['columns']===$columns&&$spec['primary']===$primary&&($spec['where']===[]||$spec['where']===$scopeFilter);
    }
    public function connection():PDO{return ($this->dependencies)();}
    public function fingerprint():string{return $this->fingerprint;}
    private function quote(string $value,string $driver):string{$q=chr($driver==='sqlite'?34:96);return $q.$value.$q;}
    private function table(string $name,string $driver):string{return ($driver==='sqlite'?'main.':'').$this->quote($name,$driver);}
    /** @return never */
    private static function corrupt():void{throw new StorageException('SQL state differs from its complete snapshot declaration.','account.snapshot_corrupt');}
    private function schema(SqlTransaction $u,string $table,array $spec):array
    {
        $driver=$u->driver();$schema=[];
        if($driver==='sqlite'){
            foreach(['main','temp'] as $scope){if($u->query("SELECT 1 FROM ".$scope.".sqlite_master WHERE name COLLATE NOCASE='pragma_table_info' LIMIT 1")->fetchColumn()!==false){self::corrupt();}}
            if($u->query("SELECT 1 FROM main.sqlite_master WHERE name=:name AND type='table' LIMIT 1",['name'=>$table])->fetchColumn()===false){self::corrupt();}
            $q=$u->query("SELECT CASE WHEN length(CAST(name AS BLOB))<=64 THEN name ELSE NULL END AS name,CASE WHEN length(CAST(type AS BLOB))<=128 THEN type ELSE NULL END AS storage_type,cid AS ordinal,\"notnull\" AS required,pk AS primary_position FROM main.pragma_table_info(:table,'main') LIMIT 65",['table'=>$table]);
            try{while($row=$q->fetch(PDO::FETCH_ASSOC)){
                if(!is_string($row['name'])||!is_string($row['storage_type'])){self::corrupt();}$name=$row['name'];if(!isset($spec['columns'][$name])||isset($schema[$name])){self::corrupt();}
                $t=self::type($spec['columns'][$name]);$actual=strtoupper($row['storage_type']);$expectedDeclaration=isset($spec['sqlite_declarations'])?$spec['sqlite_declarations'][$name]:($t['kind']==='int'?'INTEGER':($t['kind']==='blob'?'BLOB':'TEXT'));if($actual!==$expectedDeclaration){self::corrupt();}
                $required=SqlSchema::integer($row['required']);$pk=SqlSchema::integer($row['primary_position']);$expected=array_search($name,$spec['primary'],true);
                if($pk!==($expected===false?0:$expected+1)||($required!==($t['nullable']?0:1)&&!(!$t['nullable']&&count($spec['primary'])===1&&$pk===1&&$actual==='INTEGER'))){self::corrupt();}
                $schema[$name]=['type'=>$actual,'ordinal'=>SqlSchema::integer($row['ordinal']),'required'=>$required,'primary'=>$pk];
            }}finally{$q->closeCursor();}
        }else{
            $row=$u->query('SELECT CASE WHEN OCTET_LENGTH(ENGINE)<=32 THEN ENGINE ELSE NULL END AS engine,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table LIMIT 1',['table'=>$table])->fetch(PDO::FETCH_ASSOC);
            if(!is_array($row)||!is_string($row['engine'])||strtolower($row['engine'])!=='innodb'||$row['TABLE_TYPE']!=='BASE TABLE'){self::corrupt();}
            $q=$u->query('SELECT CASE WHEN OCTET_LENGTH(COLUMN_NAME)<=64 THEN COLUMN_NAME ELSE NULL END AS name,CASE WHEN OCTET_LENGTH(DATA_TYPE)<=64 THEN DATA_TYPE ELSE NULL END AS storage_type,CASE WHEN OCTET_LENGTH(COLUMN_TYPE)<=128 THEN COLUMN_TYPE ELSE NULL END AS declaration,CASE WHEN OCTET_LENGTH(COLLATION_NAME)<=128 THEN COLLATION_NAME ELSE NULL END AS collation_name,ORDINAL_POSITION AS ordinal,IS_NULLABLE AS nullable FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table ORDER BY ORDINAL_POSITION LIMIT 65',['table'=>$table]);
            try{while($row=$q->fetch(PDO::FETCH_ASSOC)){
                if(!is_string($row['name'])||!is_string($row['storage_type'])||!is_string($row['declaration'])||!in_array($row['nullable'],['YES','NO'],true)){self::corrupt();}$name=$row['name'];if(!isset($spec['columns'][$name])||isset($schema[$name])){self::corrupt();}
                $t=self::type($spec['columns'][$name]);$valid=$t['kind']==='int'?in_array($row['storage_type'],['tinyint','smallint','mediumint','int','bigint'],true):($t['kind']==='blob'?in_array($row['storage_type'],['tinyblob','blob','mediumblob','longblob'],true):in_array($row['storage_type'],['char','varchar','binary','varbinary','tinytext','text','mediumtext','longtext'],true));
                if(!$valid||($row['nullable']==='YES')!==$t['nullable']){self::corrupt();}
                $schema[$name]=['type'=>$row['storage_type'],'declaration'=>$row['declaration'],'collation'=>$row['collation_name'],'ordinal'=>SqlSchema::integer($row['ordinal']),'required'=>$row['nullable']==='NO'?1:0,'primary'=>0];
            }}finally{$q->closeCursor();}
            $q=$u->query("SELECT CASE WHEN OCTET_LENGTH(COLUMN_NAME)<=64 THEN COLUMN_NAME ELSE NULL END AS name,SEQ_IN_INDEX AS position,SUB_PART,NON_UNIQUE,INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table AND INDEX_NAME='PRIMARY' ORDER BY SEQ_IN_INDEX LIMIT 5",['table'=>$table]);$keys=[];
            try{while($row=$q->fetch(PDO::FETCH_ASSOC)){if(!is_string($row['name'])||$row['SUB_PART']!==null||(string)$row['NON_UNIQUE']!=='0'||$row['INDEX_TYPE']!=='BTREE'||!isset($schema[$row['name']])){self::corrupt();}$keys[]=$row['name'];$schema[$row['name']]['primary']=SqlSchema::integer($row['position']);}}finally{$q->closeCursor();}
            if($keys!==$spec['primary']){self::corrupt();}
        }
        if(count($schema)!==count($spec['columns'])){self::corrupt();}ksort($schema);
        if($driver==='sqlite'){
            $hash=hash_init('sha256');$this->frame($hash,'SoSecurity.State.SQLiteSchema.1.');$count=0;
            foreach(['main','temp'] as $scope){
                $objects=$scope==='main'?"type IN('table','index','trigger')":"type='trigger'";
                $q=$u->query("SELECT CASE WHEN length(CAST(name AS BLOB)) BETWEEN 1 AND 256 THEN name ELSE NULL END AS name,type,CASE WHEN sql IS NULL THEN 0 WHEN typeof(sql)='text' AND length(CAST(sql AS BLOB))<=16384 THEN 1 ELSE 2 END AS definition_kind,CASE WHEN typeof(sql)='text' AND length(CAST(sql AS BLOB))<=16384 THEN sql ELSE NULL END AS definition FROM ".$scope.".sqlite_master WHERE tbl_name=:table AND ".$objects." ORDER BY type COLLATE BINARY,name COLLATE BINARY LIMIT 129",['table'=>$table]);
                try{while($row=$q->fetch(PDO::FETCH_ASSOC)){
                    if(++$count>128||!is_string($row['name'])||!in_array($row['type'],['table','index','trigger'],true)){self::corrupt();}$kind=SqlSchema::integer($row['definition_kind']);
                    if($kind===2||($kind===0?$row['definition']!==null:!is_string($row['definition']))){self::corrupt();}
                    foreach([$scope,$row['type'],$row['name'],(string)$kind,$row['definition']??''] as $value){$this->frame($hash,$value);}
                }}finally{$q->closeCursor();}
            }$this->frame($hash,(string)$count);$schema['__objects']=hash_final($hash);
        }return $schema;
    }
    private function projection(string $driver,array $columns):string
    {
        $select=[];$valid=[];
        foreach($columns as $name=>$type){
            $t=self::type($type);$c=$this->quote($name,$driver);
            if($t['kind']==='int'){$p=($driver==='sqlite'?"typeof(".$c.")='integer' AND ":'').$c.'>=0 AND '.$c.'<=9223372036854775807';}
            else{$length=$driver==='sqlite'?'length(CAST('.$c.' AS BLOB))':'OCTET_LENGTH('.$c.')';$p=($driver==='sqlite'?"typeof(".$c.")='".($t['kind']==='blob'?'blob':'text')."' AND ":'').$length.'<='.$t['maximum'];$select[]='CASE WHEN '.$c.' IS NULL THEN -1 ELSE '.$length.' END AS '.$this->quote('__sw_length_'.$name,$driver);}
            $valid[]='('.($t['nullable']?$c.' IS NULL OR ':'').$p.')';$select[]='CASE WHEN '.$p.' THEN '.$c.' ELSE NULL END AS '.$c;
        }
        $select[]='CASE WHEN '.implode(' AND ',$valid).' THEN 1 ELSE 0 END AS '.$this->quote('__sw_valid',$driver);return implode(',',$select);
    }
    private function frame($hash,string $value):void{hash_update($hash,pack('N',strlen($value)));hash_update($hash,$value);}
    private function values(array $raw,array $spec,$hash,array &$normalized):array
    {
        if((string)($raw['__sw_valid']??'')!=='1'){self::corrupt();}$keys=[];$normalized=[];
        foreach($spec['columns'] as $name=>$type){
            $t=self::type($type);$value=$raw[$name];$this->frame($hash,$name);$this->frame($hash,$type);
            if($t['kind']==='int'){if($value===null&&$t['nullable']){$normalized[$name]=null;hash_update($hash,'N');continue;}$value=SqlSchema::integer($value);$canonical=(string)$value;}
            else{$length=$raw['__sw_length_'.$name];if((string)$length==='-1'){if(!$t['nullable']||$value!==null){self::corrupt();}$normalized[$name]=null;hash_update($hash,'N');continue;}$length=SqlSchema::integer($length);if($length>$t['maximum']){self::corrupt();}$value=$value===null&&$length===0?'':$value;
                if(!is_string($value)||strlen($value)!==$length||($t['kind']==='digest'&&!preg_match('/\A[a-f0-9]{64}\z/D',$value))||($t['kind']==='id'&&!preg_match('/\A[a-f0-9]{32}\z/D',$value))){self::corrupt();}$canonical=$value;
            }
            $normalized[$name]=$value;hash_update($hash,'V');$this->frame($hash,$canonical);if(in_array($name,$spec['primary'],true)){$keys[$name]=$value;}
        }
        return $keys;
    }
    private function rows(SqlTransaction $u,string $name,array $spec,$hash,array $selectors,array &$captured,array &$pages):void
    {
        $parent=$hash;$hash=hash_init('sha256');hash_update($hash,'SoSecurity.State.SqlSnapshot.Rows.1.');$driver=$u->driver();$table=$this->table($name,$driver);$after=null;$count=0;
        do{
            $where=[];$parameters=[];$blobs=[];
            foreach($spec['where'] as $field=>$value){$parameter='filter_'.count($parameters);$where[]=$this->quote($field,$driver).($value===null?' IS NULL':'=:'.$parameter);if($value!==null){$parameters[$parameter]=$value;if(self::type($spec['columns'][$field])['kind']==='blob'){$blobs[]=$parameter;}}}
            if($after!==null){$later=[];foreach($spec['primary'] as $i=>$field){$term=[];for($j=0;$j<=$i;++$j){$key=$spec['primary'][$j];$parameter='after_'.$i.'_'.$j;$term[]=$this->quote($key,$driver).($j===$i?'>':'=').':'.$parameter;$parameters[$parameter]=$after[$key];}$later[]='('.implode(' AND ',$term).')';}$where[]='('.implode(' OR ',$later).')';}
            $limit=min($spec['page'],$spec['maximum_rows']-$count+1);$order=[];foreach($spec['primary'] as $field){$order[]=$table.'.'.$this->quote($field,$driver).' ASC';}
            $q=$u->query('SELECT '.$this->projection($driver,$spec['columns']).' FROM '.$table.($where?' WHERE '.implode(' AND ',$where):'').' ORDER BY '.implode(',',$order).' LIMIT '.$limit,$parameters,$blobs);$fetched=0;
            try{while($row=$q->fetch(PDO::FETCH_ASSOC)){++$fetched;if(++$count>$spec['maximum_rows']){throw new StorageException('SQL snapshot row capacity exceeded.','account.snapshot_capacity');}$part=hash_init('sha256');$normalized=[];$after=$this->values($row,$spec,$part,$normalized);hash_update($hash,hash_final($part,true));
                foreach($selectors as $alias=>$selector){if($selector['table']!==$name){continue;}$matches=true;foreach($selector['key'] as $field=>$value){if($after[$field]!==$value){$matches=false;break;}}if($matches&&isset($selector['page'])){foreach($selector['filter'] as $field=>$value){if($normalized[$field]!==$value){$matches=false;break;}}}if(!$matches){continue;}
                    if(isset($selector['page'])){
                        ++$pages[$alias]['total'];
                        if(!$pages[$alias]['started']){$at=true;foreach($spec['primary'] as $field){if($after[$field]!==$selector['after'][$field]){$at=false;break;}}if($at){$pages[$alias]['started']=true;}continue;}
                        if(count($pages[$alias]['rows'])<$selector['maximum']){$selected=[];foreach($selector['columns'] as $column){$selected[$column]=$normalized[$column];}$pages[$alias]['rows'][]=$selected;$cursor=[];foreach($spec['primary'] as $field){$cursor[$field]=$after[$field];}$pages[$alias]['cursor']=$cursor;}
                        else{$pages[$alias]['more']=true;}continue;
                    }
                    if(isset($selector['count'])){++$captured[$alias]['count'];continue;}
                    if($captured[$alias]!==null){self::corrupt();}$selected=[];foreach($selector['columns'] as $column){$selected[$column]=$normalized[$column];}$captured[$alias]=$selected;
                }$u->now();}}finally{$q->closeCursor();}
        }while($fetched===$limit);
        $this->frame($hash,(string)$count);$this->frame($parent,hash_final($hash,true));
    }
    private function scan(array $selectors):array
    {
        $u=new SqlTransaction($this->connection(),new SystemClock(),$this->milliseconds);$deadline=new Deadline($this->milliseconds);
        return $u->run(function()use($u,$selectors):array{
            $captured=array_fill_keys(array_keys($selectors),null);$pages=[];foreach($selectors as $alias=>$selector){if(isset($selector['count'])){$captured[$alias]=['count'=>0];}if(isset($selector['page'])){unset($captured[$alias]);$pages[$alias]=['rows'=>[],'total'=>0,'limit'=>$selector['maximum'],'more'=>false,'cursor'=>$selector['after'],'started'=>$selector['after']===null];}}
            SqlSchema::durable($u);$hash=hash_init('sha256');$this->frame($hash,'SoSecurity.State.SqlSnapshot.1.');$this->frame($hash,$this->fingerprint);
            if($u->driver()==='mysql'){$isolation=$u->query('SELECT @@SESSION.transaction_isolation')->fetchColumn();if($isolation!=='REPEATABLE-READ'){throw new ConfigurationException('SQL snapshot sources require explicit repeatable-read isolation.','configuration.state_snapshot_isolation');}$database=$u->query('SELECT CASE WHEN OCTET_LENGTH(DATABASE()) BETWEEN 1 AND 64 THEN DATABASE() ELSE NULL END')->fetchColumn();if(!is_string($database)){self::corrupt();}$this->frame($hash,$database);}
            foreach(($this->tables)() as $name=>$spec){$this->frame($hash,$name);$schema=$this->schema($u,$name,$spec);$this->frame($hash,json_encode($schema,JSON_UNESCAPED_SLASHES));$this->rows($u,$name,$spec,$hash,$selectors,$captured,$pages);if($this->schema($u,$name,$spec)!==$schema){throw new StorageException('SQL schema changed during snapshot.','account.snapshot_changed');}}
            foreach($pages as &$page){if(!$page['started']){throw new StorageException('SQL capture cursor is absent from this exact snapshot.','account.snapshot_cursor');}unset($page['started']);}unset($page);
            return [hash_final($hash),$captured,$pages];
        },null,null,null,$deadline);
    }
    /** Pure bounded selector normalization; no SQL reads or writes. */
    public function selections(array $selectors):array
    {
        if(count($selectors)<1||count($selectors)>8){self::configuration();}$tables=($this->tables)();$copy=[];$total=0;
        foreach($selectors as $alias=>$selector){
            self::name($alias);if(!is_array($selector)){self::configuration();}$shape=array_keys($selector);sort($shape);$count=array_key_exists('count',$selector);$page=array_key_exists('page',$selector);
            if(($count&&$page)||$shape!==($page?(array_key_exists('filter',$selector)?['after','columns','filter','key','maximum','page','table']:['after','columns','key','maximum','page','table']):($count?['columns','count','key','table']:['columns','key','table']))||($count&&$selector['count']!==true)||($page&&($selector['page']!==true||!is_int($selector['maximum'])||$selector['maximum']<1||$selector['maximum']>8))||!is_string($selector['table'])||!isset($tables[$selector['table']])||!is_array($selector['key'])||!is_array($selector['columns'])||($count?$selector['columns']!==[]:(count($selector['columns'])<1||count($selector['columns'])>16))){self::configuration();}
            $table=$selector['table'];$spec=$tables[$table];$actual=array_keys($selector['key']);sort($actual);$primary=($count||$page)?array_slice($spec['primary'],0,count($actual)):$spec['primary'];$expected=$primary;sort($expected);
            if(!$actual||$actual!==$expected||count($actual)>count($spec['primary'])){self::configuration();}$key=[];
            foreach($primary as $column){$value=$selector['key'][$column];$t=self::type($spec['columns'][$column]);
                if($t['kind']==='int'){if(!is_int($value)||$value<0){self::configuration();}}
                elseif(!is_string($value)||strlen($value)>$t['maximum']||($t['kind']==='digest'&&!preg_match('/\A[a-f0-9]{64}\z/D',$value))||($t['kind']==='id'&&!preg_match('/\A[a-f0-9]{32}\z/D',$value))){self::configuration();}$key[$column]=$value;
            }
            // A physical prefix count must never silently omit matching rows due
            // to additional source filters. Every filter must be implied by the prefix.
            $filter=[];
            if($page&&array_key_exists('filter',$selector)){
                if(!is_array($selector['filter'])||count($selector['filter'])>4){self::configuration();}
                foreach($selector['filter'] as $field=>$value){
                    if(!is_string($field)||!isset($spec['columns'][$field])||in_array($field,$spec['primary'],true)){self::configuration();}$t=self::type($spec['columns'][$field]);
                    if($value===null){if(!$t['nullable']){self::configuration();}}
                    elseif($t['kind']==='int'){if(!is_int($value)||$value<0){self::configuration();}}
                    elseif(!is_string($value)||strlen($value)>min(4096,$t['maximum'])||($t['kind']==='digest'&&preg_match('/\A[a-f0-9]{64}\z/D',$value)!==1)||($t['kind']==='id'&&preg_match('/\A[a-f0-9]{32}\z/D',$value)!==1)){self::configuration();}
                    $filter[$field]=$value;
                }ksort($filter);
            }
            if($count||$page){$coverage=$key+$filter;foreach($spec['where'] as $field=>$value){if(!array_key_exists($field,$coverage)||$coverage[$field]!==$value){self::configuration();}}}

            ksort($key);$columns=[];$size=$count?19:0;
            foreach($selector['columns'] as $column){if(!is_string($column)||!isset($spec['columns'][$column])||in_array($column,$columns,true)){self::configuration();}$columns[]=$column;$size+=self::type($spec['columns'][$column])['maximum'];}
            if($size>65536){self::configuration();}
            $cursor=null;
            if($page){
                if($selector['after']!==null){if(!is_array($selector['after'])){self::configuration();}$point=$this->selections(['cursor'=>['table'=>$table,'key'=>$selector['after'],'columns'=>[$spec['primary'][0]]]]);$cursor=[];foreach($spec['primary'] as $field){$cursor[$field]=$point['cursor']['key'][$field];}foreach($key as $field=>$value){if($cursor[$field]!==$value){self::configuration();}}}
                $cursorSize=0;foreach($spec['primary'] as $field){$cursorSize+=self::type($spec['columns'][$field])['maximum'];}if($cursorSize>65536){self::configuration();}$size=$size*$selector['maximum']+$cursorSize;
            }
            $total+=$size;if($total>262144){self::configuration();}$copy[$alias]=['table'=>$table,'key'=>$key,'columns'=>$columns];if($count){$copy[$alias]['count']=true;}if($page){$copy[$alias]['page']=true;$copy[$alias]['maximum']=$selector['maximum'];$copy[$alias]['after']=$cursor;$copy[$alias]['filter']=$filter;}
        }
        return $copy;
    }
    /** Values are copied from the exact rows included in this full digest, never re-read afterwards. */
    public function capture(array $selectors):SqlStateCapture
    {
        $result=$this->scan($this->selections($selectors));return new SqlStateCapture($this,$result[0],$result[1],$result[2]);
    }
    public function digest():string{return $this->scan([])[0];}
    public function __debugInfo():array{return ['sql_state_snapshot'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload explicit state snapshot declarations.','configuration.state_snapshot');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize SQL state sources.','configuration.state_snapshot');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State sources are immutable.','configuration.immutable');}
}
