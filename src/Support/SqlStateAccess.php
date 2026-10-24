<?php
declare(strict_types=1);
namespace SoSecurity\Support;

use PDO;
use SoSecurity\Account\Policy;
use SoSecurity\Account\Repository;
use SoSecurity\Account\StateAccountConnection;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

/** @internal Process-local registration, execution guards and bounded closed metadata statements. */
final class SqlStateAccess
{
    private static $connections=[];
    private static $contexts=[];
    private static $metadata=[];
    private static $metadataUnavailable=[];
    private static $ledgerUnavailable=[];
    public static function context(string $site,string $scope,string $epoch):string
    {
        return hash('sha256',json_encode([$site,$scope,$epoch],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
    }
    public static function bind(PDO $pdo,string $context,string $binding,\Closure $guard,?\SoSecurity\Account\StateBoundary $nativeBoundary=null):void
    {
        $native=$nativeBoundary!==null;
        if($nativeBoundary!==null&&$nativeBoundary->sqlGuard($pdo)!==$guard){throw new ConfigurationException('Use the exact native boundary guard.','configuration.state_connection');}
        $id=spl_object_hash($pdo);
        if(isset(self::$connections[$id])){
            $old=self::$connections[$id];
            if($old[0]!==$pdo||$old[1]!==$context||$old[2]!==$binding||$old[3]!==$guard){throw new ConfigurationException('A protected SQL connection has one exact account authority.','configuration.state_connection');}
            return;
        }
        if(count(self::$connections)>=128){throw new ConfigurationException('Use the registered account PDO and bounded process contexts.','configuration.state_connection');}
        self::$connections[$id]=[$pdo,$context,$binding,$guard,$native];self::$contexts[$context][$id]=true;
    }
    /** Pure registration query; grants no active execution authority. */
    public static function isProtected(PDO $pdo):bool{return isset(self::$connections[spl_object_hash($pdo)]);}
    /** Code identity only, never an authorization result. Native boundary guards invoke no host callbacks. */
    public static function pureEntryGuard(PDO $pdo):bool
    {
        $entry=self::$connections[spl_object_hash($pdo)]??null;return $entry===null||($entry[0]===$pdo&&($entry[4]??false)===true);
    }
    public static function assertActive(PDO $pdo,?Deadline $deadline=null):void
    {
        $entry=self::$connections[spl_object_hash($pdo)]??null;
        if($entry!==null){if($deadline!==null&&($entry[4]??false)===true){($entry[3])(false,false,$deadline);}else{($entry[3])();}}
    }
    /** Only the exact native guard supports this internal budget protocol. */
    public static function restrictDeadline(PDO $pdo,Deadline $deadline,bool $optional=false):void
    {
        $entry=self::$connections[spl_object_hash($pdo)]??null;
        if($entry!==null&&$entry[0]===$pdo&&($entry[4]??false)===true){($entry[3])(false,false,$deadline,$optional);}
    }
    /** Fixed bounded text-only root/history query; numeric metadata is explicitly cast after range guards. */
    private static function ledgerStatement(string $sql,array $parameters):bool
    {
        if(strlen($sql)>16384||count($parameters)!==1||!is_string($parameters['namespace']??null)||preg_match('/\A[a-f0-9]{64}\z/D',$parameters['namespace'])!==1
            ||preg_match('/ LIMIT (?:[1-9]|[1-5][0-9]|6[0-4])(?: FOR UPDATE)?\z/D',$sql,$suffix)!==1){return false;}
        static $prefix=null;
        if($prefix===null){
            $records=\SoSecurity\Account\Ledger::recordTypes();unset($records['payload']);
            $prefix='SELECT '.SqlSchema::boundedProjection('mysql',\SoSecurity\Account\Ledger::rootTypes(),'r','r_',true).','.SqlSchema::boundedProjection('mysql',$records,'h','h_',true).',CAST('.SqlSchema::blobLength('mysql','payload','h')." AS CHAR) AS h_body_length,CASE WHEN h.namespace IS NULL THEN '0' ELSE '1' END AS has_record FROM sosecurity_account_roots r LEFT JOIN sosecurity_account_records h ON h.namespace=r.namespace WHERE r.namespace=:namespace ORDER BY h.record_id";
        }
        return substr($sql,0,-strlen($suffix[0]))===$prefix;
    }
    /** Execute fresh metadata on an already registered PDO. Never retains rows or accepts caller statements. */
    public static function metadataRows(SqlTransaction $unit,string $sql,array $parameters,?string $ledgerDatabase=null):array
    {
        $pdo=$unit->connection();$id=spl_object_hash($pdo);
        if($unit->driver()!=='mysql'||!isset(self::$connections[$id])||self::$connections[$id][0]!==$pdo||!preg_match('/\ASELECT\b/i',$sql)){throw new ConfigurationException('Use registered read-only SQL metadata.','configuration.sql_schema');}
        $ledgerRead=$ledgerDatabase!==null;
        if($ledgerRead&&($ledgerDatabase===''||strlen($ledgerDatabase)>256||strpos($ledgerDatabase,"\0")!==false||!$unit->canBatchLedgerReads()||!self::ledgerStatement($sql,$parameters))){throw new ConfigurationException('Use the just-verified native ledger database.','configuration.sql_schema');}
        $unit->now();$key=null;$class=null;$fetch=[];$query=null;
        $fixedVariable=$parameters===[]&&in_array($sql,['SELECT @@GLOBAL.innodb_flush_log_at_trx_commit','SELECT @@SESSION.innodb_lock_wait_timeout','SELECT @@SESSION.lock_wait_timeout','SELECT @@SESSION.innodb_lock_wait_timeout AS row_wait,@@SESSION.lock_wait_timeout AS metadata_wait'],true);
        $ledgerContext=false;
        if(strpos($sql,'SELECT _sosecurity_context.* FROM (')===0&&$unit->canBatchLedgerReads()){
            $fixed=SqlSchema::ledgerContextStatement();$ledgerContext=$sql===$fixed['sql']&&$parameters===$fixed['parameters'];
        }
        $snapshotMetadata=false;$count=count($parameters);
        if(strpos($sql,'SELECT _sosecurity_snapshot_schema.section AS section,')===0&&$count>=2&&$count<=8&&$count%2===0&&$unit->canBatchLedgerReads()){
            $tables=[];$valid=true;
            for($index=0;$index<$count/2;++$index){$table=$parameters['table_'.$index]??null;if(!is_string($table)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$table)){ $valid=false;break;}$tables[]=$table;}
            if($valid&&count(array_unique($tables))===count($tables)){$fixed=SqlSchema::snapshotMetadataStatement($tables,true);$snapshotMetadata=$sql===$fixed['sql']&&$parameters===$fixed['parameters'];}
        }
        $fixedVariableText=false;
        if($fixedVariable&&$unit->canBatchLedgerReads()){
            try{$pdo->getAttribute(PDO::ATTR_STRINGIFY_FETCHES);}catch(\Throwable $error){$fixedVariableText=true;}
        }
        $textRead=$ledgerRead||$ledgerContext||$snapshotMetadata||$fixedVariableText;
        // These exact fixed reads return only text/NULL; STRINGIFY_FETCHES cannot change their format.
        // Generic metadata keeps all original capability and fetching-format checks.
        $available=$textRead?!isset(self::$ledgerUnavailable[$id]):!isset(self::$metadataUnavailable[$id]);
        if($available&&strlen($sql)<=16384&&count($parameters)<=32&&(strpos($sql,'information_schema.COLUMNS')!==false||strpos($sql,'information_schema.STATISTICS')!==false||($fixedVariable&&get_class($pdo)===PDO::class)||$ledgerRead||$ledgerContext)){
            $names=array_keys($parameters);$valid=true;foreach($parameters as $name=>$value){if(!is_string($name)||!preg_match('/\A[a-z_][a-z0-9_]{0,63}\z/Di',$name)||(!is_null($value)&&!is_int($value)&&!is_bool($value)&&(!is_string($value)||strlen($value)>256))){$valid=false;break;}}
            if($valid){
                try{$class=$pdo->getAttribute(PDO::ATTR_STATEMENT_CLASS);$native=!$pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES)&&(int)$pdo->getAttribute(PDO::ATTR_ERRMODE)===PDO::ERRMODE_EXCEPTION;if($native&&$class===[\PDOStatement::class]){$fetch=[(int)$pdo->getAttribute(PDO::ATTR_CASE),(int)$pdo->getAttribute(PDO::ATTR_ORACLE_NULLS),$textRead?'ledger-text-v1':(bool)$pdo->getAttribute(PDO::ATTR_STRINGIFY_FETCHES)];}}catch(\Throwable $error){$class=null;$native=false;if($textRead){self::$ledgerUnavailable[$id]=true;}else{self::$metadataUnavailable[$id]=true;}unset(self::$metadata[$id]);}
                if($native&&$class===[\PDOStatement::class]){
                    if(!isset(self::$metadata[$id])||self::$metadata[$id]['class']!==$class){self::$metadata[$id]=['class'=>$class,'statements'=>[]];}
                    // Variable reads are database-independent. A ledger read receives the fresh identity
                    // directly from its immediately preceding schema/context check. Other reads still probe.
                    $database=$ledgerRead?$ledgerDatabase:($fixedVariable?'':null);
                    // DATABASE() in a prepared statement can retain its preparation database.
                    // This fresh probe MUST NOT be taken from the statement pool. Binary bytes
                    // also prevent lossy result character sets from merging different database keys.
                    if(!$fixedVariable&&!$ledgerRead){
                        $contextQuery=null;
                        try{$contextQuery=$pdo->query('SELECT CAST(DATABASE() AS BINARY)');if($contextQuery!==false){$database=$contextQuery->fetchColumn();}}catch(\Throwable $error){$database=null;}
                        if($contextQuery instanceof \PDOStatement){try{$closed=$contextQuery->closeCursor();}catch(\Throwable $error){$closed=false;}if(!$closed){throw new StorageException('Security metadata context cleanup failed.','sql.cleanup');}}
                    }
                    if(is_string($database)&&strlen($database)<=256){
                        sort($names,SORT_STRING);$key=hash('sha256',pack('N',strlen($sql)).$sql.pack('N',count($names)).implode("\0",$names)."\0".$database."\0".json_encode($fetch));
                        $query=self::$metadata[$id]['statements'][$key]??null;unset(self::$metadata[$id]['statements'][$key]);
                    }
                }else{unset(self::$metadata[$id]);}
            }
        }
        // Taking a statement removes it from the pool until its entire result has been consumed and closed.
        if($query===null){if($key!==null&&count(self::$metadata[$id]['statements'])>=8){array_shift(self::$metadata[$id]['statements']);}$query=$pdo->prepare($sql);}
        if(!($query instanceof \PDOStatement)){throw new StorageException('Cannot prepare security metadata.','sql.unavailable');}
        $failure=null;
        try{
            $unit->now();
            foreach($parameters as $name=>$value){if(!$query->bindValue(':'.$name,$value,$value===null?PDO::PARAM_NULL:(is_int($value)?PDO::PARAM_INT:PDO::PARAM_STR))){throw new StorageException('Cannot bind security metadata.','sql.unavailable');}}
            $unit->now();if(!$query->execute()){throw new StorageException('Security metadata statement failed.','sql.unavailable');}$unit->now();
            $rows=$query->fetchAll(PDO::FETCH_ASSOC);if(!is_array($rows)){throw new StorageException('Cannot read security metadata.','sql.unavailable');}
            if($fixedVariableText){$rows=self::fixedVariableRows($sql,$rows);}
        }catch(\Throwable $error){$failure=$error;}
        // Throw cleanup failure outside exception unwinding: PHP must not chain an untrusted original error.
        try{$closed=$query->closeCursor();}catch(\Throwable $error){$closed=false;}
        if(!$closed){throw new StorageException('Security metadata cursor cleanup failed.','sql.cleanup');}
        if($failure!==null){throw $failure;}
        if($key!==null&&get_class($query)===\PDOStatement::class&&isset(self::$metadata[$id])&&self::$metadata[$id]['class']===$class){
            try{$unchanged=$pdo->getAttribute(PDO::ATTR_STATEMENT_CLASS)===$class&&[(int)$pdo->getAttribute(PDO::ATTR_CASE),(int)$pdo->getAttribute(PDO::ATTR_ORACLE_NULLS),$textRead?'ledger-text-v1':(bool)$pdo->getAttribute(PDO::ATTR_STRINGIFY_FETCHES)]===$fetch&&!$pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES)&&(int)$pdo->getAttribute(PDO::ATTR_ERRMODE)===PDO::ERRMODE_EXCEPTION;}catch(\Throwable $error){$unchanged=false;}
            if($unchanged){
                if(count(self::$metadata[$id]['statements'])>=8){array_shift(self::$metadata[$id]['statements']);}
                self::$metadata[$id]['statements'][$key]=$query;
            }
        }
        return $rows;
    }
    /** The four exact variable reads have bounded non-negative integer values, independent of fetch typing. */
    private static function fixedVariableRows(string $sql,array $rows):array
    {
        $pair=$sql==='SELECT @@SESSION.innodb_lock_wait_timeout AS row_wait,@@SESSION.lock_wait_timeout AS metadata_wait';
        if(count($rows)!==1||!is_array($rows[0])||count($rows[0])!==($pair?2:1)
            ||($pair&&array_keys($rows[0])!==['row_wait','metadata_wait'])){
            throw new StorageException('Invalid fixed security SQL variable result.','sql.corrupt');
        }
        foreach($rows[0] as $name=>$value){$rows[0][$name]=(string)SqlSchema::integer($value);}
        return $rows;
    }
    public static function refusalScope(PDO $pdo):?\Closure
    {
        $entry=self::$connections[spl_object_hash($pdo)]??null;if($entry===null){return null;}
        $scope=($entry[3])(true);return $scope instanceof \Closure?$scope:null;
    }
    public static function entryGuard(PDO $pdo,Repository $accounts,string $site,string $scope,string $epoch,Clock $clock,Policy $policy,?StateAccountConnection $state):\Closure
    {
        $id=spl_object_hash($pdo);$context=self::context($site,$scope,$epoch);
        if($state===null&&(isset(self::$connections[$id])||isset(self::$contexts[$context]))){throw new ConfigurationException('Rebuild account services with their explicit protected connection.','configuration.state_connection');}
        if($state!==null){$state->validate($pdo,$accounts,$site,$scope,$epoch,$clock,$policy);}
        return static function()use($pdo,$context,$state):void{
            if($state!==null){$state->assertActive();return;}
            if(isset(self::$connections[spl_object_hash($pdo)])||isset(self::$contexts[$context])){throw new StorageException('An older account service cannot enter a protected connection.','account.state_required');}
        };
    }
}
