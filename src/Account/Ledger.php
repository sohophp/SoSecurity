<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;

/** Internal transaction participant. Caller supplies authority and owns the complete account/business transaction. */
final class Ledger
{
    private $namespace;
    private $dependencies;
    public function __construct(SqlTransaction $unit,string $site,string $scope,string $epoch,HmacKeys $keys,Policy $policy,int $format=1,?string $authority=null)
    {
        foreach([$site,$scope] as $label){Guard::label($label);if(preg_match('//u',$label)!==1){throw new ConfigurationException('Use UTF-8 account ledger labels.','configuration.account_ledger');}}
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)){throw new ConfigurationException('Use a trusted external account epoch.','configuration.account_ledger');}
        if(!in_array($format,[1,2],true)||($format===1?$authority!==null:(!is_string($authority)||!preg_match('/\A[a-f0-9]{64}\z/D',$authority)))){throw new ConfigurationException('Bind fenced ledgers to one authority.','configuration.account_ledger');}
        $this->namespace=hash('sha256',json_encode(['SoSecurity.Account.Ledger.1',$site,$scope,$epoch],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        $this->dependencies=static function()use($unit,$epoch,$keys,$policy,$format,$authority,$site,$scope):array{return [$unit,$epoch,$keys,$policy,$format,$authority,$site,$scope];};
    }
    private function unit():SqlTransaction {return ($this->dependencies)()[0];}
    private function epoch():string {return ($this->dependencies)()[1];}
    private function keys():HmacKeys {return ($this->dependencies)()[2];}
    private function policy():Policy {return ($this->dependencies)()[3];}
    private function format():int {return ($this->dependencies)()[4];}
    private function policyDigest():string {$d=($this->dependencies)();return $d[4]===1?$d[3]->fingerprint():hash('sha256','SoSecurity.Account.FencedLedger.2.'.$d[3]->fingerprint().$d[5]);}
    private function table(bool $root=false):string {return $this->unit()->prefix().'sosecurity_account_'.($root?'roots':'records');}
    private function lock():string {return $this->unit()->driver()==='mysql'&&!$this->unit()->isObservation()?' FOR UPDATE':'';}
    public static function rootTypes():array {return ['namespace'=>'digest','format'=>'int','epoch'=>'digest','policy'=>'digest','entries'=>'int','revision'=>'int','history_digest'=>'digest','created_at'=>'int','observed_at'=>'int','seal_key'=>'bytes:32','seal'=>'digest'];}
    public static function recordTypes():array {return ['namespace'=>'digest','record_id'=>'digest','owner'=>'digest','kind'=>'bytes:16','revision'=>'int','created_at'=>'int','retire_at'=>'int','updated_at'=>'int','payload_bytes'=>'int','payload_digest'=>'digest','seal_key'=>'bytes:32','seal'=>'digest','payload'=>'blob'];}
    public static function indexes():array {return ['sosecurity_account_owner'=>['unique'=>false,'columns'=>['namespace','owner','kind','created_at','record_id']],'sosecurity_account_retention'=>['unique'=>false,'columns'=>['namespace','retire_at','record_id']]];}
    private function columns(bool $root=false):string {$types=$root?self::rootTypes():self::recordTypes();unset($types['payload']);return SqlSchema::boundedProjection($this->unit()->driver(),$types);}
    private function bytes():string {return SqlSchema::blobLength($this->unit()->driver(),'payload');}
    public function verifySchema():void {$this->schemaDatabase();}
    /** The fresh database identity is passed directly to the next private read, never retained. */
    private function schemaDatabase():?string
    {
        if(!$this->unit()->isObservation()){\SoSecurity\Support\SqlStateAccess::assertActive($this->unit()->connection());}
        $context=$this->unit()->verifyLedgerSchema();return $context['database']??null;
    }
    private function checkedRoot(bool $optional=false,?string $selectedId=null,?array &$selected=null):?array
    {
        $database=$this->schemaDatabase();return $this->root($optional,$selectedId,$selected,$database);
    }
    /** @return never */
    private static function corrupt():void {throw new StorageException('Account ledger state cannot be authenticated.','account.corrupt');}
    private function encoded(array $row,bool $root):string {return LedgerState::encoded($row,$root);}
    private function sign(array $row,bool $root):array {$row['seal_key']=$this->keys()->currentId();$row['seal']=bin2hex($this->keys()->sign($this->encoded($row,$root)));return $row;}
    private function authenticated(array $row,bool $root):array
    {
        $row=LedgerState::metadata($row,$root,$this->namespace,$this->keys());
        return LedgerState::observe($row,$root,$this->epoch(),$this->policyDigest(),$this->format(),$this->policy()->maximumEntries(),$this->unit()->now());
    }
    /** Exact primary-key or LIMIT 1 reads; close and poison through the owning SQL unit.
     * @return array|false
     */
    private function first(string $sql,array $parameters)
    {
        $rows=$this->unit()->metadataRows($sql,$parameters);if(count($rows)>1){self::corrupt();}return $rows[0]??false;
    }
    private function history(?string $selectedId=null,?array &$selected=null,?array $initialRows=null):array
    {
        $selected=null;$hash=hash_init('sha256');hash_update($hash,'SoSecurity.Account.History.1.'.$this->namespace);$count=0;$cursor=null;
        do{
            $limit=min(64,$this->policy()->maximumEntries()+1-$count);$args=['namespace'=>$this->namespace];if($cursor!==null){$args['cursor']=$cursor;}
            $rows=$initialRows??$this->unit()->metadataRows('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace'.($cursor===null?'':' AND record_id>:cursor').' ORDER BY '.$this->table().'.record_id LIMIT '.$limit.$this->lock(),$args);$initialRows=null;
            foreach($rows as $raw){$row=$this->authenticated($raw,false);if($row['record_id']===$selectedId){if($selected!==null){self::corrupt();}$selected=$row;}if(++$count>$this->policy()->maximumEntries()){self::corrupt();}hash_update($hash,$row['record_id'].$row['seal']);$cursor=$row['record_id'];}
        }while(count($rows)===$limit);
        return ['entries'=>$count,'digest'=>hash_final($hash)];
    }
    private function batchPart(array $row,bool $root):array
    {
        $types=$root?self::rootTypes():self::recordTypes();unset($types['payload']);$names=array_keys($types);if(!$root){$names[]='body_length';}$prefix=$root?'r_':'h_';$result=[];
        foreach($names as $name){if(!array_key_exists($prefix.$name,$row)){self::corrupt();}$result[$name]=$row[$prefix.$name];}return $result;
    }
    private function root(bool $optional=false,?string $selectedId=null,?array &$selected=null,?string $database=null):?array
    {
        $joined=null;$initialRows=null;
        if($this->unit()->canBatchLedgerReads()){
            $records=self::recordTypes();unset($records['payload']);$limit=min(64,$this->policy()->maximumEntries()+1);$text=$database!==null&&\SoSecurity\Support\SqlStateAccess::isProtected($this->unit()->connection());$length=SqlSchema::blobLength('mysql','payload','h');
            $sql='SELECT '.SqlSchema::boundedProjection('mysql',self::rootTypes(),'r','r_',$text).','.SqlSchema::boundedProjection('mysql',$records,'h','h_',$text).','.($text?'CAST('.$length.' AS CHAR)':$length).' AS h_body_length,CASE WHEN h.namespace IS NULL THEN '.($text?"'0' ELSE '1'":'0 ELSE 1').' END AS has_record FROM '.$this->table(true).' r LEFT JOIN '.$this->table().' h ON h.namespace=r.namespace WHERE r.namespace=:namespace ORDER BY h.record_id LIMIT '.$limit.$this->lock();
            $joined=$this->unit()->metadataRows($sql,['namespace'=>$this->namespace],$text?$database:null);$raw=$joined===[]?false:$this->batchPart($joined[0],true);
        }else{$raw=$this->first('SELECT '.$this->columns(true).' FROM '.$this->table(true).' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$this->namespace]);}
        if($raw===false){if($optional){return null;}throw new StorageException('Account ledger requires explicit initialization.','account.uninitialized');}
        $root=$this->authenticated($raw,true);
        if($joined!==null){
            $initialRows=[];
            foreach($joined as $row){
                if(count($row)!==count(self::rootTypes())+count(self::recordTypes())+1||$this->batchPart($row,true)!==$raw||!array_key_exists('has_record',$row)){self::corrupt();}
                $record=$this->batchPart($row,false);$present=SqlSchema::integer($row['has_record']);
                if($present===1){$initialRows[]=$record;}elseif($present!==0||count($joined)!==1){self::corrupt();}
            }
        }
        $actual=$this->history($selectedId,$selected,$initialRows);if($root['entries']!==$actual['entries']||!hash_equals($root['history_digest'],$actual['digest'])){self::corrupt();}return $root;
    }
    private function sync(array $root,bool $insert=false):array
    {
        if($root['revision']>=PHP_INT_MAX-1){throw new StorageException('Account ledger revision exhausted.','account.capacity');}
        $history=$this->history();$root['entries']=$history['entries'];$root['history_digest']=$history['digest'];++$root['revision'];$root['observed_at']=$this->unit()->now();$root=$this->sign($root,true);$fields=array_keys(self::rootTypes());
        $sql=$insert?'INSERT INTO '.$this->table(true).'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->table(true).' SET '.implode(',',array_map(static function(string $field):string{return $field.'=:'.$field;},array_diff($fields,['namespace']))).' WHERE namespace=:namespace';
        $this->unit()->execute($sql,$root);if($this->root()!==$root){self::corrupt();}return $root;
    }
    public function initialize():bool
    {
        if($this->checkedRoot(true)!==null){return false;}
        if($this->unit()->metadataRows('SELECT 1 FROM '.$this->table().' WHERE namespace=:namespace LIMIT 1',['namespace'=>$this->namespace])!==[]){throw new StorageException('Do not adopt orphaned account history.','account.uninitialized');}
        $now=$this->unit()->now();$this->sync(['namespace'=>$this->namespace,'format'=>$this->format(),'epoch'=>$this->epoch(),'policy'=>$this->policyDigest(),'entries'=>0,'revision'=>0,'history_digest'=>hash('sha256','SoSecurity.Account.History.1.'.$this->namespace),'created_at'=>$now,'observed_at'=>$now,'seal_key'=>$this->keys()->currentId(),'seal'=>str_repeat('0',64)],true);return true;
    }
    private static function id(string $value):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$value)){throw new ConfigurationException('Use a fixed opaque account ledger ID.','configuration.account_ledger');}}
    private function record(string $id):?array
    {
        self::id($id);$raw=$this->first('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace AND record_id=:id LIMIT 1'.$this->lock(),['namespace'=>$this->namespace,'id'=>$id]);return $raw===false?null:$this->authenticated($raw,false);
    }
    private function body(array $row):string
    {
        $raw=$this->first('SELECT payload,'.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace AND record_id=:id AND '.$this->bytes().'=:bytes LIMIT 1'.$this->lock(),['namespace'=>$this->namespace,'id'=>$row['record_id'],'bytes'=>$row['payload_bytes']]);
        if(!is_array($raw)||SqlSchema::integer($raw['body_length'])!==$row['payload_bytes']){self::corrupt();}$body=$raw['payload']===null&&$row['payload_bytes']===0?'':$raw['payload'];
        return LedgerState::payload($row,$body);
    }
    /**
     * Reuse only the authenticated metadata from this complete history scan; never cache across calls.
     * @phpstan-impure
     */
    public function read(string $id):?array {self::id($id);$row=null;$this->checkedRoot(false,$id,$row);return $row===null?null:$row+['payload'=>$this->body($row)];}
    /** Internal paired initial read; keep the original checkpoint before the SDK's intervening read.
     * Host I/O in $beforeBody must use the owning unit's invoke() as usual.
     * @param-immediately-invoked-callable $beforeBody
     * @phpstan-impure
     */
    public function readCheckpoint(string $id,?callable $beforeBody=null):array
    {
        self::id($id);$row=null;$root=$this->checkedRoot(false,$id,$row);
        $context=null;
        if($beforeBody!==null){$context=$beforeBody();$this->verifySchema();}
        return ['checkpoint'=>$root,'row'=>$row===null?null:$row+['payload'=>$this->body($row)],'context'=>$context];
    }
    /** Internal paired read: authenticate the full history once and reject a changed checkpoint before body I/O.
     * @phpstan-impure
     */
    public function readIfCheckpoint(string $id,array $expected):?array
    {
        self::id($id);$row=null;$root=$this->checkedRoot(false,$id,$row);
        if($root!==$expected||$row===null){return null;}
        return $row+['payload'=>$this->body($row)];
    }
    public function latest(string $owner,string $kind):?array
    {
        self::id($owner);$this->checkedRoot();if(!in_array($kind,['register','change','recover','notice','budget'],true)){throw new ConfigurationException('Use a fixed account ledger kind.','configuration.account_ledger');}
        $raw=$this->first('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace AND owner=:owner AND kind=:kind ORDER BY '.$this->table().'.created_at DESC,'.$this->table().'.record_id DESC LIMIT 1'.$this->lock(),['namespace'=>$this->namespace,'owner'=>$owner,'kind'=>$kind]);
        if($raw===false){return null;}$row=$this->authenticated($raw,false);return $row+['payload'=>$this->body($row)];
    }
    public function put(string $id,string $owner,string $kind,string $payload,int $retireAt,?int $expectedRevision=null):array
    {
        self::id($id);self::id($owner);
        if(!in_array($kind,['register','change','recover','notice','budget'],true)||strlen($payload)>16384||$retireAt<0){throw new ConfigurationException('Use bounded account ledger records.','configuration.account_ledger');}
        $root=$this->checkedRoot();$existing=$this->record($id);$now=$this->unit()->now();
        if(($existing===null)!==($expectedRevision===null)||($existing!==null&&($existing['revision']!==$expectedRevision||$existing['owner']!==$owner||$existing['kind']!==$kind))){throw new StorageException('Account ledger revision conflict.','account.conflict');}
        if($existing!==null){$this->body($existing);}elseif($root['entries']>=$this->policy()->maximumEntries()){throw new StorageException('Account ledger capacity exhausted.','account.capacity');}
        $created=$existing===null?$now:$existing['created_at'];$revision=$existing===null?1:$existing['revision']+1;
        if($revision>=PHP_INT_MAX||$retireAt<$created||$retireAt-($kind==='budget'?$now:$created)>1209600){throw new ConfigurationException('Account retention/revision exceeds its bounds.','configuration.account_ledger');}
        $row=$this->sign(['namespace'=>$this->namespace,'record_id'=>$id,'owner'=>$owner,'kind'=>$kind,'revision'=>$revision,'created_at'=>$created,'retire_at'=>$retireAt,'updated_at'=>$now,'payload_bytes'=>strlen($payload),'payload_digest'=>hash('sha256',$payload),'seal_key'=>$this->keys()->currentId(),'seal'=>str_repeat('0',64)],false);$fields=array_keys(self::recordTypes());
        $sql=$existing===null?'INSERT INTO '.$this->table().'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->table().' SET '.implode(',',array_map(static function(string $field):string{return $field.'=:'.$field;},array_diff($fields,['namespace','record_id']))).' WHERE namespace=:namespace AND record_id=:record_id';
        $this->unit()->execute($sql,$row+['payload'=>$payload],['payload']);if($this->record($id)!==$row||$this->body($row)!==$payload){self::corrupt();}$this->sync($root);return $row+['payload'=>$payload];
    }
    /** Authenticated metadata only. Cursor denotes physical-key progress, not a stable snapshot across transactions. */
    public function page(int $limit=20,string $after=''):array
    {
        if($limit<1||$limit>50){throw new ConfigurationException('Use an account maintenance page of 1-50 records.','configuration.account_maintenance');}if($after!==''){self::id($after);}
        $this->checkedRoot();$arguments=['namespace'=>$this->namespace];if($after!==''){$arguments['after']=$after;}
        $raw=$this->unit()->metadataRows('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace'.($after===''?'':' AND record_id>:after').' ORDER BY '.$this->table().'.record_id LIMIT '.$limit.$this->lock(),$arguments);
        $rows=[];foreach($raw as $row){$rows[]=$this->authenticated($row,false);}return $rows;
    }
    /** Bounded body page. Membership is authenticated once; never read() each selected ID. */
    public function bodyPage(int $limit=20,string $after=''):array
    {
        $rows=$this->page($limit,$after);$result=[];foreach($rows as $row){$result[]=$row+['payload'=>$this->body($row)];}return $result;
    }
    /** Selected current snapshots in one locked view, including explicit missing rows. */
    public function readMany(array $ids):array
    {
        if(!$ids||count($ids)>100){throw new ConfigurationException('Read 1-100 unique account IDs.','configuration.account_maintenance');}
        foreach($ids as $id){if(!is_string($id)){throw new ConfigurationException('Use exact account IDs.','configuration.account_maintenance');}self::id($id);}
        if(count(array_unique($ids,SORT_STRING))!==count($ids)){throw new ConfigurationException('Use unique account IDs.','configuration.account_maintenance');}
        $root=$this->checkedRoot();$rows=[];
        foreach($ids as $id){$row=$this->record($id);$rows[$id]=$row===null?null:$row+['payload'=>$this->body($row)];}
        if($this->root()!==$root){self::corrupt();}return $rows;
    }
    /** Cryptographic maintenance only. Preserve payload, creation/update/retention timestamps and ownership. */
    public function reseal(array $expected):int
    {
        if(!$expected||count($expected)>100){throw new ConfigurationException('Reseal 1-100 exact account records.','configuration.account_maintenance');}
        foreach($expected as $id=>$revision){if(!is_string($id)||!is_int($revision)||$revision<1||$revision>=PHP_INT_MAX){throw new ConfigurationException('Use exact account revisions.','configuration.account_maintenance');}self::id($id);}
        $root=$this->checkedRoot();$updates=[];
        foreach($expected as $id=>$revision){
            $row=$this->record($id);if($row===null||$row['revision']!==$revision){throw new StorageException('Account reseal revision changed.','account.conflict');}$this->body($row);
            if($row['seal_key']===$this->keys()->currentId()){continue;}
            if($revision>=PHP_INT_MAX-1){throw new StorageException('Account record revision exhausted.','account.capacity');}++$row['revision'];$updates[$id]=$this->sign($row,false);
        }
        foreach($updates as $id=>$row){
            $count=$this->unit()->execute('UPDATE '.$this->table().' SET revision=:revision,seal_key=:seal_key,seal=:seal WHERE namespace=:namespace AND record_id=:id AND revision=:previous',['revision'=>$row['revision'],'seal_key'=>$row['seal_key'],'seal'=>$row['seal'],'namespace'=>$this->namespace,'id'=>$id,'previous'=>$expected[$id]]);if($count!==1||$this->record($id)!==$row){self::corrupt();}
        }
        if($updates){$this->sync($root);}return count($updates);
    }
    /** Internal CAS batch. Authenticate every body before deleting anything; no implicit expiry or permission decisions. */
    public function remove(array $expected):int
    {
        if(!$expected||count($expected)>100){throw new ConfigurationException('Remove 1-100 explicitly selected account records.','configuration.account_maintenance');}
        $validated=[];foreach($expected as $id=>$revision){if(!is_string($id)||!is_int($revision)||$revision<1||$revision>=PHP_INT_MAX){throw new ConfigurationException('Use exact account revisions.','configuration.account_maintenance');}self::id($id);$validated[$id]=$revision;}
        $root=$this->checkedRoot();
        foreach($validated as $id=>$revision){$row=$this->record($id);if($row===null||$row['revision']!==$revision){throw new StorageException('Account cleanup revision changed.','account.conflict');}$this->body($row);}
        foreach($validated as $id=>$revision){$count=$this->unit()->execute('DELETE FROM '.$this->table().' WHERE namespace=:namespace AND record_id=:id AND revision=:revision',['namespace'=>$this->namespace,'id'=>$id,'revision'=>$revision]);if($count!==1||$this->record($id)!==null){self::corrupt();}}
        $this->sync($root);return count($validated);
    }
    /** Digest only; callers must obtain and retain trusted checkpoints independently of business backups. */
    public static function digest(array $checkpoint):string
    {
        if(count($checkpoint)!==count(self::rootTypes())||array_keys($checkpoint)!==array_keys(self::rootTypes())){throw new ConfigurationException('Use a complete authenticated root checkpoint.','configuration.account_checkpoint');}
        foreach(self::rootTypes() as $field=>$type){
            $value=$checkpoint[$field];
            if($type==='int'){if(!is_int($value)||$value<0){throw new ConfigurationException('Use typed checkpoint integers.','configuration.account_checkpoint');}}
            elseif(!is_string($value)||strlen($value)>($type==='digest'?64:32)||($type==='digest'?preg_match('/\A[a-f0-9]{64}\z/D',$value)!==1:preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$value)!==1)){throw new ConfigurationException('Use bounded checkpoint fields.','configuration.account_checkpoint');}
        }
        $json=json_encode($checkpoint,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        if(!is_string($json)||strlen($json)>4096){throw new ConfigurationException('Use a bounded root checkpoint.','configuration.account_checkpoint');}
        return hash('sha256','SoSecurity.Account.Checkpoint.1.'.$json);
    }
    /** Authenticate every body in one locked view, with bounded pages and linear work; never call read() per row. */
    public function verifyBodies():array
    {
        $root=$this->checkedRoot();$cursor=null;$count=0;
        do{
            $arguments=['namespace'=>$this->namespace];if($cursor!==null){$arguments['after']=$cursor;}
            $rows=$this->unit()->metadataRows('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace'.($cursor===null?'':' AND record_id>:after').' ORDER BY '.$this->table().'.record_id LIMIT 64'.$this->lock(),$arguments);
            foreach($rows as $raw){$row=$this->authenticated($raw,false);if(++$count>$this->policy()->maximumEntries()){self::corrupt();}$this->body($row);$cursor=$row['record_id'];$this->unit()->now();}
        }while(count($rows)===64);
        if($count!==$root['entries']||$this->root()!==$root){self::corrupt();}return $root;
    }
    /** Internal explicit authority transition, same PDO transaction. Does not adopt old policies or change any records. */
    public function rebindAuthority(string $expectedDigest,string $next):array
    {
        self::id($expectedDigest);self::id($next);$d=($this->dependencies)();
        if($d[4]!==2||$next===$d[5]){throw new ConfigurationException('Use distinct fenced authorities.','configuration.account_checkpoint');}
        $before=$this->verifyBodies();
        if(!hash_equals($expectedDigest,self::digest($before))){throw new StorageException('Trusted worker checkpoint changed.','account.worker_changed');}
        if($before['revision']>=PHP_INT_MAX-1){throw new StorageException('Account root revision exhausted.','account.capacity');}
        $after=new self($d[0],$d[6],$d[7],$d[1],$d[2],$d[3],2,$next);$root=$before;$root['policy']=$after->policyDigest();++$root['revision'];$root['observed_at']=$this->unit()->now();$root=$this->sign($root,true);
        $fields=array_diff(array_keys(self::rootTypes()),['namespace']);$query=$this->unit()->query('UPDATE '.$this->table(true).' SET '.implode(',',array_map(static function(string $field):string{return $field.'=:'.$field;},$fields)).' WHERE namespace=:namespace AND revision=:previous_revision AND seal=:previous_seal',$root+['previous_revision'=>$before['revision'],'previous_seal'=>$before['seal']]);
        $count=$query->rowCount();$query->closeCursor();if($count!==1||$after->checkpoint()!==$root){self::corrupt();}return $root;
    }
    public function currentKeyId():string {return $this->keys()->currentId();}
    /** Missing is permitted only for an empty, explicitly uninitialized namespace. Never adopt orphan records. */
    public function checkpointIfInitialized():?array
    {
        $root=$this->checkedRoot(true);
        if($root===null&&$this->unit()->metadataRows('SELECT 1 FROM '.$this->table().' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$this->namespace])!==[]){throw new StorageException('Do not adopt orphaned account history.','account.uninitialized');}return $root;
    }
    /** Internal same-transaction checkpoint. It authenticates metadata/membership, not every unselected payload body.
     * @phpstan-impure
     */
    public function checkpoint():array {return $this->checkedRoot();}
    public function rotateRoot():bool {$root=$this->checkedRoot();if($root['seal_key']===$this->keys()->currentId()){return false;}$this->sync($root);return true;}
    public function capacity(int $required,bool $allowUninitialized=false):void
    {
        $root=$this->checkedRoot($allowUninitialized);
        if($root===null&&$this->unit()->metadataRows('SELECT 1 FROM '.$this->table().' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$this->namespace])!==[]){throw new StorageException('Do not adopt orphaned account history.','account.uninitialized');}
        if($required<1||$required>$this->policy()->maximumEntries()-($root===null?0:$root['entries'])){throw new StorageException('Account ledger capacity exhausted.','account.capacity');}
    }
    public function __debugInfo():array {return ['account_ledger'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild account ledger services from trusted dependencies.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Account ledger services cannot be deserialized.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account ledger services are immutable.','configuration.immutable');}
}
