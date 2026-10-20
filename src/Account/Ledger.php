<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
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
    private function lock():string {return $this->unit()->driver()==='mysql'?' FOR UPDATE':'';}
    public static function rootTypes():array {return ['namespace'=>'digest','format'=>'int','epoch'=>'digest','policy'=>'digest','entries'=>'int','revision'=>'int','history_digest'=>'digest','created_at'=>'int','observed_at'=>'int','seal_key'=>'bytes:32','seal'=>'digest'];}
    public static function recordTypes():array {return ['namespace'=>'digest','record_id'=>'digest','owner'=>'digest','kind'=>'bytes:16','revision'=>'int','created_at'=>'int','retire_at'=>'int','updated_at'=>'int','payload_bytes'=>'int','payload_digest'=>'digest','seal_key'=>'bytes:32','seal'=>'digest','payload'=>'blob'];}
    public static function indexes():array {return ['sosecurity_account_owner'=>['unique'=>false,'columns'=>['namespace','owner','kind','created_at','record_id']],'sosecurity_account_retention'=>['unique'=>false,'columns'=>['namespace','retire_at','record_id']]];}
    private function columns(bool $root=false):string {$types=$root?self::rootTypes():self::recordTypes();unset($types['payload']);return SqlSchema::boundedProjection($this->unit()->driver(),$types);}
    private function bytes():string {return SqlSchema::blobLength($this->unit()->driver(),'payload');}
    public function verifySchema():void
    {
        $u=$this->unit();SqlSchema::durable($u);SqlSchema::table($u,'sosecurity_account_roots',self::rootTypes(),['namespace']);SqlSchema::table($u,'sosecurity_account_records',self::recordTypes(),['namespace','record_id'],self::indexes());
    }
    /** @return never */
    private static function corrupt():void {throw new StorageException('Account ledger state cannot be authenticated.','account.corrupt');}
    private function encoded(array $row,bool $root):string
    {
        $result=[];foreach(array_keys($root?self::rootTypes():self::recordTypes()) as $field){if($field!=='seal'&&$field!=='payload'){$result[$field]=$row[$field];}}
        return ($root?'SoSecurity.Account.Root.1.':'SoSecurity.Account.Record.1.').json_encode($result,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    }
    private function sign(array $row,bool $root):array {$row['seal_key']=$this->keys()->currentId();$row['seal']=bin2hex($this->keys()->sign($this->encoded($row,$root)));return $row;}
    private function authenticated(array $row,bool $root):array
    {
        $types=$root?self::rootTypes():self::recordTypes();unset($types['payload']);$expected=array_keys($types);if(!$root){$expected[]='body_length';}
        if(count($row)!==count($expected)||array_diff(array_keys($row),$expected)){self::corrupt();}
        foreach($types as $field=>$type){
            if($type==='int'){$row[$field]=SqlSchema::integer($row[$field]);}
            elseif(!is_string($row[$field])||($type==='digest'&&!preg_match('/\A[a-f0-9]{64}\z/D',$row[$field]))){self::corrupt();}
        }
        if(!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$row['seal_key'])||$row['namespace']!==$this->namespace||!$this->keys()->verify($row['seal_key'],$this->encoded($row,$root),hex2bin($row['seal']))){self::corrupt();}
        if($row['revision']<1||$row['revision']>=PHP_INT_MAX||$row['created_at']>($root?$row['observed_at']:$row['updated_at'])){self::corrupt();}
        $now=$this->unit()->now();if(($root?$row['observed_at']:$row['updated_at'])>$now){throw new StorageException('Account ledger clock moved backwards.','account.clock');}
        if($root){
            if($row['format']!==$this->format()||$row['epoch']!==$this->epoch()||$row['policy']!==$this->policyDigest()){throw new ConfigurationException('Reconcile account ledger policy/epoch changes explicitly.','configuration.account_state');}
            if($row['entries']>$this->policy()->maximumEntries()){self::corrupt();}
        }else{
            $length=SqlSchema::integer($row['body_length']);
            if(!in_array($row['kind'],['register','change','recover','notice','budget'],true)||$row['payload_bytes']>16384||$length!==$row['payload_bytes']||$row['retire_at']<$row['created_at']||$row['retire_at']-($row['kind']==='budget'?$row['updated_at']:$row['created_at'])>1209600){self::corrupt();}unset($row['body_length']);
        }
        return $row;
    }
    private function history():array
    {
        $hash=hash_init('sha256');hash_update($hash,'SoSecurity.Account.History.1.'.$this->namespace);$count=0;$cursor=null;
        do{
            $limit=min(64,$this->policy()->maximumEntries()+1-$count);$args=['namespace'=>$this->namespace];if($cursor!==null){$args['cursor']=$cursor;}
            $rows=$this->unit()->query('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace'.($cursor===null?'':' AND record_id>:cursor').' ORDER BY '.$this->table().'.record_id LIMIT '.$limit.$this->lock(),$args)->fetchAll(PDO::FETCH_ASSOC);
            foreach($rows as $raw){$row=$this->authenticated($raw,false);if(++$count>$this->policy()->maximumEntries()){self::corrupt();}hash_update($hash,$row['record_id'].$row['seal']);$cursor=$row['record_id'];}
        }while(count($rows)===$limit);
        return ['entries'=>$count,'digest'=>hash_final($hash)];
    }
    private function root(bool $optional=false):?array
    {
        $raw=$this->unit()->query('SELECT '.$this->columns(true).' FROM '.$this->table(true).' WHERE namespace=:namespace'.$this->lock(),['namespace'=>$this->namespace])->fetch(PDO::FETCH_ASSOC);
        if($raw===false){if($optional){return null;}throw new StorageException('Account ledger requires explicit initialization.','account.uninitialized');}
        $root=$this->authenticated($raw,true);$actual=$this->history();if($root['entries']!==$actual['entries']||!hash_equals($root['history_digest'],$actual['digest'])){self::corrupt();}return $root;
    }
    private function sync(array $root,bool $insert=false):array
    {
        if($root['revision']>=PHP_INT_MAX-1){throw new StorageException('Account ledger revision exhausted.','account.capacity');}
        $history=$this->history();$root['entries']=$history['entries'];$root['history_digest']=$history['digest'];++$root['revision'];$root['observed_at']=$this->unit()->now();$root=$this->sign($root,true);$fields=array_keys(self::rootTypes());
        $sql=$insert?'INSERT INTO '.$this->table(true).'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->table(true).' SET '.implode(',',array_map(static function(string $field):string{return $field.'=:'.$field;},array_diff($fields,['namespace']))).' WHERE namespace=:namespace';
        $this->unit()->query($sql,$root)->closeCursor();if($this->root()!==$root){self::corrupt();}return $root;
    }
    public function initialize():bool
    {
        $this->verifySchema();if($this->root(true)!==null){return false;}
        if($this->unit()->query('SELECT 1 FROM '.$this->table().' WHERE namespace=:namespace LIMIT 1',['namespace'=>$this->namespace])->fetchColumn()!==false){throw new StorageException('Do not adopt orphaned account history.','account.uninitialized');}
        $now=$this->unit()->now();$this->sync(['namespace'=>$this->namespace,'format'=>$this->format(),'epoch'=>$this->epoch(),'policy'=>$this->policyDigest(),'entries'=>0,'revision'=>0,'history_digest'=>hash('sha256','SoSecurity.Account.History.1.'.$this->namespace),'created_at'=>$now,'observed_at'=>$now,'seal_key'=>$this->keys()->currentId(),'seal'=>str_repeat('0',64)],true);return true;
    }
    private static function id(string $value):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$value)){throw new ConfigurationException('Use a fixed opaque account ledger ID.','configuration.account_ledger');}}
    private function record(string $id):?array
    {
        self::id($id);$raw=$this->unit()->query('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace AND record_id=:id'.$this->lock(),['namespace'=>$this->namespace,'id'=>$id])->fetch(PDO::FETCH_ASSOC);return $raw===false?null:$this->authenticated($raw,false);
    }
    private function body(array $row):string
    {
        $raw=$this->unit()->query('SELECT payload,'.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace AND record_id=:id AND '.$this->bytes().'=:bytes'.$this->lock(),['namespace'=>$this->namespace,'id'=>$row['record_id'],'bytes'=>$row['payload_bytes']])->fetch(PDO::FETCH_ASSOC);
        if(!is_array($raw)||SqlSchema::integer($raw['body_length'])!==$row['payload_bytes']){self::corrupt();}$body=$raw['payload']===null&&$row['payload_bytes']===0?'':$raw['payload'];
        if(!is_string($body)||strlen($body)!==$row['payload_bytes']||!hash_equals($row['payload_digest'],hash('sha256',$body))){self::corrupt();}return $body;
    }
    /** @phpstan-impure */
    public function read(string $id):?array {$this->verifySchema();$this->root();$row=$this->record($id);return $row===null?null:$row+['payload'=>$this->body($row)];}
    public function latest(string $owner,string $kind):?array
    {
        self::id($owner);$this->verifySchema();$this->root();if(!in_array($kind,['register','change','recover','notice','budget'],true)){throw new ConfigurationException('Use a fixed account ledger kind.','configuration.account_ledger');}
        $raw=$this->unit()->query('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace AND owner=:owner AND kind=:kind ORDER BY '.$this->table().'.created_at DESC,'.$this->table().'.record_id DESC LIMIT 1'.$this->lock(),['namespace'=>$this->namespace,'owner'=>$owner,'kind'=>$kind])->fetch(PDO::FETCH_ASSOC);
        if($raw===false){return null;}$row=$this->authenticated($raw,false);return $row+['payload'=>$this->body($row)];
    }
    public function put(string $id,string $owner,string $kind,string $payload,int $retireAt,?int $expectedRevision=null):array
    {
        self::id($id);self::id($owner);
        if(!in_array($kind,['register','change','recover','notice','budget'],true)||strlen($payload)>16384||$retireAt<0){throw new ConfigurationException('Use bounded account ledger records.','configuration.account_ledger');}
        $this->verifySchema();$root=$this->root();$existing=$this->record($id);$now=$this->unit()->now();
        if(($existing===null)!==($expectedRevision===null)||($existing!==null&&($existing['revision']!==$expectedRevision||$existing['owner']!==$owner||$existing['kind']!==$kind))){throw new StorageException('Account ledger revision conflict.','account.conflict');}
        if($existing!==null){$this->body($existing);}elseif($root['entries']>=$this->policy()->maximumEntries()){throw new StorageException('Account ledger capacity exhausted.','account.capacity');}
        $created=$existing===null?$now:$existing['created_at'];$revision=$existing===null?1:$existing['revision']+1;
        if($revision>=PHP_INT_MAX||$retireAt<$created||$retireAt-($kind==='budget'?$now:$created)>1209600){throw new ConfigurationException('Account retention/revision exceeds its bounds.','configuration.account_ledger');}
        $row=$this->sign(['namespace'=>$this->namespace,'record_id'=>$id,'owner'=>$owner,'kind'=>$kind,'revision'=>$revision,'created_at'=>$created,'retire_at'=>$retireAt,'updated_at'=>$now,'payload_bytes'=>strlen($payload),'payload_digest'=>hash('sha256',$payload),'seal_key'=>$this->keys()->currentId(),'seal'=>str_repeat('0',64)],false);$fields=array_keys(self::recordTypes());
        $sql=$existing===null?'INSERT INTO '.$this->table().'('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')':'UPDATE '.$this->table().' SET '.implode(',',array_map(static function(string $field):string{return $field.'=:'.$field;},array_diff($fields,['namespace','record_id']))).' WHERE namespace=:namespace AND record_id=:record_id';
        $this->unit()->query($sql,$row+['payload'=>$payload],['payload'])->closeCursor();if($this->record($id)!==$row||$this->body($row)!==$payload){self::corrupt();}$this->sync($root);return $row+['payload'=>$payload];
    }
    /** Authenticated metadata only. Cursor denotes physical-key progress, not a stable snapshot across transactions. */
    public function page(int $limit=20,string $after=''):array
    {
        if($limit<1||$limit>50){throw new ConfigurationException('Use an account maintenance page of 1-50 records.','configuration.account_maintenance');}if($after!==''){self::id($after);}
        $this->verifySchema();$this->root();$arguments=['namespace'=>$this->namespace];if($after!==''){$arguments['after']=$after;}
        $raw=$this->unit()->query('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace'.($after===''?'':' AND record_id>:after').' ORDER BY '.$this->table().'.record_id LIMIT '.$limit.$this->lock(),$arguments)->fetchAll(PDO::FETCH_ASSOC);
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
        $this->verifySchema();$root=$this->root();$rows=[];
        foreach($ids as $id){$row=$this->record($id);$rows[$id]=$row===null?null:$row+['payload'=>$this->body($row)];}
        if($this->root()!==$root){self::corrupt();}return $rows;
    }
    /** Cryptographic maintenance only. Preserve payload, creation/update/retention timestamps and ownership. */
    public function reseal(array $expected):int
    {
        if(!$expected||count($expected)>100){throw new ConfigurationException('Reseal 1-100 exact account records.','configuration.account_maintenance');}
        foreach($expected as $id=>$revision){if(!is_string($id)||!is_int($revision)||$revision<1||$revision>=PHP_INT_MAX){throw new ConfigurationException('Use exact account revisions.','configuration.account_maintenance');}self::id($id);}
        $this->verifySchema();$root=$this->root();$updates=[];
        foreach($expected as $id=>$revision){
            $row=$this->record($id);if($row===null||$row['revision']!==$revision){throw new StorageException('Account reseal revision changed.','account.conflict');}$this->body($row);
            if($row['seal_key']===$this->keys()->currentId()){continue;}
            if($revision>=PHP_INT_MAX-1){throw new StorageException('Account record revision exhausted.','account.capacity');}++$row['revision'];$updates[$id]=$this->sign($row,false);
        }
        foreach($updates as $id=>$row){
            $q=$this->unit()->query('UPDATE '.$this->table().' SET revision=:revision,seal_key=:seal_key,seal=:seal WHERE namespace=:namespace AND record_id=:id AND revision=:previous',['revision'=>$row['revision'],'seal_key'=>$row['seal_key'],'seal'=>$row['seal'],'namespace'=>$this->namespace,'id'=>$id,'previous'=>$expected[$id]]);$count=$q->rowCount();$q->closeCursor();if($count!==1||$this->record($id)!==$row){self::corrupt();}
        }
        if($updates){$this->sync($root);}return count($updates);
    }
    /** Internal CAS batch. Authenticate every body before deleting anything; no implicit expiry or permission decisions. */
    public function remove(array $expected):int
    {
        if(!$expected||count($expected)>100){throw new ConfigurationException('Remove 1-100 explicitly selected account records.','configuration.account_maintenance');}
        $validated=[];foreach($expected as $id=>$revision){if(!is_string($id)||!is_int($revision)||$revision<1||$revision>=PHP_INT_MAX){throw new ConfigurationException('Use exact account revisions.','configuration.account_maintenance');}self::id($id);$validated[$id]=$revision;}
        $this->verifySchema();$root=$this->root();
        foreach($validated as $id=>$revision){$row=$this->record($id);if($row===null||$row['revision']!==$revision){throw new StorageException('Account cleanup revision changed.','account.conflict');}$this->body($row);}
        foreach($validated as $id=>$revision){$q=$this->unit()->query('DELETE FROM '.$this->table().' WHERE namespace=:namespace AND record_id=:id AND revision=:revision',['namespace'=>$this->namespace,'id'=>$id,'revision'=>$revision]);$count=$q->rowCount();$q->closeCursor();if($count!==1||$this->record($id)!==null){self::corrupt();}}
        $this->sync($root);return count($validated);
    }
    /** Digest only; callers must obtain and retain trusted checkpoints independently of business backups. */
    public static function digest(array $checkpoint):string
    {
        if(array_keys($checkpoint)!==array_keys(self::rootTypes())){throw new ConfigurationException('Use a complete authenticated root checkpoint.','configuration.account_checkpoint');}
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
        $this->verifySchema();$root=$this->root();$cursor=null;$count=0;
        do{
            $arguments=['namespace'=>$this->namespace];if($cursor!==null){$arguments['after']=$cursor;}
            $rows=$this->unit()->query('SELECT '.$this->columns().','.$this->bytes().' AS body_length FROM '.$this->table().' WHERE namespace=:namespace'.($cursor===null?'':' AND record_id>:after').' ORDER BY '.$this->table().'.record_id LIMIT 64'.$this->lock(),$arguments)->fetchAll(PDO::FETCH_ASSOC);
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
        $this->verifySchema();$root=$this->root(true);
        if($root===null&&$this->unit()->query('SELECT 1 FROM '.$this->table().' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$this->namespace])->fetchColumn()!==false){throw new StorageException('Do not adopt orphaned account history.','account.uninitialized');}return $root;
    }
    /** Internal same-transaction checkpoint. It authenticates metadata/membership, not every unselected payload body.
     * @phpstan-impure
     */
    public function checkpoint():array {$this->verifySchema();return $this->root();}
    public function rotateRoot():bool {$this->verifySchema();$root=$this->root();if($root['seal_key']===$this->keys()->currentId()){return false;}$this->sync($root);return true;}
    public function capacity(int $required,bool $allowUninitialized=false):void
    {
        $this->verifySchema();$root=$this->root($allowUninitialized);
        if($root===null&&$this->unit()->query('SELECT 1 FROM '.$this->table().' WHERE namespace=:namespace LIMIT 1'.$this->lock(),['namespace'=>$this->namespace])->fetchColumn()!==false){throw new StorageException('Do not adopt orphaned account history.','account.uninitialized');}
        if($required<1||$required>$this->policy()->maximumEntries()-($root===null?0:$root['entries'])){throw new StorageException('Account ledger capacity exhausted.','account.capacity');}
    }
    public function __debugInfo():array {return ['account_ledger'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild account ledger services from trusted dependencies.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Account ledger services cannot be deserialized.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account ledger services are immutable.','configuration.immutable');}
}
