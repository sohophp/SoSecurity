<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** A fixed destructive containment, never account activation, password assignment or an arbitrary callback. */
final class StateAccountContainment
{
    private $dependencies;
    private $fingerprint;
    public function __construct(LocalStateWitness $witness,CompositeStateSnapshot $source,SqlStateSnapshot $sql,string $sqlName,string $table,array $columns,string $scope,array $subjects)
    {
        $required=['scope'=>'bytes:256','subject'=>'bytes:256','credential_version'=>'bytes:256','address_version'=>'bytes:256','address'=>'bytes:320','password'=>'nullable_bytes:4096','status'=>'bytes:16','verified'=>'int','mfa_required'=>'int','roles'=>'bytes:4096'];
        if($witness->format()!==3||!$witness->allowsScope($scope)||!$witness->coversSnapshot($source)||!$source->contains($sqlName,$sql)||$source->connection()!==$sql->connection()||array_keys($columns)!==array_keys($required)||count($subjects)<1||count($subjects)>8){self::invalid();}
        $types=[];$copiedColumns=[];foreach($required as $field=>$type){$name=$columns[$field];if(!is_string($name)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$name)||isset($types[$name])){self::invalid();}$types[$name]=$type;$copiedColumns[$field]=$name;}$columns=$copiedColumns;
        if(!$sql->containsDefinition($table,$types,[$columns['scope'],$columns['subject']],[$columns['scope']=>$scope])){self::invalid();}
        $copy=[];foreach($subjects as $subject){if(!is_string($subject)){self::invalid();}Guard::label($subject);if(preg_match('//u',$subject)!==1||in_array($subject,$copy,true)){self::invalid();}$copy[]=$subject;}sort($copy,SORT_STRING);
        $this->fingerprint=hash('sha256',json_encode(['SoSecurity.Account.StateAccountContainment.1',$witness->binding(),$witness->generation(),$source->fingerprint(),$sql->fingerprint(),$sqlName,$table,$columns,$scope,$copy],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        $this->dependencies=static function()use($witness,$source,$sql,$sqlName,$table,$columns,$scope,$copy):array{return [$witness,$source,$sql,$sqlName,$table,$columns,$scope,$copy];};
        $sql->selections($this->selectors());
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use an exact covered account containment plan with at most eight subjects.','configuration.state_containment');}
    private function d():array{return ($this->dependencies)();}
    public function boundTo(LocalStateWitness $witness):bool{return $this->d()[0]===$witness&&$witness->coversSnapshot($this->d()[1]);}
    public function binding():string{return $this->fingerprint;}
    public function count():int{return count($this->d()[7]);}
    private function selectors():array{$d=$this->d();$s=[];foreach($d[7] as $i=>$subject){$s['account_'.$i]=['table'=>$d[4],'key'=>[$d[5]['scope']=>$d[6],$d[5]['subject']=>$subject],'columns'=>array_values($d[5])];}return $s;}
    /** No triggers or FK relationships may extend this fixed update beyond its selected rows. */
    private function dependencies(SqlTransaction $unit,?string $selectedTable=null):void
    {
        $d=$this->d();$table=$selectedTable??$d[4];$checks=[];
        if($unit->driver()==='mysql'){
            if((string)$unit->query('SELECT @@GLOBAL.partial_revokes')->fetchColumn()!=='0'){throw new StorageException('Partial revokes prevent this recovery connection from proving unrestricted dependency visibility.','account.containment_visibility');}

            // Recovery uses a dedicated inspection connection. Empty filtered metadata is not proof of no dependencies.
            $identity=$unit->query('SELECT CASE WHEN OCTET_LENGTH(CURRENT_USER())<=320 THEN CURRENT_USER() ELSE NULL END')->fetchColumn();
            if(!is_string($identity)||!preg_match('/\A([A-Za-z0-9_.-]{1,32})@([A-Za-z0-9_.:%\/-]{1,255})\z/D',$identity,$match)){throw new StorageException('Cannot prove database dependency metadata visibility.','account.containment_visibility');}
            $grantee="'".$match[1]."'@'".$match[2]."'";$q=$unit->query("SELECT 1 FROM information_schema.USER_PRIVILEGES WHERE BINARY GRANTEE=:grantee AND PRIVILEGE_TYPE='TRIGGER' LIMIT 1",['grantee'=>$grantee]);$visible=$q->fetchColumn()!==false;$q->closeCursor();
            if(!$visible){throw new StorageException('Dedicated recovery inspection visibility is required; ordinary application connections are not sufficient.','account.containment_visibility');}

            $checks[]=['SELECT 1 FROM information_schema.TRIGGERS WHERE LOWER(TRIGGER_SCHEMA)=LOWER(DATABASE()) AND LOWER(EVENT_OBJECT_TABLE)=:table LIMIT 1',['table'=>$table]];
            $checks[]=['SELECT 1 FROM information_schema.KEY_COLUMN_USAGE WHERE REFERENCED_TABLE_NAME IS NOT NULL AND ((LOWER(TABLE_SCHEMA)=LOWER(DATABASE()) AND LOWER(TABLE_NAME)=:outgoing) OR (LOWER(REFERENCED_TABLE_SCHEMA)=LOWER(DATABASE()) AND LOWER(REFERENCED_TABLE_NAME)=:incoming)) LIMIT 1',['outgoing'=>$table,'incoming'=>$table]];
        }else{
            foreach(['main','temp'] as $schema){$checks[]=["SELECT 1 FROM ".$schema.".sqlite_master WHERE type='trigger' AND tbl_name COLLATE NOCASE=:table LIMIT 1",['table'=>$table]];$checks[]=["SELECT 1 FROM ".$schema.".sqlite_master WHERE name COLLATE NOCASE='pragma_foreign_key_list' LIMIT 1",[]];}
            $checks[]=["SELECT 1 FROM main.sqlite_master m JOIN main.pragma_foreign_key_list(m.name,'main') f WHERE m.type='table' AND (m.name COLLATE NOCASE=:outgoing OR f.\"table\" COLLATE NOCASE=:incoming) LIMIT 1",['outgoing'=>$table,'incoming'=>$table]];
            $checks[]=["SELECT 1 FROM temp.sqlite_master m JOIN main.pragma_foreign_key_list(m.name,'temp') f WHERE m.type='table' AND (m.name COLLATE NOCASE=:outgoing OR f.\"table\" COLLATE NOCASE=:incoming) LIMIT 1",['outgoing'=>$table,'incoming'=>$table]];
        }
        foreach($checks as $check){$q=$unit->query($check[0],$check[1]);$related=$q->fetchColumn()!==false;$q->closeCursor();if($related){throw new StorageException('Fixed account containment requires a table without triggers or foreign-key dependencies.','account.containment_dependencies');}}
    }
    private function writable():void{$unit=SqlTransaction::forObservation($this->d()[2]->connection(),new SystemClock(),30000);$unit->run(function()use($unit):void{$this->dependencies($unit);});}
    private function view():array
    {
        $d=$this->d();$view=$d[1]->capture([$d[3]=>$this->selectors()]);$part=$view->part($d[3]);if(!$view->matches($d[1])||!$part instanceof SqlStateCapture||!$part->matches($d[2])){self::invalid();}$rows=[];
        foreach($d[7] as $i=>$subject){$row=$part->row('account_'.$i);if($row===null||$row[$d[5]['scope']]!==$d[6]||$row[$d[5]['subject']]!==$subject){throw new StorageException('An exact selected account is missing.','account.containment_changed');}$rows[]=$row;}return [$view->digest(),$rows];
    }
    /** Bounded current capture; never publishes selected passwords or roles. */
    public function observed():string{$this->writable();return $this->view()[0];}
    private function version(string $operation,string $subject,string $purpose):string{return hash('sha256',json_encode(['SoSecurity.Account.StateContainedVersion.1',$this->fingerprint,$operation,$subject,$purpose],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));}
    private function quote(string $column,string $driver):string{$q=$driver==='sqlite'?'"':'`';return $q.$column.$q;}
    private function rowDigest(array $row):string{$encoded=[];foreach($row as $column=>$value){$encoded[]=[$column,is_string($value)?['bytes',bin2hex($value)]:$value];}return hash('sha256','SoSecurity.Account.StateContainedRow.1.'.json_encode($encoded,JSON_UNESCAPED_SLASHES));}
    private function expected(array $row,string $operation,string $subject):array
    {
        $d=$this->d();foreach(['credential_version'=>$this->version($operation,$subject,'credential'),'address_version'=>$this->version($operation,$subject,'address'),'password'=>null,'status'=>'disabled','verified'=>0,'mfa_required'=>1,'roles'=>'[]'] as $field=>$value){$row[$d[5][$field]]=$value;}return $row;
    }
    /** Exact row hashes only; the original password, address and roles are never persisted in recovery metadata. */
    public function manifest(string $operation):array
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$operation)){self::invalid();}$this->writable();$d=$this->d();$view=$this->view();$rows=[];
        foreach($view[1] as $i=>$row){$rows[]=['before'=>$this->rowDigest($row),'after'=>$this->rowDigest($this->expected($row,$operation,$d[7][$i]))];}
        return ['format'=>1,'source'=>$d[1]->fingerprint(),'sql'=>$d[2]->fingerprint(),'plan'=>$this->binding(),'operation'=>$operation,'observed'=>$view[0],'rows'=>$rows];
    }
    public function acceptsManifest(array $manifest):bool
    {
        $d=$this->d();return StateAccountManifest::valid($manifest)&&$manifest['source']===$d[1]->fingerprint()&&$manifest['sql']===$d[2]->fingerprint()&&$manifest['plan']===$this->binding()&&count($manifest['rows'])===$this->count();
    }
    private function resolutionView(StateAccountResolution $resolution):array
    {
        if(!$resolution->usesPlan($this)||!$this->acceptsManifest($resolution->manifest())){self::invalid();}$manifest=$resolution->manifest();$view=$this->view();
        foreach($view[1] as $i=>$row){$digest=$this->rowDigest($row);$entry=$manifest['rows'][$i];if($digest!==$entry['before']&&$digest!==$entry['after']){throw new StorageException('Account row is neither its sealed before nor fixed after state.','account.account_resolution_changed');}if($digest===$entry['before']&&$this->rowDigest($this->expected($row,$manifest['operation'],$this->d()[7][$i]))!==$entry['after']){throw new StorageException('Account resolution transformation differs from the original manifest.','account.account_resolution_changed');}}return $view;
    }
    public function resolutionObserved(StateAccountResolution $resolution):string{$this->writable();return $this->resolutionView($resolution)[0];}
    /** No caller can execute this before the exact witness publishes an independently approved pending receipt. */
    public function apply(LocalStateWitness $witness,string $operation,Deadline $deadline):void
    {
        if(!$this->boundTo($witness)||!$witness->containmentActive($this,$operation)){self::invalid();}$view=$this->view();if(!$witness->containmentActive($this,$operation,$view[0])){throw new StorageException('Source changed before fixed containment effects.','account.containment_changed');}
        $this->writeRows($witness,$operation,$operation,$view,$deadline,null);
    }
    /** Fresh approved convergence uses original versions; it never repeats the original account operation with new effects. */
    public function resolve(StateAccountResolution $resolution,LocalStateWitness $witness,string $operation,Deadline $deadline):void
    {
        if(!$resolution->usesPlan($this)||!$resolution->boundTo($witness)||!$witness->accountResolutionActive($resolution,$operation)){self::invalid();}$view=$this->resolutionView($resolution);if(!$witness->accountResolutionActive($resolution,$operation,$view[0])){throw new StorageException('Account source changed before approved resolution.','account.account_resolution_changed');}
        $this->writeRows($witness,$operation,$resolution->manifest()['operation'],$view,$deadline,$resolution);
    }
    private function writeRows(LocalStateWitness $witness,string $operation,string $original,array $view,Deadline $deadline,?StateAccountResolution $resolution):void
    {
        $d=$this->d();$unit=$resolution===null?SqlTransaction::forAccountContainment($d[2]->connection(),new SystemClock(),30000,$this,$witness,$operation):SqlTransaction::forAccountResolution($d[2]->connection(),new SystemClock(),30000,$resolution,$witness,$operation);$driver=$unit->driver();$table=$unit->prefix().$this->quote($d[4],$driver);
        $unit->run(function()use($witness,$operation,$original,$resolution,$d,$view,$unit,$driver,$table):void{
            // Acquire the actual table's metadata/row lock before inspecting write dependencies.
            $q=$unit->query('SELECT 1 FROM '.$table.' WHERE '.$this->quote($d[5]['scope'],$driver).'=:scope AND '.$this->quote($d[5]['subject'],$driver).'=:subject'.($driver==='mysql'?' FOR UPDATE':''),['scope'=>$d[6],'subject'=>$d[7][0]]);$q->fetchColumn();$q->closeCursor();$this->dependencies($unit);

            foreach($view[1] as $i=>$row){if($resolution===null?!$witness->containmentActive($this,$operation):!$witness->accountResolutionActive($resolution,$operation)){self::invalid();}if($resolution!==null&&$this->rowDigest($row)===$resolution->manifest()['rows'][$i]['after']){continue;}$parameters=[];$blobs=[];$where=[];
                foreach($d[5] as $field=>$column){$q=$this->quote($column,$driver);$name='old_'.$field;$value=$row[$column];if($value===null){$where[]=$q.' IS NULL';}elseif(is_int($value)){$where[]=$q.'=:'.$name;$parameters[$name]=$value;}else{$where[]=($driver==='sqlite'?'CAST('.$q.' AS BLOB)':'BINARY '.$q).'=:'.$name;$parameters[$name]=$value;$blobs[]=$name;}}
                $parameters['credential_next']=$this->version($original,$d[7][$i],'credential');$parameters['address_next']=$this->version($original,$d[7][$i],'address');
                $set=$this->quote($d[5]['credential_version'],$driver).'=:credential_next,'.$this->quote($d[5]['address_version'],$driver)."=:address_next,".$this->quote($d[5]['password'],$driver).'=NULL,'.$this->quote($d[5]['status'],$driver)."='disabled',".$this->quote($d[5]['verified'],$driver).'=0,'.$this->quote($d[5]['mfa_required'],$driver).'=1,'.$this->quote($d[5]['roles'],$driver)."='[]'";
                $q=$unit->query('UPDATE '.$table.' SET '.$set.' WHERE '.implode(' AND ',$where),$parameters,$blobs);$count=$q->rowCount();$q->closeCursor();if($count!==1){throw new StorageException('Selected account changed during containment.','account.containment_changed');}
            }
        },null,function()use($witness,$operation,$resolution):void{if($resolution===null){$witness->containmentCurrent($this,$operation);}else{$witness->accountResolutionCurrent($resolution,$operation);}},null,$deadline);
    }
    public function matchesContainedRow(array $row,string $subject,string $operation,string $expectedHash):bool
    {
        $d=$this->d();$ordered=[];foreach($d[5] as $column){if(!array_key_exists($column,$row)){return false;}$ordered[$column]=$row[$column];}return $ordered[$d[5]['scope']]===$d[6]&&$ordered[$d[5]['subject']]===$subject&&$this->rowDigest($ordered)===$expectedHash&&$this->expected($ordered,$operation,$subject)===$ordered;
    }
    public function installationLayout(string $subject):array
    {
        $d=$this->d();if(!in_array($subject,$d[7],true)){self::invalid();}return ['table'=>$d[4],'columns'=>$d[5],'scope'=>$d[6],'subject'=>$subject];
    }
    public function installationDependencies(\SoSecurity\Support\SqlTransaction $unit,StateCredentialInstallation $plan,LocalStateWitness $witness,string $operation):void
    {
        if(!$plan->usesAccounts($this)||!$witness->usesConnection($unit->connection())||!$witness->credentialInstallationActive($plan,$operation)){self::invalid();}foreach([$this->d()[4],'sosecurity_account_roots','sosecurity_account_records'] as $table){$this->dependencies($unit,$table);}
    }
    public function credentialTarget(array $manifest,string $subject):array
    {
        if(!$this->acceptsManifest($manifest)){self::invalid();}$index=array_search($subject,$this->d()[7],true);if($index===false){self::invalid();}$view=$this->view();$row=$view[1][$index];if($this->rowDigest($row)!==$manifest['rows'][$index]['after']){throw new StorageException('The exact contained account changed before credential preparation.','account.credentials_changed');}
        return ['scope'=>$this->d()[6],'subject'=>$subject,'row'=>$manifest['rows'][$index]['after'],'observed'=>$view[0]];
    }
    public function contained(string $operation):string
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$operation)){self::invalid();}$d=$this->d();$view=$this->view();foreach($view[1] as $i=>$row){$expected=['credential_version'=>$this->version($operation,$d[7][$i],'credential'),'address_version'=>$this->version($operation,$d[7][$i],'address'),'password'=>null,'status'=>'disabled','verified'=>0,'mfa_required'=>1,'roles'=>'[]'];foreach($expected as $field=>$value){if($row[$d[5][$field]]!==$value){throw new StorageException('Account containment postcondition changed.','account.containment_changed');}}}return $view[0];
    }
    public function __debugInfo():array{return ['account_containment'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
