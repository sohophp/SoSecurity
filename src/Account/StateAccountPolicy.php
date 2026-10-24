<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Auth\RegistryState;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Mfa\ManagedFactorFrame;
use SoSecurity\Mfa\TotpFactorState;
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;

/** Concrete read-only account/session policy. It never invokes providers, storage callbacks or factor proofs. */
final class StateAccountPolicy
{
    private $dependencies;
    /** File positions only; every use still captures and authenticates the complete current source. */
    private $factorFiles=[];
    public function __construct(LocalStateWitness $witness,CompositeStateSnapshot $source,SqlStateSnapshot $sql,FileStateSnapshot $files,string $sqlName,string $fileName,string $table,array $columns,FileStore $sessions,SessionRegistry $registry,ManagedSecondFactor $adapter,\SoSecurity\Mfa\TotpFactors $factors,string $site,string $scope,string $epoch,HmacKeys $keys)
    {
        if($witness->format()<2){self::invalid();}
        $session=$registry->statePolicy($sessions,$adapter,$witness);$factor=$factors->statePolicy($site,$scope,$epoch,$keys);
        if($session===null||$factor===null){self::invalid();}$clock=$session['clock'];$idle=$session['idle'];$absolute=$session['absolute'];$context=$factor['context'];$ledger=$adapter->ledgerPolicy($keys);if($ledger===null){self::invalid();}
        if(!($clock===$factor['clock']||($clock instanceof \SoSecurity\Support\SystemClock&&$factor['clock'] instanceof \SoSecurity\Support\SystemClock))||!$adapter->matchesStatePolicy($factors,$sql->connection(),$site,$scope,$epoch,$clock)){self::invalid();}
        $required=['scope','subject','credential_version','status','verified','mfa_required','roles','password'];$actual=array_keys($columns);sort($actual);$sorted=$required;sort($sorted);
        if($actual!==$sorted||!$source->contains($sqlName,$sql)||!$source->contains($fileName,$files)||$sqlName===$fileName||!$files->coversStore($sessions)||!$files->coversReference($factor['reference'])||!$witness->coversSnapshot($source)||!$witness->matches($site,$scope,$epoch)||$idle<1||$idle>31536000||$absolute<1||$absolute>31536000){self::invalid();}
        self::name($table);$copy=[];foreach($required as $name){self::name($columns[$name]);$copy[$name]=$columns[$name];}if(count(array_unique($copy))!==8){self::invalid();}
        $this->dependencies=static function()use($witness,$source,$sql,$files,$sqlName,$fileName,$table,$copy,$sessions,$factors,$site,$scope,$epoch,$keys,$clock,$idle,$absolute,$context,$ledger,$registry):array{return [$witness,$source,$sql,$files,$sqlName,$fileName,$table,$copy,$sessions,$factors,$site,$scope,$epoch,$keys,$clock,$idle,$absolute,$context,$ledger,$registry];};
        // Validate the exact PK/columns and both source plans without any I/O.
        $sql->selections($this->sqlSelectors('policy-configuration-check'));$files->selections(['session'=>$sessions->snapshotFile(Guard::key('auth-sessions',$scope,'policy-configuration-check'))]);
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use a matching concrete account/session state policy.','configuration.state_permission');}
    private static function name($name):void{if(!is_string($name)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$name)){self::invalid();}}
    private function d():array{return ($this->dependencies)();}
    public function boundTo(LocalStateWitness $witness):bool{$d=$this->d();return $d[0]===$witness&&$witness->coversSnapshot($d[1])&&$witness->matches($d[10],$d[11],$d[12]);}
    public function recoveryRegistry(\SoSecurity\Auth\SessionRegistry $registry,string $scope):bool{$d=$this->d();return $d[19]===$registry&&$d[11]===$scope;}
    public function recoveryClock(\SoSecurity\Support\Clock $clock):bool{$actual=$this->d()[14];return $actual===$clock||($actual instanceof \SoSecurity\Support\SystemClock&&$clock instanceof \SoSecurity\Support\SystemClock);}
    public function accountConnection(StateBoundary $boundary,Repository $accounts,Policy $policy,string $addressColumn,string $addressVersionColumn):StateAccountConnection
    {
        $d=$this->d();$columns=$d[7];$columns['address']=$addressColumn;$columns['address_version']=$addressVersionColumn;
        return new StateAccountConnection($boundary,$d[0],$d[1],$d[2],$d[4],$accounts,$d[6],$columns,$d[10],$d[11],$d[12],$d[14],$policy,$d[19]);
    }
    public function binding():string{$d=$this->d();return hash('sha256',json_encode(['SoSecurity.Account.StateAccountPolicy.3',$d[0]->binding(),$d[0]->format(),$d[1]->fingerprint(),$d[4],$d[5],$d[6],$d[7],$d[8]->snapshotReference(Guard::key('auth-sessions',$d[11],'state-policy-check')),$d[9]->stateReference($d[11],'state-policy-check',$d[17]),$d[10],$d[11],$d[12],$d[13]->currentId(),$d[15],$d[16],$d[17],$d[18]->fingerprint()]+($d[0]->format()===3?[19=>$d[0]->generation()]:[]),JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));}
    public function now():int{try{$now=$this->d()[14]->now();}catch(\Throwable $error){throw new StorageException('Account permission clock unavailable.','account.clock');}if($now<0||$now>PHP_INT_MAX-31536001){throw new StorageException('Invalid permission clock.','account.clock');}return $now;}
    private function sqlSelectors(string $actor):array
    {
        $d=$this->d();$namespace=hash('sha256',json_encode(['SoSecurity.Account.Ledger.1','account-factor-directory:'.hash('sha256',json_encode([$d[10],$actor])),$d[11],$d[12]],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        return ['actor'=>['table'=>$d[6],'key'=>[$d[7]['scope']=>$d[11],$d[7]['subject']=>$actor],'columns'=>array_values($d[7])],
            'directory'=>['table'=>'sosecurity_account_records','key'=>['namespace'=>$namespace,'record_id'=>hash('sha256','SoSecurity.Account.FactorRegistry.Pointer.1.'.$actor)],'columns'=>array_keys(Ledger::recordTypes())],
            'directory_root'=>['table'=>'sosecurity_account_roots','key'=>['namespace'=>$namespace],'columns'=>array_keys(Ledger::rootTypes())],
            'directory_count'=>['table'=>'sosecurity_account_records','key'=>['namespace'=>$namespace],'columns'=>[],'count'=>true]];
    }
    public function selectors(StatePermission $permission):array
    {
        $d=$this->d();$r=$permission->definition();if($r['scope']!==$d[11]){self::invalid();}
        return [$d[4]=>$this->sqlSelectors($r['actor']),$d[5]=>['session'=>$d[8]->snapshotFile(Guard::key('auth-sessions',$r['scope'],$r['actor']))]];
    }
    private function parts(CompositeStateCapture $view):array
    {
        $d=$this->d();$sql=$view->part($d[4]);$files=$view->part($d[5]);
        if(!$view->matches($d[1])||!$sql instanceof SqlStateCapture||!$files instanceof FileStateCapture||!$sql->matches($d[2])||!$files->matches($d[3])){self::invalid();}return [$sql,$files];
    }
    private function directory(StatePermission $permission,CompositeStateCapture $view,int $now):?array
    {
        return $this->directorySubject($permission->definition()['actor'],$view,$now);
    }
    private function directorySubject(string $actor,CompositeStateCapture $view,int $now):?array
    {
        $d=$this->d();$parts=$this->parts($view);$row=$parts[0]->row('directory');$root=$parts[0]->row('directory_root');$count=$parts[0]->row('directory_count');
        if($root===null){throw new StorageException('Account ledger requires explicit initialization.','account.uninitialized');}
        if($row===null||!is_array($count)||array_keys($count)!==['count']||!is_int($count['count'])){throw new StorageException('Managed factor pointer is absent or corrupt.','account.factor_corrupt');}
        $selectors=$this->sqlSelectors($actor);$namespace=$selectors['directory']['key']['namespace'];$policy=$d[18];
        $root=LedgerState::authenticate($root,true,$namespace,$d[12],$policy->fingerprint(),1,$policy->maximumEntries(),$d[13],$now);
        $payload=$row['payload'];unset($row['payload']);$row['body_length']=strlen($payload);
        $row=LedgerState::authenticate($row,false,$namespace,$d[12],$policy->fingerprint(),1,$policy->maximumEntries(),$d[13],$now);
        LedgerState::single($root,$row,$count['count']);$row['payload']=LedgerState::payload($row,$payload);
        $data=FactorDirectoryState::read($d[10],$d[11],$d[12],$row,$actor);
        return in_array($data['origin'],['migrating','retired','revoked'],true)?null:$data;
    }
    /** The factor filename is discovered only from a view already checked against the independent witness. */
    public function completeSelectors(StatePermission $permission,CompositeStateCapture $initial,int $now):?array
    {
        $d=$this->d();$directory=$this->directory($permission,$initial,$now);if($directory===null){return null;}$selectors=$this->selectors($permission);
        if($directory['factor_id']!==''){$reference=$d[9]->stateReference($directory['slot_scope'],$directory['slot_subject'],$d[17]);if($reference===null||!$d[3]->coversReference($reference)){self::invalid();}$selectors[$d[5]]['factor']=$reference['file'];}return $selectors;
    }
    /** @internal Only LocalStateWitness evaluates its own capture, never a caller-supplied object. */
    public function allows(StatePermission $permission,CompositeStateCapture $view,int $now):bool
    {
        $d=$this->d();$r=$permission->definition();if($r['scope']!==$d[11]||($r['self']&&$r['target']!==$r['actor'])){return false;}$parts=$this->parts($view);$row=$parts[0]->row('actor');if($row===null){return false;}$a=[];foreach($d[7] as $name=>$column){$a[$name]=$row[$column];}
        if($a['scope']!==$r['scope']||$a['subject']!==$r['actor']||!in_array($a['status'],['active','pending','disabled'],true)||!in_array($a['verified'],[0,1],true)||!in_array($a['mfa_required'],[0,1],true)||!is_string($a['roles'])){throw new StorageException('Account permission fields are corrupt.','account.state_corrupt');}
        if($a['status']!=='active'||$a['verified']!==1){return false;}$roles=json_decode($a['roles'],true,3);
        if(!is_array($roles)||array_values($roles)!==$roles||json_encode($roles)!==$a['roles']){throw new StorageException('Account roles are corrupt.','account.state_corrupt');}
        $account=new Account($a['scope'],$a['subject'],$a['credential_version'],true,$roles,$a['mfa_required']===1);
        foreach($r['roles'] as $role){if(!in_array($role,$account->roles(),true)){return false;}}
        if(!is_string($a['password'])){return false;}$account=(new PasswordRecord($account,$a['password']))->identity();$directory=$this->directory($permission,$view,$now);if($directory===null){return false;}if($parts[0]->row('directory')['updated_at']>$now){throw new StorageException('Managed directory clock moved backwards.','account.clock');}$binding=null;
        if($directory['factor_id']!==''){
            if(!$account->mfaRequired()){throw new StorageException('Account factor requirement differs from its pointer.','account.state_corrupt');}$raw=$parts[1]->file('factor');if($raw===null){return false;}
            $context=hash('sha256',json_encode(['SoSecurity.Mfa.ManagedContext.1',$d[10],$d[11],$d[12]],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));$key=Guard::key('mfa-totp',$directory['slot_scope'],$directory['slot_subject']);
            $frame=ManagedFactorFrame::read($context,$d[13],$key,Codec::decode($raw,$now));if($frame['migration']!==null&&$frame['migration']['state']!=='committed'){return false;}
            $factor=TotpFactorState::read($frame['payload'],$now);if($factor===null||$factor['enabled']===null||$factor['enabled']['id']!==$directory['factor_id']){return false;}
            $binding=FactorDirectoryState::binding($d[10],$d[11],$d[12],$directory);
        }elseif($account->mfaRequired()){return false;}
        $fingerprint=hash('sha256',$account->fingerprint().':'.($binding===null?'none':strlen($binding).':'.$binding));$raw=$parts[1]->file('session');if($raw===null){return false;}
        $state=RegistryState::read(Codec::decode($raw,$now),$now,$d[15],$d[16]);$record=$state===null?null:($state['sessions'][$r['reference']['id']]??null);
        if($record===null||!hash_equals($record['digest'],$r['reference']['digest'])||!hash_equals($record['fingerprint'],$fingerprint)||SessionRegistry::strength($record['method'])<max($r['strength'],$binding!==null?2:0)||($r['fresh']&&$record['resumed'])||$record['authenticated']<1||$record['authenticated']>$now||$now-$record['authenticated']>=$r['age']||(!empty($r['methods'])&&!in_array($record['method'],$r['methods'],true))){return false;}return true;
    }
    /** Pure graph agreement; no snapshot read or authority is granted. */
    public function credentialContext(\SoSecurity\Storage\AtomicStore $store,SessionRegistry $sessions,Clock $clock,StateBoundary $boundary):bool
    {
        $d=$this->d();return $boundary->boundTo($d[0])&&$d[19]===$sessions&&$d[14]===$clock&&($store===$d[8]||($store instanceof WitnessedStore&&$store->protects($d[8])&&$store->boundTo($boundary)));
    }
    /** Exact PDO and complete declared business tables; this is configuration agreement, not permission. */
    public function linkContext(\SoSecurity\Storage\AtomicStore $store,SessionRegistry $sessions,\SoSecurity\Support\Clock $clock,StateBoundary $boundary,string $site):bool{return $site===$this->d()[10]&&$this->credentialContext($store,$sessions,$clock,$boundary);}
    /** Pure native reset graph agreement, including authoritative mailbox-version columns. */
    public function resetContext(\SoSecurity\Storage\AtomicStore $store,SessionRegistry $sessions,Clock $clock,StateBoundary $boundary,string $site,string $addressColumn,string $addressVersionColumn):bool
    {
        $d=$this->d();self::name($addressColumn);self::name($addressVersionColumn);if($addressColumn===$addressVersionColumn||in_array($addressColumn,$d[7],true)||in_array($addressVersionColumn,$d[7],true)){return false;}
        return $this->linkContext($store,$sessions,$clock,$boundary,$site)&&$d[2]->coversColumns($d[6],[$addressColumn=>'bytes:320',$addressVersionColumn=>'bytes:256'],[$d[7]['scope'],$d[7]['subject']],[$d[7]['scope']=>$d[11]]);
    }
    /** Actual current account, mailbox and effective password/factor binding; locked admission only. */
    public function resetView(string $scope,string $subject,string $expected,string $addressColumn,string $addressVersionColumn):?array
    {
        $d=$this->d();self::name($addressColumn);self::name($addressVersionColumn);if($addressColumn===$addressVersionColumn||in_array($addressColumn,$d[7],true)||in_array($addressVersionColumn,$d[7],true)||!$d[2]->coversColumns($d[6],[$addressColumn=>'bytes:320',$addressVersionColumn=>'bytes:256'],[$d[7]['scope'],$d[7]['subject']],[$d[7]['scope']=>$d[11]])){self::invalid();}
        $identity=$this->credentialView($scope,$subject,null,$expected);if($identity===null){return null;}$selectors=$this->sqlSelectors($subject);$selectors['actor']['columns'][]=$addressColumn;$selectors['actor']['columns'][]=$addressVersionColumn;$view=$d[1]->capture([$d[4]=>$selectors]);if(!hash_equals($expected,$view->digest())){throw new StorageException('Reset account authority changed.','account.witness_stale');}$part=$view->part($d[4]);if(!$part instanceof SqlStateCapture||!$part->matches($d[2])){self::invalid();}$row=$part->row('actor');if($row===null){return null;}$account=$identity['account'];$record=new AccountRecord(new Account($scope,$subject,$row[$d[7]['credential_version']],true,$account->roles(),$account->mfaRequired()),new Address($row[$addressColumn]),$row[$addressVersionColumn],true,'active');
        return ['account'=>$account,'record'=>$record,'fingerprint'=>hash('sha256',json_encode(['SoSecurity.Password.Reset.Identity.1',$identity['fingerprint'],$record->fingerprint()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE))];
    }
    /** Actual native address identity and session from the same complete observed source. */
    public function addressView(string $scope,string $subject,string $token,string $expected,string $addressColumn,string $addressVersionColumn,bool $smtpUtf8=false):?array
    {
        $d=$this->d();self::name($addressColumn);self::name($addressVersionColumn);
        if($addressColumn===$addressVersionColumn||in_array($addressColumn,$d[7],true)||in_array($addressVersionColumn,$d[7],true)||!$d[2]->coversColumns($d[6],[$addressColumn=>'bytes:320',$addressVersionColumn=>'bytes:256'],[$d[7]['scope'],$d[7]['subject']],[$d[7]['scope']=>$d[11]])){self::invalid();}
        $identity=$this->credentialView($scope,$subject,$token,$expected);if($identity===null||$identity['session']===null){return null;}
        $selectors=$this->sqlSelectors($subject);$selectors['actor']['columns'][]=$addressColumn;$selectors['actor']['columns'][]=$addressVersionColumn;$view=$d[1]->capture([$d[4]=>$selectors]);
        if(!hash_equals($expected,$view->digest())){throw new StorageException('Address account authority changed.','account.witness_stale');}$part=$view->part($d[4]);if(!$part instanceof SqlStateCapture||!$part->matches($d[2])){self::invalid();}$row=$part->row('actor');if($row===null){return null;}$account=$identity['account'];
        $record=new AccountRecord(new Account($scope,$subject,$row[$d[7]['credential_version']],true,$account->roles(),$account->mfaRequired()),new Address($row[$addressColumn],$smtpUtf8),$row[$addressVersionColumn],true,'active');
        return $identity+['record'=>$record];
    }
    /** Pure agreement with the actual covered immutable HMAC key configuration. */
    public function signatureContext(\SoSecurity\Storage\AtomicStore $store,SessionRegistry $sessions,Clock $clock,StateBoundary $boundary,string $site,KeyRingStateSnapshot $keys,string $keyName):bool
    {
        $d=$this->d();return $this->linkContext($store,$sessions,$clock,$boundary,$site)&&$d[1]->contains($keyName,$keys)&&$keys->connection()===$d[2]->connection();
    }
    /** Physical file headroom is checked while native admission owns the exact witness lock. */
    public function credentialCapacity(string $key,string $expected):bool
    {
        $d=$this->d();$this->credentialBytes($key,$expected);$available=$d[3]->canStoreFile($d[8]->snapshotFile($key));if(!hash_equals($expected,$d[1]->digest())){throw new StorageException('Credential capacity source changed.','account.witness_stale');}return $available;
    }
    /** Exact account mapping agreement, without any state reads or permission grant. */
    public function maintenanceContext(SqlStateSnapshot $sql,string $table,array $columns):bool
    {
        $d=$this->d();if($d[2]!==$sql||$d[6]!==$table||count($columns)!==10){return false;}
        foreach($d[7] as $name=>$column){if(!isset($columns[$name])||$columns[$name]!==$column){return false;}}return true;
    }
    /** Read-only current permission from one complete source; use only inside an owned witness operation.
     * @phpstan-impure
     */
    public function maintenancePermission(StatePermission $permission,?string $expected=null):bool
    {
        $d=$this->d();$r=$permission->definition();if($r['scope']!==$d[11]||$r['self']||!$r['roles']){self::invalid();}
        $at=$this->now();$first=$d[1]->capture($this->selectors($permission));$digest=$first->digest();
        if($expected!==null&&!hash_equals($expected,$digest)){throw new StorageException('Maintenance permission source changed.','account.witness_stale');}
        $selectors=$this->completeSelectors($permission,$first,$at);if($selectors===null){return false;}$view=$d[1]->capture($selectors);$now=$this->now();
        if($now<$at){throw new StorageException('Maintenance permission clock moved backwards.','account.clock');}
        if(!hash_equals($digest,$view->digest())||!hash_equals($digest,$d[1]->digest())){throw new StorageException('Maintenance permission source changed.','account.witness_stale');}
        $finished=$this->now();if($finished<$now){throw new StorageException('Maintenance permission clock moved backwards.','account.clock');}return $this->allows($permission,$view,$finished);
    }
    /** Exact complete SQL audit coverage; no callback, SQL read or state mutation occurs here. */
    public function credentialAuditContext(\SoSecurity\Audit\AuditLogger $logger):?string
    {
        $d=$this->d();$context=$logger->stateContext($d[2]->connection(),$d[10],$d[14]);
        if($context===null||!$this->credentialSqlContext($d[2]->connection(),$context['tables'])
            ||$d[2]->maximumRows('sosecurity_audit_roots')<1
            ||$d[2]->maximumRows('sosecurity_audit_records')<$context['maximum_records']){return null;}
        return hash('sha256','SoSecurity.Account.CredentialAudit.1.'.$this->binding().'.'.$context['fingerprint']);
    }
    public function prepareCredentialAudit(\SoSecurity\Audit\AuditLogger $logger,string $subject,bool $allowed,\SoSecurity\Support\Deadline $deadline):\Closure
    {
        if($this->credentialAuditContext($logger)===null){self::invalid();}$d=$this->d();
        return $logger->prepareState($d[2]->connection(),$d[10],$d[14],$d[2]->maximumRows('sosecurity_audit_records'),$deadline,$d[11],$subject,$allowed);
    }
    public function credentialSqlContext(\PDO $pdo,array $tables):bool
    {
        $d=$this->d();if($d[2]->connection()!==$pdo||!$tables||count($tables)>4){return false;}
        foreach($tables as $table=>$spec){
            if(!is_string($table)||!is_array($spec)||array_diff(array_keys($spec),['columns','primary','where'])||!isset($spec['columns'],$spec['primary'])||!is_array($spec['columns'])||!is_array($spec['primary'])||(isset($spec['where'])&&!is_array($spec['where']))||!$d[2]->containsDefinition($table,$spec['columns'],$spec['primary'],$spec['where']??[])){return false;}
        }return true;
    }
    /** Read only exact native bytes from a full source capture. Callers must use locked witness admission. */
    public function credentialBytes(string $key,string $expected):?string
    {
        $d=$this->d();$file=$d[8]->snapshotFile($key);$view=$d[1]->capture([$d[5]=>['credential'=>$file]]);if(!hash_equals($expected,$view->digest())){throw new StorageException('Credential admission source changed.','account.witness_stale');}$part=$view->part($d[5]);if(!$part instanceof FileStateCapture||!$part->matches($d[3])){self::invalid();}return $part->file('credential');
    }
    /** Native current identity and optional session, reconstructed without providers, callbacks or state writes. */
    public function credentialView(string $scope,string $subject,?string $token,string $expected):?array
    {
        $d=$this->d();Guard::label($subject);if($scope!==$d[11]){self::invalid();}$at=$this->now();$selectors=[$d[4]=>$this->sqlSelectors($subject),$d[5]=>['session'=>$d[8]->snapshotFile(Guard::key('auth-sessions',$scope,$subject))]];$hint=$this->factorFileHint($scope,$subject);if($hint!==null){$selectors[$d[5]]['factor']=$hint;}$view=$d[1]->capture($selectors);
        return $this->credentialCaptured($scope,$subject,$token,$expected,$at,$selectors,$view);
    }
    /** Location only: the fresh directory still proves the exact reference. Mutable PDO attributes and hints.
     * @phpstan-impure
     */
    private function factorFileHint(string $scope,string $subject):?string
    {
        $hint=$this->factorFiles[hash('sha256',$subject)]??null;if($hint!==null){return $hint;}
        $d=$this->d();$pdo=$d[2]->connection();
        if(!$d[14] instanceof \SoSecurity\Support\SystemClock||get_class($pdo)!==\PDO::class||!\SoSecurity\Support\SqlStateAccess::pureEntryGuard($pdo)){return null;}
        try{if((int)$pdo->getAttribute(\PDO::ATTR_ERRMODE)!==\PDO::ERRMODE_EXCEPTION||$pdo->getAttribute(\PDO::ATTR_STATEMENT_CLASS)!==[\PDOStatement::class]||($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME)==='mysql'&&$pdo->getAttribute(\PDO::ATTR_EMULATE_PREPARES))){return null;}}catch(\Throwable $error){return null;}
        $reference=$d[9]->stateReference($scope,$subject,$d[17]);
        return $reference!==null&&$d[3]->coversReference($reference)?$reference['file']:null;
    }
    /** Capture the actual operator and target together; never cache authority across calls or accept caller captures. */
    public function credentialPair(string $scope,string $actor,?string $token,string $target,string $expected):array
    {
        $d=$this->d();Guard::label($actor);Guard::label($target);if($scope!==$d[11]){self::invalid();}
        if($actor===$target){$view=$this->credentialView($scope,$actor,$token,$expected);return ['actor'=>$view,'target'=>$view];}
        $at=$this->now();$selectors=[$d[4]=>[],$d[5]=>[]];$subjects=['a'=>$actor,'b'=>$target];
        foreach($subjects as $prefix=>$subject){
            foreach($this->sqlSelectors($subject) as $alias=>$selection){$selectors[$d[4]][$prefix.'_'.$alias]=$selection;}
            $selectors[$d[5]][$prefix.'_session']=$d[8]->snapshotFile(Guard::key('auth-sessions',$scope,$subject));
            $hint=$this->factorFileHint($scope,$subject);if($hint!==null){$selectors[$d[5]][$prefix.'_factor']=$hint;}
        }
        $view=$d[1]->capture($selectors);if(!hash_equals($expected,$view->digest())){throw new StorageException('Credential pair source changed.','account.witness_stale');}$parts=$this->parts($view);$result=[];
        foreach($subjects as $prefix=>$subject){
            $selected=$this->sqlSelectors($subject);$rows=[];foreach($selected as $alias=>$selection){$rows[$alias]=$parts[0]->row($prefix.'_'.$alias);}
            $single=[$d[4]=>$selected,$d[5]=>['session'=>$selectors[$d[5]][$prefix.'_session']]];$selectedFiles=['session'=>$parts[1]->file($prefix.'_session')];
            if(isset($selectors[$d[5]][$prefix.'_factor'])){$single[$d[5]]['factor']=$selectors[$d[5]][$prefix.'_factor'];$selectedFiles['factor']=$parts[1]->file($prefix.'_factor');}
            $captured=new CompositeStateCapture($d[1],$view->digest(),[
                $d[4]=>new SqlStateCapture($d[2],$parts[0]->digest(),$rows),
                $d[5]=>new FileStateCapture($d[3],$parts[1]->digest(),$selectedFiles)
            ]);
            $result[$prefix==='a'?'actor':'target']=$this->credentialCaptured($scope,$subject,$prefix==='a'?$token:null,$expected,$at,$single,$captured);
        }
        return $result;
    }
    /** Evaluate only a capture obtained internally from the exact complete source. */
    private function credentialCaptured(string $scope,string $subject,?string $token,string $expected,int $at,array $selectors,CompositeStateCapture $view):?array
    {
        $d=$this->d();
        if(!hash_equals($expected,$view->digest())){throw new StorageException('Credential authority source changed.','account.witness_stale');}$parts=$this->parts($view);$row=$parts[0]->row('actor');if($row===null){return null;}$a=[];foreach($d[7] as $name=>$column){$a[$name]=$row[$column];}
        if($a['scope']!==$scope||$a['subject']!==$subject||!in_array($a['status'],['active','pending','disabled'],true)||!in_array($a['verified'],[0,1],true)||!in_array($a['mfa_required'],[0,1],true)||!is_string($a['roles'])){throw new StorageException('Account permission fields are corrupt.','account.state_corrupt');}if($a['status']!=='active'||$a['verified']!==1){return null;}$roles=json_decode($a['roles'],true,3);if(!is_array($roles)||array_values($roles)!==$roles||json_encode($roles)!==$a['roles']){throw new StorageException('Account roles are corrupt.','account.state_corrupt');}
        if(!is_string($a['password'])){return null;}$account=(new PasswordRecord(new Account($scope,$subject,$a['credential_version'],true,$roles,$a['mfa_required']===1),$a['password']))->identity();$directory=$this->directorySubject($subject,$view,$at);if($directory===null){return null;}$binding=null;$factorFile=null;
        if($directory['factor_id']!==''){
            if(!$account->mfaRequired()){throw new StorageException('Account factor requirement differs from its pointer.','account.state_corrupt');}$reference=$d[9]->stateReference($directory['slot_scope'],$directory['slot_subject'],$d[17]);if($reference===null||!$d[3]->coversReference($reference)){self::invalid();}$factorFile=$reference['file'];
            // A remembered position is usable only after the current witnessed directory proves the same reference.
            if(($selectors[$d[5]]['factor']??null)!==$factorFile){$selectors[$d[5]]['factor']=$factorFile;$view=$d[1]->capture($selectors);if(!hash_equals($expected,$view->digest())){throw new StorageException('Credential factor source changed.','account.witness_stale');}$parts=$this->parts($view);}$raw=$parts[1]->file('factor');if($raw===null){return null;}
            $context=hash('sha256',json_encode(['SoSecurity.Mfa.ManagedContext.1',$d[10],$d[11],$d[12]],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));$key=Guard::key('mfa-totp',$directory['slot_scope'],$directory['slot_subject']);$frame=ManagedFactorFrame::read($context,$d[13],$key,Codec::decode($raw,$at));if($frame['migration']!==null&&$frame['migration']['state']!=='committed'){return null;}$factor=TotpFactorState::read($frame['payload'],$at);if($factor===null||$factor['enabled']===null||$factor['enabled']['id']!==$directory['factor_id']){return null;}$binding=FactorDirectoryState::binding($d[10],$d[11],$d[12],$directory);
        }elseif($account->mfaRequired()){return null;}
        $now=$this->now();if($now<$at||$parts[0]->row('directory')['updated_at']>$now){throw new StorageException('Credential authority clock moved backwards.','account.clock');}$fingerprint=hash('sha256',$account->fingerprint().':'.($binding===null?'none':strlen($binding).':'.$binding));$session=null;
        if($token!==null){$ref=SessionRegistry::reference($token);$raw=$parts[1]->file('session');if($ref===null||$raw===null){return null;}$state=RegistryState::read(Codec::decode($raw,$now),$now,$d[15],$d[16]);$record=$state===null?null:($state['sessions'][$ref['id']]??null);if($record===null||!hash_equals($record['digest'],$ref['digest'])||!hash_equals($record['fingerprint'],$fingerprint)||SessionRegistry::strength($record['method'])<($binding===null?0:2)){return null;}$session=new \SoSecurity\Auth\VerifiedSession($account,$ref['id'],$record['method'],$record['created'],$record['authenticated'],min($record['expires'],$record['created']+$d[16]),$record['resumed']);}
        $hintKey=hash('sha256',$subject);unset($this->factorFiles[$hintKey]);if($factorFile!==null){if(count($this->factorFiles)>=16){array_shift($this->factorFiles);}$this->factorFiles[$hintKey]=$factorFile;}
        return ['account'=>$account,'fingerprint'=>$fingerprint,'session'=>$session];
    }
    /** Current effect digest only; the exact already-active boundary is required. This grants no permission. */
    public function activePolicyDigest(StateBoundary $boundary):string
    {
        if(!$boundary->acceptsPolicy($this)){self::invalid();}$boundary->assertActive();return $this->d()[1]->digest();
    }
    /** Pure agreement with the complete SQL authority used by this account graph. */
    public function policySource(SqlStateSnapshot $source):bool{return $this->d()[2]===$source;}
    /** Capture bounded exact rows internally; caller-created capture objects are never accepted. */
    public function policyFacts(SqlStateSnapshot $source,array $selectors,string $expected):array
    {
        if(!$this->policySource($source)){self::invalid();}
        if($selectors===[]){$this->policyCurrent($expected);return [];}
        $selectors=$source->selections($selectors);
        foreach($selectors as $selection){if(isset($selection['page'])||isset($selection['count'])){self::invalid();}}
        $d=$this->d();$view=$d[1]->capture([$d[4]=>$selectors]);
        if(!hash_equals($expected,$view->digest())){throw new StorageException('Declared policy authority changed.','account.witness_stale');}
        $part=$view->part($d[4]);if(!$part instanceof SqlStateCapture||!$part->matches($source)){self::invalid();}
        $facts=[];foreach($selectors as $alias=>$selection){$facts[$alias]=$part->row($alias);}return $facts;
    }
    /** Re-observe the full graph after a declared read-only policy callback, including files and configuration. */
    public function policyCurrent(string $expected):void
    {
        if(!hash_equals($expected,$this->d()[1]->digest())){throw new StorageException('Declared policy changed protected authority.','account.witness_stale');}
    }
    public function __debugInfo():array{return ['state_account_policy'=>'[redacted]'];}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
