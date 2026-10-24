<?php
declare(strict_types=1);
namespace SoSecurity\Support;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

/** Internal owned or enlisted SQL unit. Never retries callbacks or an uncertain COMMIT. */
final class SqlTransaction
{
    private $pdo;
    private $driver;
    private $clock;
    private $milliseconds;
    private $deadline;
    private $observed=0;
    private $busy=false;
    private $failed=false;
    private $witness;
    private $lost=false;
    private $lastCommitted=false;
    private $observation=false;
    private $recovery;
    private $schemaChecks=[];
    private $lockedSchemaChecks=[];
    private $rollbackState;
    private $reading=false;
    private $combinedWitness;

    public function __construct(PDO $pdo,Clock $clock,int $milliseconds)
    {
        $driver=$pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if(PHP_INT_SIZE<8||!in_array($driver,['sqlite','mysql'],true)||(int)$pdo->getAttribute(PDO::ATTR_ERRMODE)!==PDO::ERRMODE_EXCEPTION||($driver==='mysql'&&$pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES))||$milliseconds<1||$milliseconds>30000){throw new ConfigurationException('Use exception-mode SQLite/MySQL, native MySQL prepares and a bounded SQL budget.','configuration.sql_transaction');}
        $this->pdo=$pdo;$this->driver=$driver;$this->clock=$clock;$this->milliseconds=$milliseconds;
    }
    public function driver():string {return $this->driver;}
    public function isObservation():bool {return $this->observation;}
    /** Internal concrete snapshot/metadata path; query writes and host callback invocation are forbidden. */
    public static function forObservation(PDO $pdo,Clock $clock,int $milliseconds):self
    {
        $unit=new self($pdo,$clock,$milliseconds);$unit->observation=true;return $unit;
    }
    /** Fixed containment is the only write path allowed without the quarantined business context. */
    public static function forAccountContainment(PDO $pdo,Clock $clock,int $milliseconds,\SoSecurity\Account\StateAccountContainment $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):self
    {
        $unit=new self($pdo,$clock,$milliseconds);
        $unit->recovery=static function()use($plan,$witness,$operation,$pdo):void{
            if(!$witness->usesConnection($pdo)||!$plan->boundTo($witness)||!$witness->containmentActive($plan,$operation)){throw new ConfigurationException('Use the exact approved fixed account containment.','configuration.state_containment');}
        };
        ($unit->recovery)();return $unit;
    }
    /** Fixed containment is the only write path allowed without the quarantined business context. */
    public static function forAccountResolution(PDO $pdo,Clock $clock,int $milliseconds,\SoSecurity\Account\StateAccountResolution $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):self
    {
        $unit=new self($pdo,$clock,$milliseconds);
        $unit->recovery=static function()use($plan,$witness,$operation,$pdo):void{
            if(!$witness->usesConnection($pdo)||!$plan->boundTo($witness)||!$witness->accountResolutionActive($plan,$operation)){throw new ConfigurationException('Use the exact approved fixed account resolution.','configuration.state_containment');}
        };
        ($unit->recovery)();return $unit;
    }
    /** Fixed containment is the only write path allowed without the quarantined business context. */
    public static function forCredentialInstallation(PDO $pdo,Clock $clock,int $milliseconds,\SoSecurity\Account\StateCredentialInstallation $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):self
    {
        $unit=new self($pdo,$clock,$milliseconds);
        $unit->recovery=static function()use($plan,$witness,$operation,$pdo):void{
            if(!$witness->usesConnection($pdo)||!$plan->boundTo($witness)||!$witness->credentialInstallationActive($plan,$operation)){throw new ConfigurationException('Use the exact approved fixed credential installation.','configuration.state_containment');}
        };
        ($unit->recovery)();return $unit;
    }
    public static function forWorkerHandoff(PDO $pdo,Clock $clock,int $milliseconds,\SoSecurity\Account\StateWorkerHandoff $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):self
    {
        $unit=new self($pdo,$clock,$milliseconds);
        $unit->recovery=static function()use($plan,$witness,$operation,$pdo):void{
            if(!$witness->usesConnection($pdo)||!$plan->boundTo($witness)||!$witness->workerHandoffActive($plan,$operation)){throw new ConfigurationException('Use the exact approved fixed worker handoff.','configuration.state_containment');}
        };
        ($unit->recovery)();return $unit;
    }
    /** Host admission may reenter or invalidate this unit. @phpstan-impure */
    private function stateAdmission():void
    {
        if($this->recovery!==null){($this->recovery)();}
        elseif(!$this->observation){SqlStateAccess::assertActive($this->pdo,$this->deadline);}
        elseif($this->deadline!==null){SqlStateAccess::restrictDeadline($this->pdo,$this->deadline,true);}
    }
    private function restrictDeadline(Deadline $deadline):Deadline
    {
        if($this->recovery===null){SqlStateAccess::restrictDeadline($this->pdo,$deadline,$this->observation);}return $deadline;
    }
    /** Reuse only within one MySQL statement batch under the owned savepoint and metadata locks.
     * Generic proofs expire at host callbacks. Concrete locked DDL proofs require fresh context checks; writes and transaction boundaries always expire them. */
    public function verifySchema(string $key,callable $verify,?callable $currentContext=null):void
    {
        $this->schemaProof($key,$verify,$currentContext,false);
    }
    /** Internal fixed proof: no caller callback can stand in for the current ledger context. */
    public function verifyLedgerSchema():?array
    {
        $unit=$this;if(!$unit->canBatchLedgerReads()){SqlSchema::durable($unit);}
        return $this->schemaProof('account-ledger-v1',static function()use($unit):void{
            SqlSchema::tables($unit,['sosecurity_account_roots'=>['types'=>\SoSecurity\Account\Ledger::rootTypes(),'primary'=>['namespace'],'indexes'=>[]],'sosecurity_account_records'=>['types'=>\SoSecurity\Account\Ledger::recordTypes(),'primary'=>['namespace','record_id'],'indexes'=>\SoSecurity\Account\Ledger::indexes()]]);
        },static function()use($unit):array{return SqlSchema::ledgerSchemaContext($unit);},true);
    }
    private function schemaProof(string $key,callable $verify,?callable $currentContext,bool $fixedContext):?array
    {
        $this->now();
        // A host clock, entry guard, PDO or statement override can change database/authority
        // without ending this savepoint. Only concrete callback-free execution can reuse proof.
        if($this->driver!=='mysql'||$this->witness===null||!$this->clock instanceof SystemClock
            ||get_class($this->pdo)!==PDO::class||!SqlStateAccess::pureEntryGuard($this->pdo)
            ||$this->pdo->getAttribute(PDO::ATTR_STATEMENT_CLASS)!==[\PDOStatement::class]){$this->schemaChecks=[];$this->lockedSchemaChecks=[];$verify();return null;}
        if($currentContext!==null){
            if(isset($this->lockedSchemaChecks[$key])&&$this->lockedSchemaChecks[$key][0]===$this->witness&&($this->lockedSchemaChecks[$key][2]??false)===$fixedContext){
                $context=$this->schemaContext($currentContext,$fixedContext);
                if($context===$this->lockedSchemaChecks[$key][1]){return $fixedContext?$context:null;}
            }
            if(count($this->lockedSchemaChecks)>=8){$this->lockedSchemaChecks=[];}
            $verify();$context=$this->schemaContext($currentContext,$fixedContext);
            $this->lockedSchemaChecks[$key]=[$this->witness,$context,$fixedContext];return $fixedContext?$context:null;
        }
        if(isset($this->schemaChecks[$key])&&$this->schemaChecks[$key]===$this->witness){$this->witness();return null;}
        if(count($this->schemaChecks)>=8){$this->schemaChecks=[];$this->lockedSchemaChecks=[];}
        $verify();$this->witness();$this->schemaChecks[$key]=$this->witness;return null;
    }
    /** Only fixed ledger DDL locks survive a final host callback in this same witnessed transaction.
     * Authorization and physical resolution remain fresh in schemaContext(); generic certificates expire.
     * @phpstan-impure
     */
    private function finalCallbackProofs():void
    {
        $this->schemaChecks=[];
        $entry=$this->witness!==null&&$this->canBatchLedgerReads()?($this->lockedSchemaChecks['account-ledger-v1']??null):null;
        $this->lockedSchemaChecks=$entry!==null&&$entry[0]===$this->witness&&($entry[2]??false)===true?['account-ledger-v1'=>$entry]:[];
    }
    private function schemaContext(callable $currentContext,bool $fixedContext)
    {
        $this->witness();$native=$fixedContext&&$this->canBatchLedgerReads();$context=$currentContext();
        // Only the fixed internal read can cross this interval without host code. Generic callbacks always re-prove ownership.
        if(!$native||!$this->canBatchLedgerReads()){$this->witness();}return $context;
    }
    /** Only a real owned SQL rollback and the exact completed protected execution can confirm refusal. */
    public function refusalGuard():?\Closure
    {
        if(!$this->busy||$this->witness===null||$this->rollbackState===null){return null;}$this->now();
        $scope=SqlStateAccess::refusalScope($this->pdo);if($scope===null){return null;}$state=$this->rollbackState;
        return static function()use($state,$scope):bool{return $state->confirmed===true&&$scope()===true;};
    }
    public function connection():PDO {return $this->pdo;}
    public function committed():bool {return $this->lastCommitted;}
    public function prefix():string {return $this->driver==='sqlite'?'main.':'';}
    /** Business calls must stop after uncertain cleanup; rollback uses witness(false). */
    private function assertUsable():void
    {
        if($this->failed){throw new StorageException('Security SQL cleanup or ownership is uncertain; rebuild the connection.','sql.cleanup');}
    }
    /** @phpstan-impure */
    public function now():int
    {
        $this->assertUsable();$this->stateAdmission();$this->assertUsable();
        if(!$this->busy||$this->deadline===null){throw new ConfigurationException('SQL unit is not active.','configuration.sql_transaction');}
        $this->deadline->check('sql.timeout');
        try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Security clock unavailable.','sql.clock');}
        $this->assertUsable();
        if($now<0||$now>PHP_INT_MAX-31536001||$now<$this->observed){throw new StorageException('Security clock is invalid or moved backwards.','sql.clock');}
        // Admission and clocks can invoke host code. Recheck mutable execution policy after both:
        // emulated prepares can execute multiple statements, including on a borrowed read-only unit.
        try{$valid=(int)$this->pdo->getAttribute(PDO::ATTR_ERRMODE)===PDO::ERRMODE_EXCEPTION&&($this->driver!=='mysql'||!$this->pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES));}
        catch(\Throwable $error){$valid=false;}
        if(!$valid){throw new ConfigurationException('Use exception-mode SQLite/MySQL and native MySQL prepares throughout SQL execution.','configuration.sql_transaction');}
        $this->observed=$now;return $now;
    }
    public function query(string $sql,array $parameters=[],array $blobs=[]):\PDOStatement
    {
        if(($this->observation||$this->reading)&&!preg_match('/\ASELECT\b/i',$sql)&&!in_array($sql,['PRAGMA database_list','PRAGMA main.journal_mode','PRAGMA main.synchronous','PRAGMA busy_timeout'],true)){throw new ConfigurationException('Read-only units cannot change SQL state.','configuration.state_observation');}
        if(!preg_match('/\ASELECT\b/i',$sql)){$this->schemaChecks=[];$this->lockedSchemaChecks=[];}
        $this->now();$query=$this->pdo->prepare($sql);
        if($query===false){throw new StorageException('Cannot prepare a security statement.','sql.unavailable');}
        try{
            $this->now();
            foreach($parameters as $name=>$value){$type=$value===null?PDO::PARAM_NULL:(is_int($value)?PDO::PARAM_INT:(in_array($name,$blobs,true)?PDO::PARAM_LOB:PDO::PARAM_STR));if(!$query->bindValue(':'.$name,$value,$type)){throw new StorageException('Cannot bind a security statement.','sql.unavailable');}}
            $this->now();if(!$query->execute()){throw new StorageException('Security statement failed.','sql.unavailable');}$this->now();return $query;
        }catch(\Throwable $error){
            // Failed SQLite statements may retain an active cursor through the exception trace and block RELEASE.
            try{if(!$query->closeCursor()){$this->failed=true;}}catch(\Throwable $cleanup){$this->failed=true;}
            throw $error;
        }
    }
    /** Complete an internal write before its result can be observed; never leave uncertain cleanup usable. */
    public function execute(string $sql,array $parameters=[],array $blobs=[]):int
    {
        $this->assertUsable();
        if(!preg_match('/\A(?:INSERT|UPDATE|DELETE)\b/i',$sql)){throw new ConfigurationException('Use an explicit SQL data write.','configuration.sql_transaction');}
        $query=$this->query($sql,$parameters,$blobs);$valid=true;$count=0;
        try{$count=SqlSchema::integer($query->rowCount());}catch(\Throwable $error){$valid=false;}
        try{$closed=$query->closeCursor();}catch(\Throwable $error){$closed=false;}
        if(!$closed){$this->failed=true;throw new StorageException('Security write cursor cleanup failed.','sql.cleanup');}
        if(!$valid){$this->failed=true;throw new StorageException('Security write result unavailable.','sql.unavailable');}
        return $count;
    }
    /** SELECT metadata and three exact SQLite policy PRAGMAs; every call executes and closes its cursor. */
    public function metadataRows(string $sql,array $parameters=[],?string $ledgerDatabase=null):array
    {
        if(!preg_match('/\ASELECT\b/i',$sql)&&!($this->driver==='sqlite'&&$parameters===[]&&in_array($sql,['PRAGMA database_list','PRAGMA main.journal_mode','PRAGMA main.synchronous'],true))){throw new ConfigurationException('Metadata reads cannot change SQL state.','configuration.sql_schema');}
        if($this->driver!=='mysql'||!SqlStateAccess::isProtected($this->pdo)){
            return $this->closedRows($this->query($sql,$parameters));
        }
        try{return SqlStateAccess::metadataRows($this,$sql,$parameters,$ledgerDatabase);}
        catch(StorageException $error){if($error->reason()==='sql.cleanup'){$this->failed=true;}throw $error;}
    }
    private function closedRows(\PDOStatement $query):array
    {
        $failure=null;
        try{$rows=$query->fetchAll(PDO::FETCH_ASSOC);}catch(\Throwable $error){$failure=$error;}
        try{$closed=$query->closeCursor();}catch(\Throwable $error){$closed=false;}
        if(!$closed){$this->failed=true;throw new StorageException('Security metadata cursor cleanup failed.','sql.cleanup');}
        if($failure!==null){throw $failure;}return $rows;
    }
    /** Read fresh session policy and release its cursor before changing connection state. */
    private function lockTimeout():int
    {
        $rows=$this->driver==='mysql'?$this->metadataRows('SELECT @@SESSION.innodb_lock_wait_timeout'):$this->closedRows($this->query('PRAGMA busy_timeout'));
        if(count($rows)!==1||!is_array($rows[0])||count($rows[0])!==1){throw new StorageException('Invalid SQL lock timeout state.','sql.corrupt');}
        return SqlSchema::integer(reset($rows[0]));
    }
    /** Fresh values only; no host callback can run between this native read and the policy commands.
     * @return array{0:int,1:int}|null
     * @phpstan-impure
     */
    private function nativeWaitTimeouts():?array
    {
        if(!$this->nativeLockPolicy()){return null;}
        $rows=$this->metadataRows('SELECT @@SESSION.innodb_lock_wait_timeout AS row_wait,@@SESSION.lock_wait_timeout AS metadata_wait');
        if(count($rows)!==1||!is_array($rows[0])||count($rows[0])!==2){throw new StorageException('Invalid SQL wait timeout state.','sql.corrupt');}
        $values=array_values($rows[0]);$values=[SqlSchema::integer($values[0]),SqlSchema::integer($values[1])];
        return $this->nativeLockPolicy()?$values:null;
    }
    /** Fresh native values are captured together; the later metadata cap still follows elapsed time.
     * @param-out int $row
     */
    private function limitReadTimeouts(?int &$row,?int &$metadata):void
    {
        $values=$this->nativeWaitTimeouts();
        if($values!==null){
            $row=$values[0];$value=$values[1];
            if($value<1||$value>31536000){throw new StorageException('Invalid SQL metadata lock timeout state.','sql.corrupt');}
            $metadata=$value;$remaining=max(1,(int)ceil($this->deadline->remaining()));
            $rowLimit=min($row,$remaining);$metadataLimit=min($metadata,$remaining);
            if($rowLimit!==$row||$metadataLimit!==$metadata){$this->command('SET SESSION innodb_lock_wait_timeout='.$rowLimit.',lock_wait_timeout='.$metadataLimit);}
            // Match the original second setting when the first transport crosses a second boundary.
            $later=min($metadata,max(1,(int)ceil($this->deadline->remaining())));
            if($later<$metadataLimit){$this->command('SET SESSION lock_wait_timeout='.$later);}
            return;
        }
        $row=$this->lockTimeout();$limit=min($row,max(1,(int)ceil($this->deadline->remaining()*($this->driver==='sqlite'?1000:1))));
        if($limit!==$row){$this->command(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$limit);}
        $this->metadataTimeout($metadata);
    }
    /** Capture before SET so a rejected or interrupted change still restores the original session policy. */
    private function metadataTimeout(?int &$original,?int $captured=null):void
    {
        if($this->driver!=='mysql'){return;}
        if($captured===null){
            $rows=$this->metadataRows('SELECT @@SESSION.lock_wait_timeout');
            if(count($rows)!==1||!is_array($rows[0])||count($rows[0])!==1){throw new StorageException('Invalid SQL metadata lock timeout state.','sql.corrupt');}
            $value=SqlSchema::integer(reset($rows[0]));
        }else{$value=$captured;}
        if($value<1||$value>31536000){throw new StorageException('Invalid SQL metadata lock timeout state.','sql.corrupt');}
        $original=$value;$limit=min($value,max(1,(int)ceil($this->deadline->remaining())));
        if($limit!==$value){$this->command('SET SESSION lock_wait_timeout='.$limit);}
    }
    private function restoreMetadataTimeout(?int $original):void
    {
        if($original!==null&&!$this->failed){try{$this->command('SET SESSION lock_wait_timeout='.$original);}catch(\Throwable $error){$this->failed=true;}}
    }
    /** A read may call a host clock or statement adapter even when entry needed no SET. */
    private function restoreReadTimeouts(?int $row,?int $metadata):void
    {
        if($this->failed){return;}
        if($row!==null&&$metadata!==null&&$this->nativeLockPolicy()){
            try{$this->command('SET SESSION innodb_lock_wait_timeout='.$row.',lock_wait_timeout='.$metadata);}catch(\Throwable $error){$this->failed=true;}
            return;
        }
        $this->restoreMetadataTimeout($metadata);
        if($row!==null&&!$this->failed){try{$this->command(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$row);}catch(\Throwable $error){$this->failed=true;}}
    }
    /** Reads mutable PDO attributes and the current entry guard.
     * @phpstan-impure
     */
    private function nativeLockPolicy():bool
    {
        if($this->driver!=='mysql'||$this->recovery!==null||!$this->clock instanceof SystemClock||get_class($this->pdo)!==PDO::class||!SqlStateAccess::pureEntryGuard($this->pdo)){return false;}
        try{return (int)$this->pdo->getAttribute(PDO::ATTR_ERRMODE)===PDO::ERRMODE_EXCEPTION&&!$this->pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES)&&$this->pdo->getAttribute(PDO::ATTR_STATEMENT_CLASS)===[\PDOStatement::class];}
        catch(\Throwable $error){return false;}
    }
    /** Internal code identity only; reads mutable PDO attributes.
     * @phpstan-impure
     */
    public function canBatchLedgerReads():bool
    {
        if(!$this->nativeLockPolicy()){return false;}
        try{return (int)$this->pdo->getAttribute(PDO::ATTR_CASE)===PDO::CASE_NATURAL;}
        catch(\Throwable $error){return false;}
    }
    private function command(string $sql):void
    {
        $this->stateAdmission();
        if($this->pdo->exec($sql)===false){throw new StorageException('Security transaction failed.','sql.unavailable');}
    }
    private function assertIdle():void
    {
        SqlTransactionGuard::assertIdle($this->pdo,$this->driver,$this->deadline);
        if($this->driver!=='sqlite'){return;}
        // Old PDO SQLite omits SQL-started transactions from inTransaction(). BEGIN fails without changing them.
        try{$this->command('BEGIN DEFERRED');}
        catch(\PDOException $error){
            $info=$error->errorInfo;
            if(isset($info[1],$info[2])&&(int)$info[1]===1&&$info[2]==='cannot start a transaction within a transaction'){throw new ConfigurationException('Refuse an SQL-started host transaction.','configuration.transaction');}
            throw new StorageException('Cannot inspect SQLite transaction ownership.','sql.unavailable');
        }
        // Only our successfully started, empty probe is rolled back. Deadline/clock errors cannot skip its cleanup.
        try{$this->command('ROLLBACK');}catch(\Throwable $error){$this->failed=true;throw new StorageException('Cannot finish the empty transaction probe.','sql.cleanup');}
        $this->now();
    }
    private function witness(bool $checkClock=true):void
    {
        if($checkClock){$this->assertUsable();}
        if($this->witness===null){return;}
        try{
            $combined=false;
            if($this->driver==='mysql'&&$this->recovery===null&&$this->combinedWitness!==false
                &&$this->clock instanceof SystemClock&&get_class($this->pdo)===PDO::class&&SqlStateAccess::pureEntryGuard($this->pdo)
                &&(int)$this->pdo->getAttribute(PDO::ATTR_ERRMODE)===PDO::ERRMODE_EXCEPTION&&!$this->pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES)
                &&$this->pdo->getAttribute(PDO::ATTR_STATEMENT_CLASS)===[\PDOStatement::class]){
                $this->stateAdmission();
                try{
                    // Both fixed control commands affect zero rows. Old PDO can return 1 on a later error.
                    if($this->pdo->exec('RELEASE SAVEPOINT '.$this->witness.'; SAVEPOINT '.$this->witness)!==0){throw new StorageException('Cannot confirm the complete transaction witness.','sql.unavailable');}
                    $this->combinedWitness=true;$combined=true;
                }catch(\PDOException $error){
                    $info=$error->errorInfo;
                    if($this->combinedWitness===true||!is_array($info)||($info[0]??null)!=='42000'||(int)($info[1]??0)!==1064){throw $error;}
                    // A disabled multi-statement connection retains the original command path and options.
                    // RELEASE below must still prove that the old witness exists before it is recreated.
                    $this->combinedWitness=false;
                }
                if($combined){$this->stateAdmission();}
            }
            if(!$combined){$this->command('RELEASE SAVEPOINT '.$this->witness);$this->command('SAVEPOINT '.$this->witness);}
        }
        catch(\Throwable $error){$this->lost=true;$this->failed=true;throw new ConfigurationException('A callback ended or replaced the security transaction.','configuration.sql_transaction_lost');}
        if($checkClock){$this->now();}
    }
    /** Arguments are local copies, including when a trusted callback declares reference parameters. */
    public function invoke(callable $callback,array $arguments,string $reason)
    {
        if($this->observation||$this->reading){throw new ConfigurationException('Read-only units cannot invoke host callbacks.','configuration.state_observation');}
        $this->schemaChecks=[];$this->now();$local=array_values($arguments);$references=[];foreach($local as &$value){$references[]=&$value;}unset($value);
        $failed=false;$result=null;
        try{$result=call_user_func_array($callback,$references);}catch(\Throwable $error){$failed=true;}
        $this->schemaChecks=[];$this->witness();$this->now();
        if($failed){$this->lockedSchemaChecks=[];throw new DependencyException('Security callback unavailable.',$reason);}
        return $result;
    }
    /**
     * Join an existing host transaction without committing or rolling back that transaction.
     * A successful result is provisional until the host commits. Any failure must abort the enclosing business unit.
     * @param-immediately-invoked-callable $body
     * @param-immediately-invoked-callable $preflight
     * @param-immediately-invoked-callable $beforeRelease
     */
    public function enlist(callable $body,?callable $preflight=null,?callable $beforeRelease=null,?Deadline $budget=null)
    {
        return $this->enlisted($body,$preflight,$beforeRelease,$budget,false);
    }
    /** Select ownership once at entry. Host results remain provisional; an inactive entry owns its transaction.
     * @param-immediately-invoked-callable $body
     * @param-immediately-invoked-callable $beforeFinish
     * @phpstan-impure
     */
    public function inContext(callable $body,?callable $beforeFinish=null,?Deadline $budget=null)
    {
        if($this->observation){throw new ConfigurationException('Observation units own their complete snapshot transaction.','configuration.state_observation');}
        if($this->busy||$this->failed){throw new StorageException('Rebuild a failed or busy security SQL service.','sql.cleanup');}
        $budget=$this->restrictDeadline($budget??new Deadline($this->milliseconds));
        // Unknown entry guards may change the transaction; retain the original selection and recheck around them.
        if(!SqlStateAccess::pureEntryGuard($this->pdo)){
            $active=SqlTransactionGuard::active($this->pdo,$this->driver,$budget);
            return $active?$this->enlist($body,null,$beforeFinish,$budget):$this->run($body,null,$beforeFinish,null,$budget);
        }
        return $this->enlisted($body,null,$beforeFinish,$budget,true);
    }
    /** Internal concrete SQL reads only: no host callbacks, writes or external effects in $body.
     * Preserve the child's clock and budget while borrowing an exact live owner's transaction.
     * @param-immediately-invoked-callable $body
     */
    public function readIn(self $owner,callable $body,?Deadline $budget=null)
    {
        if($owner===$this||$owner->pdo!==$this->pdo||!$owner->busy||$owner->witness===null||$owner->deadline===null||$owner->failed||$owner->observation||$owner->reading||$this->observation){throw new ConfigurationException('Use an exact live SQL owner for concrete reads.','configuration.sql_transaction');}
        if($this->busy||$this->failed){throw new StorageException('Rebuild a failed or busy security SQL service.','sql.cleanup');}
        $deadline=$budget??new Deadline($this->milliseconds);$deadline->restrictTo($owner->deadline);$this->restrictDeadline($deadline);
        $owner->witness();
        // Unknown entry guards can change SQL state on every now(); never share certificates across them.
        if(!SqlStateAccess::pureEntryGuard($this->pdo)){
            // The conservative transaction path still owns a read-only child, including guard reentry.
            $this->reading=true;$failure=null;$result=null;
            try{$result=$this->inContext($body,null,$deadline);$owner->now();}
            catch(SecurityException|ConfigurationException $error){$failure=$error;}
            catch(\Throwable $error){$failure=new StorageException('Concrete security SQL read unavailable.','sql.unavailable');}
            finally{
                // The child's separate savepoint does not prove that the original parent survived.
                // Probe only after the nested scope has closed: SQLite RELEASE also drops later points.
                try{$owner->witness(false);}catch(\Throwable $error){$this->failed=true;}
                $this->reading=false;
                if($owner->failed){$this->failed=true;$this->lost=$this->lost||$owner->lost;}
                if($this->failed){$owner->failed=true;$owner->lost=$owner->lost||$this->lost;}
            }
            // Throw outside unwinding so PHP cannot chain an untrusted guard exception.
            if($this->failed){throw new StorageException('Concrete SQL read cleanup or ownership is uncertain; abort the host unit.','sql.cleanup');}
            if($failure!==null){throw $failure;}
            $deadline->check('sql.timeout');return $result;
        }
        $this->busy=true;$this->reading=true;$this->deadline=$deadline;$this->witness=$owner->witness;$this->lost=false;$this->lastCommitted=false;
        $this->schemaChecks=&$owner->schemaChecks;$this->lockedSchemaChecks=&$owner->lockedSchemaChecks;$this->combinedWitness=&$owner->combinedWitness;
        $timeout=null;$metadataTimeout=null;$failure=null;$result=null;
        try{
            $this->now();
            $this->limitReadTimeouts($timeout,$metadataTimeout);
            $this->now();$result=$body();$this->now();$owner->now();
        }catch(SecurityException | ConfigurationException $error){$failure=$error;}
        catch(\Throwable $error){$failure=new StorageException('Concrete security SQL read unavailable.','sql.unavailable');}
        finally{
            // Always test ownership, even on a deadline/clock failure. Never commit or roll back the owner.
            try{$this->witness(false);}catch(\Throwable $error){$this->failed=true;}
            $this->restoreReadTimeouts($timeout,$metadataTimeout);
            if($failure!==null||$this->failed){$this->schemaChecks=[];$this->lockedSchemaChecks=[];}
            if($this->failed){$owner->failed=true;$owner->lost=$owner->lost||$this->lost;}
            unset($this->schemaChecks,$this->lockedSchemaChecks,$this->combinedWitness);$this->schemaChecks=[];$this->lockedSchemaChecks=[];$this->combinedWitness=null;
            $this->busy=false;$this->reading=false;$this->deadline=null;$this->witness=null;
        }
        if($this->failed){throw new StorageException('Concrete SQL read cleanup or ownership is uncertain; abort the host unit.','sql.cleanup');}
        if($failure!==null){throw $failure;}
        $deadline->check('sql.timeout');$owner->now();return $result;
    }
    /** @param-immediately-invoked-callable $body
     * @param-immediately-invoked-callable $preflight
     * @param-immediately-invoked-callable $beforeRelease
     */
    private function enlisted(callable $body,?callable $preflight,?callable $beforeRelease,?Deadline $budget,bool $allowOwned)
    {
        if($this->observation){throw new ConfigurationException('Observation units own their complete snapshot transaction.','configuration.state_observation');}
        if($this->busy||$this->failed){throw new StorageException('Rebuild a failed or busy security SQL service.','sql.cleanup');}
        $this->stateAdmission();
        if($this->observation){throw new ConfigurationException('Observation units own their complete snapshot transaction.','configuration.state_observation');}
        if($this->busy||$this->failed){throw new StorageException('Rebuild a failed or busy security SQL service.','sql.cleanup');}
        // The rollback boundary never moves. invoke() refreshes only the separate ownership witness.
        $boundary='sosecurity_enlisted_'.bin2hex(random_bytes(16));$name='sosecurity_witness_'.bin2hex(random_bytes(16));
        $deadline=$this->restrictDeadline($budget??new Deadline($this->milliseconds));
        $this->busy=true;$this->deadline=$deadline;$this->lost=false;$this->witness=null;$this->lastCommitted=false;$this->schemaChecks=[];$this->lockedSchemaChecks=[];$this->rollbackState=null;
        $joined=false;$released=false;$timeout=null;$metadataTimeout=null;$selectOwned=false;$sharedBudget=$this->deadline;
        $entryNative=$allowOwned&&$this->nativeLockPolicy();
        try{
            try{if($allowOwned){$selectOwned=!SqlTransactionGuard::active($this->pdo,$this->driver,$this->deadline);}else{SqlTransactionGuard::assertActive($this->pdo,$this->driver,$this->deadline);}}
            catch(StorageException $error){$this->failed=true;throw $error;}
            if(!$selectOwned){
                $this->now();
                $joined=true;$this->command('SAVEPOINT '.$boundary);
                $this->command('SAVEPOINT '.$name);$this->witness=$name;$this->now();
                if($this->driver==='sqlite'){
                    $timeout=$this->lockTimeout();
                    $this->command('PRAGMA busy_timeout='.min($timeout,max(1,(int)ceil($this->deadline->remaining()*1000))));
                }else{
                    $native=$this->nativeLockPolicy();
                    $timeout=$this->lockTimeout();
                    $limit=min($timeout,max(1,(int)ceil($this->deadline->remaining())));
                    if(!$native||!$this->nativeLockPolicy()||$limit!==$timeout){$this->command('SET SESSION innodb_lock_wait_timeout='.$limit);}
                }
                $this->metadataTimeout($metadataTimeout);
                if($preflight!==null&&$this->invoke($preflight,[],'sql.authority')!==true){return null;}
                $this->now();$result=$body();$this->witness();
                if($beforeRelease!==null){$this->finalCallbackProofs();$beforeRelease($result);$this->finalCallbackProofs();$this->witness();}$this->now();
                // Release our current witness and then our older fixed rollback boundary explicitly.
                $this->command('RELEASE SAVEPOINT '.$name);$this->witness=null;
                $this->command('RELEASE SAVEPOINT '.$boundary);$released=true;
                // If this returns late, the caller must abort the host unit: the local rollback boundary is already gone.
                try{$this->now();}catch(\Throwable $error){$this->failed=true;throw $error;}
                return $result;
            }
        }catch(SecurityException $error){throw $error;}
        catch(ConfigurationException $error){throw $error;}
        catch(\Throwable $error){throw new StorageException('Enlisted security SQL operation unavailable.','sql.unavailable');}
        finally{
            if($joined&&!$released&&!$this->lost){
                try{
                    // Never perform an outer ROLLBACK, even after timeout/clock failure. A missing point poisons this unit.
                    $this->witness(false);
                    if($this->witness!==null){$this->command('RELEASE SAVEPOINT '.$name);$this->witness=null;}
                    $this->command('ROLLBACK TO SAVEPOINT '.$boundary);
                    $this->command('RELEASE SAVEPOINT '.$boundary);
                }catch(\Throwable $error){$this->failed=true;}
            }
            $this->restoreMetadataTimeout($metadataTimeout);
            if($timeout!==null&&!$this->failed){try{$this->command(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$timeout);}catch(\Throwable $error){$this->failed=true;}}
            try{if($this->failed){throw new StorageException('Enlisted SQL cleanup or ownership is uncertain; abort the host unit and rebuild the connection.','sql.cleanup');}}
            finally{$this->busy=false;$this->deadline=null;$this->witness=null;$this->schemaChecks=[];$this->lockedSchemaChecks=[];}
        }
        // Only a confirmed inactive entry reaches this branch; callback failures never select another path.
        return $this->owned($body,$preflight,$beforeRelease,null,$sharedBudget,$entryNative&&$this->nativeLockPolicy());
    }
    /**
     * These callbacks run synchronously within this call and can exchange state through local reference captures.
     * @param-immediately-invoked-callable $body
     * @param-immediately-invoked-callable $preflight
     * @param-immediately-invoked-callable $beforeCommit
     * @param-immediately-invoked-callable $afterCommit
     */
    public function run(callable $body,?callable $preflight=null,?callable $beforeCommit=null,?callable $afterCommit=null,?Deadline $budget=null)
    {
        return $this->owned($body,$preflight,$beforeCommit,$afterCommit,$budget,false);
    }
    /** The private entry proof crosses no host code and is never retained beyond this call.
     * @param-immediately-invoked-callable $body
     * @param-immediately-invoked-callable $preflight
     * @param-immediately-invoked-callable $beforeCommit
     * @param-immediately-invoked-callable $afterCommit
     */
    private function owned(callable $body,?callable $preflight,?callable $beforeCommit,?callable $afterCommit,?Deadline $budget,bool $entryChecked)
    {
        if($this->busy||$this->failed){throw new StorageException('Rebuild a failed or busy security SQL service.','sql.cleanup');}
        $this->stateAdmission();
        if($this->busy||$this->failed){throw new StorageException('Rebuild a failed or busy security SQL service.','sql.cleanup');}
        $deadline=$this->restrictDeadline($budget??new Deadline($this->milliseconds));
        $name='sosecurity_unit_'.bin2hex(random_bytes(16));$this->busy=true;$this->deadline=$deadline;$this->lost=false;$this->witness=null;$this->lastCommitted=false;$this->schemaChecks=[];$this->lockedSchemaChecks=[];$this->rollbackState=(object)['confirmed'=>false];
        $owned=false;$timeout=null;$metadataTimeout=null;$committed=false;$commitAttempted=false;$result=null;$rolledBack=false;
        try{
            $nativeIdle=$this->nativeLockPolicy();
            if(!$entryChecked||!$nativeIdle){$this->assertIdle();}$this->now();
            if($preflight!==null&&$this->invoke($preflight,[],'sql.authority')!==true){return null;}
            // Native now()/admission cannot replace the transaction; every host preflight still expires the proof.
            if($preflight!==null||!$nativeIdle||!$this->nativeLockPolicy()){$this->assertIdle();}
            if($this->driver==='sqlite'){
                $timeout=$this->lockTimeout();
                $this->command('PRAGMA busy_timeout='.min($timeout,max(1,(int)ceil($this->deadline->remaining()*1000))));$this->command('BEGIN IMMEDIATE');$owned=true;
            }else{
                $native=$this->nativeLockPolicy();
                $timeout=$this->lockTimeout();
                $limit=min($timeout,max(1,(int)ceil($this->deadline->remaining())));
                // Skip only a proven redundant entry command; finally still reasserts the original value.
                if(!$native||!$this->nativeLockPolicy()||$limit!==$timeout){$this->command('SET SESSION innodb_lock_wait_timeout='.$limit);}
                $this->metadataTimeout($metadataTimeout);
                if(!$this->pdo->beginTransaction()){throw new StorageException('Cannot begin a security transaction.','sql.unavailable');}$owned=true;
            }
            $this->command('SAVEPOINT '.$name);$this->witness=$name;$this->now();$result=$body();$this->witness();
            if($beforeCommit!==null){$this->finalCallbackProofs();$beforeCommit($result);$this->finalCallbackProofs();$this->witness();}$this->now();$commitAttempted=true;
            if($this->driver==='sqlite'){$this->command('COMMIT');}elseif(!$this->pdo->commit()){throw new StorageException('Commit was not confirmed.','sql.commit');}
            $owned=false;$committed=true;$this->lastCommitted=true;$this->witness=null;$this->now();return $result;
        }catch(SecurityException $error){throw $error;}
        catch(ConfigurationException $error){throw $error;}
        catch(\Throwable $error){throw new StorageException('Security SQL operation unavailable.','sql.unavailable');}
        finally{
            if($owned&&!$this->lost){
                try{$this->witness(false);if($this->driver==='sqlite'){$this->command('ROLLBACK');$rolledBack=true;}elseif(!$this->pdo->rollBack()){$this->failed=true;}else{$rolledBack=true;}}
                catch(\Throwable $error){$this->failed=true;}
            }
            if($commitAttempted&&!$committed){$this->failed=true;}
            $this->restoreMetadataTimeout($metadataTimeout);
            if($timeout!==null&&!$this->failed){try{$this->command(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$timeout);}catch(\Throwable $error){$this->failed=true;}}
            try{
                if($this->failed){throw new StorageException('Security SQL cleanup or ownership is uncertain; rebuild the connection.','sql.cleanup');}
                if($committed){$this->now();if($afterCommit!==null){$this->schemaChecks=[];$this->lockedSchemaChecks=[];$afterCommit($result);$this->schemaChecks=[];$this->lockedSchemaChecks=[];$this->now();}}
            }finally{$this->rollbackState->confirmed=$rolledBack&&!$commitAttempted&&!$committed&&!$this->failed&&!$this->lost;$this->busy=false;$this->deadline=null;$this->witness=null;$this->schemaChecks=[];$this->lockedSchemaChecks=[];$this->rollbackState=null;}
        }
    }
    public function __debugInfo():array {return ['sql'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild SQL services from trusted configuration.','configuration.sql_serialization');}
}
