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

    public function __construct(PDO $pdo,Clock $clock,int $milliseconds)
    {
        $driver=$pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if(PHP_INT_SIZE<8||!in_array($driver,['sqlite','mysql'],true)||(int)$pdo->getAttribute(PDO::ATTR_ERRMODE)!==PDO::ERRMODE_EXCEPTION||($driver==='mysql'&&$pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES))||$milliseconds<1||$milliseconds>30000){throw new ConfigurationException('Use exception-mode SQLite/MySQL, native MySQL prepares and a bounded SQL budget.','configuration.sql_transaction');}
        $this->pdo=$pdo;$this->driver=$driver;$this->clock=$clock;$this->milliseconds=$milliseconds;
    }
    public function driver():string {return $this->driver;}
    public function connection():PDO {return $this->pdo;}
    public function committed():bool {return $this->lastCommitted;}
    public function prefix():string {return $this->driver==='sqlite'?'main.':'';}
    /** @phpstan-impure */
    public function now():int
    {
        if(!$this->busy||$this->deadline===null){throw new ConfigurationException('SQL unit is not active.','configuration.sql_transaction');}
        $this->deadline->check('sql.timeout');
        try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Security clock unavailable.','sql.clock');}
        if($now<0||$now>PHP_INT_MAX-31536001||$now<$this->observed){throw new StorageException('Security clock is invalid or moved backwards.','sql.clock');}
        $this->observed=$now;return $now;
    }
    public function query(string $sql,array $parameters=[],array $blobs=[]):\PDOStatement
    {
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
    private function command(string $sql):void
    {
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
        if($this->witness===null){return;}
        try{$this->command('RELEASE SAVEPOINT '.$this->witness);$this->command('SAVEPOINT '.$this->witness);}
        catch(\Throwable $error){$this->lost=true;$this->failed=true;throw new ConfigurationException('A callback ended or replaced the security transaction.','configuration.sql_transaction_lost');}
        if($checkClock){$this->now();}
    }
    /** Arguments are local copies, including when a trusted callback declares reference parameters. */
    public function invoke(callable $callback,array $arguments,string $reason)
    {
        $this->now();$local=array_values($arguments);$references=[];foreach($local as &$value){$references[]=&$value;}unset($value);
        $failed=false;$result=null;
        try{$result=call_user_func_array($callback,$references);}catch(\Throwable $error){$failed=true;}
        $this->witness();$this->now();
        if($failed){throw new DependencyException('Security callback unavailable.',$reason);}
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
        if($this->busy||$this->failed){throw new StorageException('Rebuild a failed or busy security SQL service.','sql.cleanup');}
        // The rollback boundary never moves. invoke() refreshes only the separate ownership witness.
        $boundary='sosecurity_enlisted_'.bin2hex(random_bytes(16));$name='sosecurity_witness_'.bin2hex(random_bytes(16));
        $this->busy=true;$this->deadline=$budget ?? new Deadline($this->milliseconds);$this->lost=false;$this->witness=null;$this->lastCommitted=false;
        $joined=false;$released=false;$timeout=null;
        try{
            try{SqlTransactionGuard::assertActive($this->pdo,$this->driver,$this->deadline);}
            catch(StorageException $error){$this->failed=true;throw $error;}
            $this->now();
            $joined=true;$this->command('SAVEPOINT '.$boundary);
            $this->command('SAVEPOINT '.$name);$this->witness=$name;$this->now();
            if($this->driver==='sqlite'){
                $timeout=SqlSchema::integer($this->query('PRAGMA busy_timeout')->fetchColumn());
                $this->command('PRAGMA busy_timeout='.max(1,min($timeout,(int)ceil($this->deadline->remaining()*1000))));
            }else{
                $timeout=SqlSchema::integer($this->query('SELECT @@SESSION.innodb_lock_wait_timeout')->fetchColumn());
                $this->command('SET SESSION innodb_lock_wait_timeout='.max(1,min($timeout,(int)ceil($this->deadline->remaining()))));
            }
            if($preflight!==null&&$this->invoke($preflight,[],'sql.authority')!==true){return null;}
            $this->now();$result=$body();$this->witness();
            if($beforeRelease!==null){$beforeRelease($result);$this->witness();}$this->now();
            // MySQL RELEASE does not remove newer savepoints. Release both explicitly, witness first.
            $this->command('RELEASE SAVEPOINT '.$name);$this->witness=null;
            $this->command('RELEASE SAVEPOINT '.$boundary);$released=true;
            // If this returns late, the caller must abort the host unit: the local rollback boundary is already gone.
            try{$this->now();}catch(\Throwable $error){$this->failed=true;throw $error;}
            return $result;
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
            if($timeout!==null&&!$this->failed){try{$this->command(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$timeout);}catch(\Throwable $error){$this->failed=true;}}
            try{if($this->failed){throw new StorageException('Enlisted SQL cleanup or ownership is uncertain; abort the host unit and rebuild the connection.','sql.cleanup');}}
            finally{$this->busy=false;$this->deadline=null;$this->witness=null;}
        }
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
        if($this->busy||$this->failed){throw new StorageException('Rebuild a failed or busy security SQL service.','sql.cleanup');}
        $name='sosecurity_unit_'.bin2hex(random_bytes(16));$this->busy=true;$this->deadline=$budget ?? new Deadline($this->milliseconds);$this->lost=false;$this->witness=null;$this->lastCommitted=false;
        $owned=false;$timeout=null;$committed=false;$commitAttempted=false;$result=null;
        try{
            $this->assertIdle();$this->now();
            if($preflight!==null&&$this->invoke($preflight,[],'sql.authority')!==true){return null;}
            $this->assertIdle();
            if($this->driver==='sqlite'){
                $timeout=SqlSchema::integer($this->query('PRAGMA busy_timeout')->fetchColumn());
                $this->command('PRAGMA busy_timeout='.max(1,min($timeout,(int)ceil($this->deadline->remaining()*1000))));$this->command('BEGIN IMMEDIATE');$owned=true;
            }else{
                $timeout=SqlSchema::integer($this->query('SELECT @@SESSION.innodb_lock_wait_timeout')->fetchColumn());
                $this->command('SET SESSION innodb_lock_wait_timeout='.max(1,min($timeout,(int)ceil($this->deadline->remaining()))));
                if(!$this->pdo->beginTransaction()){throw new StorageException('Cannot begin a security transaction.','sql.unavailable');}$owned=true;
            }
            $this->command('SAVEPOINT '.$name);$this->witness=$name;$this->now();$result=$body();$this->witness();
            if($beforeCommit!==null){$beforeCommit($result);$this->witness();}$this->now();$commitAttempted=true;
            if($this->driver==='sqlite'){$this->command('COMMIT');}elseif(!$this->pdo->commit()){throw new StorageException('Commit was not confirmed.','sql.commit');}
            $owned=false;$committed=true;$this->lastCommitted=true;$this->witness=null;$this->now();return $result;
        }catch(SecurityException $error){throw $error;}
        catch(ConfigurationException $error){throw $error;}
        catch(\Throwable $error){throw new StorageException('Security SQL operation unavailable.','sql.unavailable');}
        finally{
            if($owned&&!$this->lost){
                try{$this->witness(false);if($this->driver==='sqlite'){$this->command('ROLLBACK');}elseif(!$this->pdo->rollBack()){$this->failed=true;}}
                catch(\Throwable $error){$this->failed=true;}
            }
            if($commitAttempted&&!$committed){$this->failed=true;}
            if($timeout!==null&&!$this->failed){try{$this->command(($this->driver==='sqlite'?'PRAGMA busy_timeout=':'SET SESSION innodb_lock_wait_timeout=').$timeout);}catch(\Throwable $error){$this->failed=true;}}
            try{
                if($this->failed){throw new StorageException('Security SQL cleanup or ownership is uncertain; rebuild the connection.','sql.cleanup');}
                if($committed){$this->now();if($afterCommit!==null){$afterCommit($result);$this->now();}}
            }finally{$this->busy=false;$this->deadline=null;$this->witness=null;}
        }
    }
    public function __debugInfo():array {return ['sql'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild SQL services from trusted configuration.','configuration.sql_serialization');}
}
