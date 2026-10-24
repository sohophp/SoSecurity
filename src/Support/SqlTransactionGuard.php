<?php
declare(strict_types=1);
namespace SoSecurity\Support;

use PDO;
use PDOException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

/** Internal ownership checks. Never ends an existing transaction or changes autocommit/isolation settings. */
final class SqlTransactionGuard
{
    public static function assertIdle(PDO $pdo,string $driver,?Deadline $deadline=null):void
    {
        $deadline=$deadline ?? new Deadline(30000);
        $deadline->check('storage.transaction_timeout');
        if($pdo->inTransaction()){throw new ConfigurationException('Refuse an existing host transaction.','configuration.transaction');}
        if($driver!=='mysql'){return;}
        $value=self::autocommit($pdo,$deadline);
        $deadline->check('storage.transaction_timeout');
        if((string)$value!=='1'){throw new ConfigurationException('Use an autocommit-enabled connection for owned security transactions.','configuration.transaction');}
        // Old PDO MySQL does not always report SQL-started transactions. A savepoint persists only in an active transaction.
        $name='sosecurity_idle_'.bin2hex(random_bytes(8));
        list($created)=self::command($pdo,'SAVEPOINT '.$name);
        if(!$created){throw new StorageException('Cannot inspect transaction ownership.','storage.transaction_state');}
        list($released,$code)=self::command($pdo,'RELEASE SAVEPOINT '.$name);
        $deadline->check('storage.transaction_timeout');
        if($released){throw new ConfigurationException('Refuse an SQL-started host transaction.','configuration.transaction');}
        // Outside a transaction MySQL discards the savepoint; only its precise missing-savepoint error establishes idle.
        if($code!==1305){throw new StorageException('Cannot confirm an idle transaction connection.','storage.transaction_state');}
    }

    /** Require an explicit existing transaction, including SQL-started transactions hidden by old PDO. */
    public static function assertActive(PDO $pdo,string $driver,Deadline $deadline):void
    {
        if(!self::active($pdo,$driver,$deadline)){throw new ConfigurationException('Begin the host transaction before enlisting security writes.','configuration.transaction');}
    }

    /** Native entry observation only. Unsupported ownership and uncertain probes throw; absence is explicit false. */
    public static function active(PDO $pdo,string $driver,Deadline $deadline):bool
    {
        $deadline->check('storage.transaction_timeout');
        if($driver==='sqlite'){
            // Always probe the engine: old PDO can also retain a true flag after a SQL COMMIT.
            list($began,$code,$message)=self::command($pdo,'BEGIN DEFERRED');
            if($began){
                // Only the successfully created, empty probe belongs to us. Cleanup cannot depend on the clock.
                list($rolledBack)=self::command($pdo,'ROLLBACK');
                if(!$rolledBack){throw new StorageException('Cannot clean up the empty transaction probe.','sql.cleanup');}
                $deadline->check('storage.transaction_timeout');
                return false;
            }
            if($code!==1||$message!=='cannot start a transaction within a transaction'){throw new StorageException('Cannot confirm an active SQLite transaction.','storage.transaction_state');}
        }elseif($driver==='mysql'){
            $value=self::autocommit($pdo,$deadline,true);
            $deadline->check('storage.transaction_timeout');
            // With autocommit=0 a savepoint can persist even before any host DML. It cannot prove prior ownership.
            if((string)$value!=='1'){throw new ConfigurationException('Enlist only in an explicit autocommit-enabled host transaction.','configuration.transaction');}
            $name='sosecurity_active_'.bin2hex(random_bytes(8));
            list($created)=self::command($pdo,'SAVEPOINT '.$name);
            if(!$created){throw new StorageException('Cannot inspect transaction ownership.','storage.transaction_state');}
            list($released,$code)=self::command($pdo,'RELEASE SAVEPOINT '.$name);
            if(!$released){
                if($code===1305){return false;}
                throw new StorageException('Cannot confirm an active host transaction.','storage.transaction_state');
            }
        }else{throw new ConfigurationException('Use SQLite or MySQL transactions.','configuration.sql_transaction');}
        $deadline->check('storage.transaction_timeout');return true;
    }

    /** Close even after failed execution/fetch; unconfirmed cleanup never proves ownership. */
    private static function autocommit(PDO $pdo,Deadline $deadline,bool $direct=false)
    {
        $query=null;$failed=false;$value=null;
        try{
            $query=$direct?@$pdo->query('SELECT @@SESSION.autocommit'):@$pdo->prepare('SELECT @@SESSION.autocommit');
            if($query===false){throw new \RuntimeException();}
            $deadline->check('storage.transaction_timeout');
            if(!$direct&&!@$query->execute()){throw new \RuntimeException();}
            $value=$query->fetchColumn();
        }catch(\Throwable $error){$failed=true;}
        if($query instanceof \PDOStatement){
            try{if(!$query->closeCursor()){$failed=true;}}catch(\Throwable $error){$failed=true;}
        }
        if($failed){throw new StorageException('Cannot inspect transaction state.','storage.transaction_state');}
        return $value;
    }

    private static function command(PDO $pdo,string $sql):array
    {
        try {
            // Warning/silent PDO modes are supported. Expected 1305 is checked, never emitted or treated as general success.
            $result=@$pdo->exec($sql);
            if($result!==false){return [true,0,''];}
            $info=$pdo->errorInfo();return [false,isset($info[1])?(int)$info[1]:0,$info[2] ?? ''];
        } catch (PDOException $error) {
            return [false,isset($error->errorInfo[1])?(int)$error->errorInfo[1]:0,$error->errorInfo[2] ?? ''];
        } catch (\Throwable $error) {
            throw new StorageException('Cannot inspect transaction ownership.','storage.transaction_state');
        }
    }
}
