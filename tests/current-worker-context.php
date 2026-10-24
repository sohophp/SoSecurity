<?php
declare(strict_types=1);
// Borrow only a live exact SQL owner; no handoff, recovery or unknown continuation.
$ownedRoot=is_file(__DIR__.'/bootstrap.php')?dirname(__DIR__):dirname(__DIR__,2);
require $ownedRoot.'/tests/bootstrap.php';
require $ownedRoot.'/tests/webhook-inbox-support.php';

use SoSecurity\Account\FactorWorkerAuthority;
use SoSecurity\Account\Ledger;
use SoSecurity\Account\LocalEpochFence;
use SoSecurity\Account\LocalStatePersistence;
use SoSecurity\Account\Policy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SqlTransaction;

final class OwnedWorkerContextClock implements SoSecurity\Support\Clock
{
    public $time=100000;
    public $fault=false;
    public $reads=0;
    public function now():int
    {
        ++$this->reads;
        if($this->fault){throw new RuntimeException('PRIVATE-WORKER-CLOCK-FAULT');}
        return $this->time;
    }
}

$ownedBackend=$argv[1]??'sqlite';
$ownedCase=$argv[2]??'normal';
$ownedCases=['normal','normal-joined','idle-owner','after-commit','wrong-pdo','wrong-owner-pdo',
    'root-corrupt','history-corrupt','outer-deadline','worker-deadline','worker-clock-backward','worker-clock-fault',
    'schema-refresh','schema-change','transaction-ended','lock-budget','child-write','child-callback','opaque-entry','lock-immediate'];
if(!in_array($ownedBackend,['sqlite','mysql'],true)||!in_array($ownedCase,array_merge($ownedCases,['all']),true)){
    throw new RuntimeException('Use sqlite|mysql and a fixed current-worker-context case.');
}
$ownedMysql=$ownedBackend==='mysql';$ownedSocket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($ownedMysql&&(!is_string($ownedSocket)
    ||preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$ownedSocket)!==1
    ||!is_file(dirname($ownedSocket).'/account-test-owner')||is_link(dirname($ownedSocket)))){
    throw new RuntimeException('Only the controller-owned private MySQL instance is permitted.');
}

foreach($ownedCase==='all'?$ownedCases:[$ownedCase] as $ownedMode){
    $ownedAssertions=Check::$assertions;$ownedDirectory=privateDirectory();
    $ownedPdo=null;$ownedOther=null;$ownedCreated=[];$ownedTemporaryTable=false;$ownedTemporaryTrigger=false;
    try{
        mkdir($ownedDirectory.'/fence',0700);
        $ownedDsn=$ownedMysql?'mysql:unix_socket='.$ownedSocket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$ownedDirectory.'/worker.sqlite';
        // InboxEnvironment is deliberately not instantiated: it drops unrelated tables.
        $ownedPdo=new InboxTestConnection($ownedDsn,$ownedMysql?'sosecurity_test':null,
            $ownedMysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
        $ownedPdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$ownedPdo]]);
        if(!$ownedMysql){$ownedPdo->exec('PRAGMA journal_mode=DELETE');$ownedPdo->exec('PRAGMA synchronous=FULL');}
        $ownedDdl=preg_replace('/^--.*$/m','',file_get_contents($ownedRoot.'/resources/sql/account-'.$ownedBackend.'.sql'));
        if(stripos($ownedDdl,'IF NOT EXISTS')!==false){throw new RuntimeException('Strict new ledger tables are required.');}
        foreach(explode(';',$ownedDdl) as $ownedStatement){
            $ownedStatement=trim($ownedStatement);if($ownedStatement===''){continue;}
            $ownedPdo->exec($ownedStatement);
            if(preg_match('/\ACREATE TABLE\s+(sosecurity_account_(?:roots|records))\b/i',$ownedStatement,$ownedMatch)){
                // Record ownership only after this exact CREATE succeeds.
                $ownedCreated[]=$ownedMatch[1];
            }
        }
        Check::same(2,count($ownedCreated));
        $ownedClock=new TestClock();$ownedSite='owned-current-worker-context';$ownedScope='tenant';$ownedEpoch=str_repeat('e',64);
        $ownedKeys=new HmacKeys('owned',['owned'=>str_repeat('k',32)]);
        $ownedPolicy=new Policy(['maximum_entries'=>4,'io_milliseconds'=>in_array($ownedMode,['worker-deadline','lock-budget'],true)?1000:10000]);
        $ownedFence=new LocalEpochFence($ownedDirectory.'/fence',$ownedSite,$ownedScope,$ownedEpoch,$ownedKeys,
            new LocalStatePersistence($ownedDirectory.'/fence',10000),10000);
        // Exactly one fresh local authority. No close, predecessor, handoff or recovery.
        $ownedFence->initialize();
        $ownedUnit=new SqlTransaction($ownedPdo,$ownedClock,10000);
        $ownedLedger=new Ledger($ownedUnit,'account-factor-recovery:'.hash('sha256',$ownedSite),
            $ownedScope,$ownedEpoch,$ownedKeys,$ownedPolicy,2,$ownedFence->binding());
        $ownedId=str_repeat('1',64);$ownedOwner=str_repeat('a',64);
        $ownedUnit->run(static function()use($ownedLedger,$ownedId,$ownedOwner,$ownedClock):void{
            Check::same(true,$ownedLedger->initialize());
            $ownedLedger->put($ownedId,$ownedOwner,'budget','owned-initial-history',$ownedClock->time+60);
        });
        if(in_array($ownedMode,['root-corrupt','history-corrupt'],true)){
            $ownedTable=$ownedMode==='root-corrupt'?'sosecurity_account_roots':'sosecurity_account_records';
            $ownedSeal=$ownedPdo->query('SELECT seal FROM '.$ownedTable)->fetchColumn();
            Check::same(true,is_string($ownedSeal)&&strlen($ownedSeal)===64);
            $ownedBadSeal=($ownedSeal[0]==='0'?'1':'0').substr($ownedSeal,1);
            $ownedQuery=$ownedPdo->prepare('UPDATE '.$ownedTable.' SET seal=:seal');$ownedQuery->execute(['seal'=>$ownedBadSeal]);$ownedQuery->closeCursor();
        }
        $ownedSnapshot=static function()use($ownedPdo,$ownedDirectory):string{
            $rows=[];foreach(['sosecurity_account_roots','sosecurity_account_records'] as $table){
                $query=$ownedPdo->query('SELECT * FROM '.$table.' ORDER BY namespace'.($table==='sosecurity_account_records'?',record_id':''));
                $rows[$table]=$query->fetchAll(PDO::FETCH_ASSOC);$query->closeCursor();
            }
            $frames=[];foreach(glob($ownedDirectory.'/fence/*.fence') as $path){$frames[basename($path)]=hash_file('sha256',$path);}ksort($frames);
            return hash('sha256',serialize([$rows,$frames]));
        };
        $ownedBefore=$ownedSnapshot();$ownedCallbacks=0;$ownedRoots=0;$ownedHistory=0;$ownedNested=0;$ownedReading=false;
        $ownedSchema=0;$ownedHostCalls=0;$ownedInjected=false;$ownedLockDuring=null;$ownedLockAfter=null;$ownedWrites=0;$ownedGuards=0;
        $ownedWorkerClock=new OwnedWorkerContextClock();
        // Initialization has its own complete unit. The borrowed parent has its own original budget.
        $ownedUnit=new SqlTransaction($ownedPdo,$ownedClock,$ownedMode==='outer-deadline'?1000:10000);
        $ownedPermission=static function()use(&$ownedCallbacks):bool{++$ownedCallbacks;throw new RuntimeException('The null request must not invoke host permission.');};
        $ownedAuthority=new FactorWorkerAuthority($ownedPdo,$ownedSite,$ownedScope,$ownedEpoch,$ownedKeys,$ownedFence,
            $ownedPermission,$ownedPolicy,$ownedWorkerClock);
        if($ownedMode==='opaque-entry'){
            // Register only this fresh test PDO. A non-native guard has no pure code identity.
            SqlStateAccess::bind($ownedPdo,SqlStateAccess::context($ownedSite,$ownedScope,$ownedEpoch),$ownedFence->binding(),
                static function()use(&$ownedGuards):void{++$ownedGuards;});
            Check::same(false,SqlStateAccess::pureEntryGuard($ownedPdo));
        }
        $ownedPdo->beforeStatement=static function(string $sql)use(&$ownedRoots,&$ownedHistory,&$ownedSchema,&$ownedWrites,$ownedMysql):void{
            if(strpos($sql,'AS history_digest')!==false){++$ownedRoots;}
            if(preg_match('/ORDER BY (?:main\\.)?sosecurity_account_records\\.record_id\\b/',$sql)===1){++$ownedHistory;}
            if(($ownedMysql&&strpos($sql,'AS __table')!==false)||(!$ownedMysql&&strpos($sql,'main.pragma_table_info(')!==false)){++$ownedSchema;}
            if(preg_match('/\AUPDATE\b/i',$sql)===1){++$ownedWrites;}
        };
        $ownedPdo->afterStatement=static function(string $sql)use($ownedMode,$ownedMysql,$ownedPdo,$ownedWorkerClock,&$ownedInjected,&$ownedLockDuring):void{
            if($ownedInjected||strpos($sql,'AS history_digest')===false){return;}
            $ownedInjected=true;
            if(in_array($ownedMode,['outer-deadline','worker-deadline'],true)){usleep(1100000);}
            elseif($ownedMode==='worker-clock-backward'){--$ownedWorkerClock->time;}
            elseif($ownedMode==='worker-clock-fault'){$ownedWorkerClock->fault=true;}
            elseif($ownedMode==='transaction-ended'){
                if($ownedMysql){Check::same(true,$ownedPdo->commit());}else{$ownedPdo->exec('COMMIT');}
            }elseif(in_array($ownedMode,['lock-budget','lock-immediate'],true)){
                $query=$ownedPdo->query($ownedMysql?'SELECT @@SESSION.innodb_lock_wait_timeout':'PRAGMA busy_timeout');
                $ownedLockDuring=(int)$query->fetchColumn();$query->closeCursor();
            }
        };
        $ownedPdo->afterExec=static function(string $sql)use(&$ownedReading,&$ownedNested):void{
            if($ownedReading&&preg_match('/\\ASAVEPOINT sosecurity_enlisted_/i',trim($sql))===1){++$ownedNested;}
        };
        $ownedJoined=$ownedMode==='normal-joined';if($ownedJoined){Check::same(true,$ownedPdo->beginTransaction());}
        $ownedCall=static function(?SqlTransaction $owner=null)use($ownedAuthority,$ownedPdo,$ownedUnit,&$ownedReading):void{
            $ownedReading=true;
            try{$ownedAuthority->assertCurrent($ownedPdo,$owner??$ownedUnit);}finally{$ownedReading=false;}
        };
        $ownedBody=static function()use($ownedCall,$ownedUnit,$ownedMode,$ownedPdo,$ownedMysql,$ownedWorkerClock,$ownedDdl,&$ownedReading,&$ownedHostCalls,&$ownedTemporaryTable,&$ownedTemporaryTrigger,&$ownedLockAfter):bool{
            if(in_array($ownedMode,['child-write','child-callback'],true)){
                $child=new SqlTransaction($ownedPdo,$ownedWorkerClock,10000);$ownedReading=true;
                try{
                    $child->readIn($ownedUnit,static function()use($child,$ownedMode,&$ownedHostCalls):void{
                        if($ownedMode==='child-write'){
                            $child->query('UPDATE sosecurity_account_roots SET revision=revision+1')->closeCursor();
                        }else{
                            $child->invoke(static function()use(&$ownedHostCalls):void{++$ownedHostCalls;},[],'owned-worker.child_callback');
                        }
                    });
                }finally{$ownedReading=false;}
                return true;
            }
            if(in_array($ownedMode,['lock-budget','lock-immediate'],true)){
                $ownedUnit->invoke(static function()use($ownedPdo,$ownedMysql,$ownedMode,&$ownedHostCalls):void{
                    ++$ownedHostCalls;
                    if($ownedMode==='lock-immediate'){$ownedPdo->exec($ownedMysql?'SET SESSION innodb_lock_wait_timeout=1':'PRAGMA busy_timeout=0');}
                    else{$ownedPdo->exec($ownedMysql?'SET SESSION innodb_lock_wait_timeout=60':'PRAGMA busy_timeout=60000');}
                },[],'owned-worker.callback');
            }
            $ownedCall();
            if(in_array($ownedMode,['schema-refresh','schema-change'],true)){
                $ownedUnit->invoke(static function()use($ownedMode,$ownedMysql,$ownedPdo,$ownedDdl,&$ownedHostCalls,&$ownedTemporaryTable,&$ownedTemporaryTrigger):void{
                    ++$ownedHostCalls;
                    if($ownedMode==='schema-change'){
                        if($ownedMysql){
                            $rootStatements=[];foreach(explode(';',$ownedDdl) as $statement){$statement=trim($statement);if(preg_match('/\ACREATE TABLE\s+sosecurity_account_roots\b/i',$statement)){$rootStatements[]=$statement;}}
                            if(count($rootStatements)!==1){throw new RuntimeException('Use the exact owned roots DDL.');}
                            $ownedPdo->exec(preg_replace('/\ACREATE TABLE\b/i','CREATE TEMPORARY TABLE',$rootStatements[0],1));$ownedTemporaryTable=true;
                        }else{
                            $ownedPdo->exec('CREATE TEMP TRIGGER owned_worker_context_trigger BEFORE UPDATE ON main.sosecurity_account_roots BEGIN SELECT 1; END');$ownedTemporaryTrigger=true;
                        }
                    }
                },[],'owned-worker.callback');
                $ownedCall();
            }
            if(in_array($ownedMode,['lock-budget','lock-immediate'],true)){
                $query=$ownedPdo->query($ownedMysql?'SELECT @@SESSION.innodb_lock_wait_timeout':'PRAGMA busy_timeout');
                $ownedLockAfter=(int)$query->fetchColumn();$query->closeCursor();
            }
            return true;
        };
        $ownedError=null;$ownedResult=null;
        try{
            $ownedResult=$ownedFence->work(static function()use($ownedJoined,$ownedUnit,$ownedBody,$ownedMode,$ownedCall,$ownedPdo,$ownedDsn,$ownedMysql,$ownedAuthority,$ownedClock,&$ownedOther){
                if($ownedMode==='idle-owner'){$ownedCall();return true;}
                if($ownedMode==='after-commit'){
                    return $ownedUnit->run(static function():bool{return true;},null,null,static function()use($ownedCall):void{$ownedCall();});
                }
                if(in_array($ownedMode,['wrong-pdo','wrong-owner-pdo'],true)){
                    $ownedOther=new PDO($ownedDsn,$ownedMysql?'sosecurity_test':null,$ownedMysql?'integration-only':null,
                        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
                    if($ownedMode==='wrong-pdo'){
                        return $ownedUnit->run(static function()use($ownedAuthority,$ownedOther,$ownedUnit):bool{$ownedAuthority->assertCurrent($ownedOther,$ownedUnit);return true;});
                    }
                    $wrong=new SqlTransaction($ownedOther,$ownedClock,10000);
                    return $wrong->run(static function()use($ownedCall,$wrong):bool{$ownedCall($wrong);return true;});
                }
                return $ownedJoined?$ownedUnit->enlist($ownedBody):$ownedUnit->run($ownedBody);
            });
        }catch(SecurityException | ConfigurationException $error){$ownedError=$error;}
        $ownedPdo->beforeStatement=null;$ownedPdo->afterStatement=null;$ownedPdo->afterExec=null;
        if($ownedJoined){Check::same(true,$ownedPdo->inTransaction());Check::same(true,$ownedPdo->rollBack());}
        if($ownedTemporaryTable){$ownedPdo->exec('DROP TEMPORARY TABLE sosecurity_account_roots');$ownedTemporaryTable=false;}
        if($ownedTemporaryTrigger){$ownedPdo->exec('DROP TRIGGER IF EXISTS temp.owned_worker_context_trigger');$ownedTemporaryTrigger=false;}
        $ownedSuccess=in_array($ownedMode,['normal','normal-joined','schema-refresh','lock-budget','opaque-entry','lock-immediate'],true);
        if($ownedSuccess){
            Check::same(null,$ownedError);Check::same(true,$ownedResult);
            Check::same($ownedMode==='schema-refresh'?2:1,$ownedRoots);Check::same($ownedMode==='schema-refresh'?2:1,$ownedHistory);
            Check::same(($ownedMysql?1:2)*($ownedMode==='schema-refresh'?2:1),$ownedSchema);
            if($ownedMode==='schema-refresh'){Check::same(1,$ownedHostCalls);}
            if($ownedMode==='opaque-entry'){Check::same(true,$ownedGuards>0);Check::same(0,$ownedHostCalls);}
            if($ownedMode==='lock-budget'){
                Check::same(1,$ownedHostCalls);Check::same(true,$ownedLockDuring!==null&&$ownedLockDuring>0&&$ownedLockDuring<=($ownedMysql?1:1000));
                Check::same($ownedMysql?60:60000,$ownedLockAfter);
            }
            if($ownedMode==='lock-immediate'){
                Check::same(1,$ownedHostCalls);Check::same($ownedMysql?1:0,$ownedLockDuring);Check::same($ownedMysql?1:0,$ownedLockAfter);
            }
        }else{
            Check::same(true,$ownedError instanceof SecurityException||$ownedError instanceof ConfigurationException);Check::same(null,$ownedResult);
            if(in_array($ownedMode,['idle-owner','after-commit','wrong-owner-pdo'],true)){
                Check::same('configuration.sql_transaction',$ownedError->reason());Check::same(0,$ownedRoots);
                if($ownedMode==='after-commit'){Check::same(true,$ownedUnit->committed());}
            }elseif($ownedMode==='wrong-pdo'){
                Check::same('configuration.factor_workers',$ownedError->reason());Check::same(0,$ownedRoots);
            }elseif(in_array($ownedMode,['root-corrupt','history-corrupt'],true)){
                Check::same('account.corrupt',$ownedError->reason());Check::same(1,$ownedRoots);
            }elseif(in_array($ownedMode,['outer-deadline','worker-deadline'],true)){
                Check::same('sql.timeout',$ownedError->reason());Check::same(true,$ownedInjected);
            }elseif(in_array($ownedMode,['worker-clock-backward','worker-clock-fault'],true)){
                Check::same('sql.clock',$ownedError->reason());Check::same(true,$ownedInjected);Check::same(true,$ownedWorkerClock->reads>1);
            }elseif($ownedMode==='schema-change'){
                Check::same($ownedMysql?'sql.unavailable':'configuration.sql_schema',$ownedError->reason());Check::same(1,$ownedHostCalls);Check::same(1,$ownedRoots);
            }elseif(in_array($ownedMode,['child-write','child-callback'],true)){
                Check::same('configuration.state_observation',$ownedError->reason());Check::same(0,$ownedRoots);Check::same(0,$ownedHistory);
                Check::same(0,$ownedWrites);Check::same(0,$ownedHostCalls);
            }else{
                Check::same(true,in_array($ownedError->reason(),['sql.cleanup','configuration.sql_transaction_lost'],true));Check::same(true,$ownedInjected);
            }
        }
        Check::same(0,$ownedCallbacks);
        if($ownedOther!==null){Check::same(false,$ownedOther->inTransaction());}
        Check::same(false,$ownedPdo->inTransaction());Check::same($ownedBefore,$ownedSnapshot());
        // Old assertCurrent ignores the extra argument and creates an unnecessary enlisted unit.
        Check::same($ownedMode==='opaque-entry'?1:0,$ownedNested);
        echo 'PASS current registered worker context '.$ownedMode.' '.(Check::$assertions-$ownedAssertions).' assertions PHP '.PHP_VERSION.' '.$ownedBackend.'; initial independent authority only'.PHP_EOL;
    }finally{
        if($ownedPdo instanceof InboxTestConnection){
            $ownedPdo->beforeStatement=null;$ownedPdo->afterStatement=null;$ownedPdo->afterExec=null;
            $ownedPdo->beforeCommit=null;$ownedPdo->afterCommit=null;
            if($ownedPdo->inTransaction()){$ownedPdo->rollBack();}
            if($ownedTemporaryTable){$ownedPdo->exec('DROP TEMPORARY TABLE sosecurity_account_roots');}
            if($ownedTemporaryTrigger){$ownedPdo->exec('DROP TRIGGER IF EXISTS temp.owned_worker_context_trigger');}
            foreach(array_reverse($ownedCreated) as $table){$ownedPdo->exec('DROP TABLE '.$table);}
        }
        $ownedOther=null;$ownedPdo=null;gc_collect_cycles();
        if(is_dir($ownedDirectory.'/fence')){cleanDirectory($ownedDirectory.'/fence');}
        cleanDirectory($ownedDirectory);
    }
}
