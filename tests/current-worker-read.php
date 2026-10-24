<?php
declare(strict_types=1);
// Independent current-worker checks; no handoff, recovery or unknown continuation.
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
use SoSecurity\Support\SqlTransaction;

$ownedBackend=$argv[1]??'sqlite';
$ownedCase=$argv[2]??'normal';
$ownedCases=['normal','normal-joined','permission','permission-joined','denied','callback-root-change','transaction-ended',
    'root-corrupt','history-corrupt','wrong-pdo','deadline','null-deadline'];
if(!in_array($ownedBackend,['sqlite','mysql'],true)||!in_array($ownedCase,array_merge($ownedCases,['all']),true)){
    throw new RuntimeException('Use sqlite|mysql and a fixed current-worker-read case.');
}
$ownedMysql=$ownedBackend==='mysql';$ownedSocket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($ownedMysql&&(!is_string($ownedSocket)
    ||preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$ownedSocket)!==1
    ||!is_file(dirname($ownedSocket).'/account-test-owner')||is_link(dirname($ownedSocket)))){
    throw new RuntimeException('Only the controller-owned private MySQL instance is permitted.');
}

foreach($ownedCase==='all'?$ownedCases:[$ownedCase] as $ownedMode){
    $ownedAssertions=Check::$assertions;$ownedDirectory=privateDirectory();
    $ownedPdo=null;$ownedOther=null;$ownedCreated=[];
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
        $ownedClock=new TestClock();$ownedSite='owned-current-worker-read';$ownedScope='tenant';$ownedEpoch=str_repeat('e',64);
        $ownedKeys=new HmacKeys('owned',['owned'=>str_repeat('k',32)]);
        $ownedPolicy=new Policy(['maximum_entries'=>4,'io_milliseconds'=>in_array($ownedMode,['deadline','null-deadline'],true)?1000:10000]);
        $ownedFence=new LocalEpochFence($ownedDirectory.'/fence',$ownedSite,$ownedScope,$ownedEpoch,$ownedKeys,
            new LocalStatePersistence($ownedDirectory.'/fence',10000),10000);
        // Exactly one fresh local authority. No close, predecessor, handoff or recovery.
        $ownedFence->initialize();
        $ownedUnit=new SqlTransaction($ownedPdo,$ownedClock,10000);
        $ownedLedger=new Ledger($ownedUnit,'account-factor-recovery:'.hash('sha256',$ownedSite),
            $ownedScope,$ownedEpoch,$ownedKeys,$ownedPolicy,2,$ownedFence->binding());
        $ownedId=str_repeat('1',64);$ownedSecondId=str_repeat('2',64);$ownedOwner=str_repeat('a',64);
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
        $ownedBefore=$ownedSnapshot();$ownedCallbacks=0;$ownedRoots=0;$ownedHistory=0;$ownedDelayed=false;
        $ownedPermission=static function(string $action,string $phase,string $scope,string $subject,array $metadata)
            use(&$ownedCallbacks,$ownedMode,$ownedScope,$ownedUnit,$ownedLedger,$ownedSecondId,$ownedOwner,$ownedClock,$ownedPdo):bool{
            ++$ownedCallbacks;Check::same('status',$action);Check::same('before',$phase);Check::same($ownedScope,$scope);Check::same('owned-subject',$subject);Check::same([],$metadata);
            if($ownedMode==='callback-root-change'){
                // A valid signed change proves checkpoint comparison, rather than only MAC rejection.
                $ownedUnit->enlist(static function()use($ownedLedger,$ownedSecondId,$ownedOwner,$ownedClock):void{
                    $ownedLedger->put($ownedSecondId,$ownedOwner,'budget','owned-callback-history',$ownedClock->time+60);
                });
            }
            if($ownedMode==='transaction-ended'){
                if($ownedPdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'){$ownedPdo->exec('COMMIT');}
                else{Check::same(true,$ownedPdo->commit());}
            }
            if($ownedMode==='deadline'){usleep(1100000);}
            return $ownedMode!=='denied';
        };
        $ownedAuthority=new FactorWorkerAuthority($ownedPdo,$ownedSite,$ownedScope,$ownedEpoch,$ownedKeys,$ownedFence,
            $ownedPermission,$ownedPolicy,$ownedClock);
        $ownedPdo->beforeStatement=static function(string $sql)use(&$ownedRoots,&$ownedHistory):void{
            if(strpos($sql,'AS history_digest')!==false){++$ownedRoots;}
            if(preg_match('/ORDER BY (?:main\.)?sosecurity_account_records\.record_id\b/',$sql)===1){++$ownedHistory;}
        };
        if($ownedMode==='null-deadline'){
            $ownedPdo->afterStatement=static function(string $sql)use(&$ownedDelayed):void{
                if(!$ownedDelayed&&strpos($sql,'AS history_digest')!==false){$ownedDelayed=true;usleep(1100000);}
            };
        }
        $ownedJoined=in_array($ownedMode,['normal-joined','permission-joined'],true);if($ownedJoined){Check::same(true,$ownedPdo->beginTransaction());}
        $ownedError=null;$ownedResult=null;
        try{
            $ownedResult=$ownedFence->work(static function()use($ownedAuthority,$ownedPdo,$ownedDsn,$ownedMysql,$ownedMode,$ownedScope,&$ownedOther){
                if($ownedMode==='wrong-pdo'){
                    $ownedOther=new PDO($ownedDsn,$ownedMysql?'sosecurity_test':null,$ownedMysql?'integration-only':null,
                        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
                    $ownedAuthority->assertCurrent($ownedOther);return null;
                }
                if(in_array($ownedMode,['normal','normal-joined','root-corrupt','history-corrupt','null-deadline'],true)){
                    $ownedAuthority->assertCurrent($ownedPdo);return true;
                }
                return $ownedAuthority('status','before',$ownedScope,'owned-subject',[]);
            });
        }catch(SecurityException | ConfigurationException $error){$ownedError=$error;}
        $ownedPdo->beforeStatement=null;$ownedPdo->afterStatement=null;
        if($ownedJoined){Check::same(true,$ownedPdo->inTransaction());Check::same(true,$ownedPdo->rollBack());}
        if(in_array($ownedMode,['normal','normal-joined'],true)){
            Check::same(null,$ownedError);Check::same(true,$ownedResult);Check::same(0,$ownedCallbacks);
            // Deliberate failing-before expectation: old source performs two complete checkpoints.
            Check::same(1,$ownedRoots);Check::same(1,$ownedHistory);
        }elseif(in_array($ownedMode,['permission','permission-joined','denied'],true)){
            Check::same(null,$ownedError);Check::same($ownedMode!=='denied',$ownedResult);Check::same(1,$ownedCallbacks);
            Check::same(2,$ownedRoots);Check::same(2,$ownedHistory);
        }else{
            Check::same(true,$ownedError instanceof SecurityException||($ownedMode==='wrong-pdo'&&$ownedError instanceof ConfigurationException));Check::same(null,$ownedResult);
            if($ownedMode==='callback-root-change'){Check::same('account.worker_changed',$ownedError->reason());Check::same(1,$ownedCallbacks);}
            elseif($ownedMode==='transaction-ended'){
                Check::same(true,in_array($ownedError->reason(),['sql.cleanup','configuration.sql_transaction_lost'],true));Check::same(1,$ownedCallbacks);
            }elseif(in_array($ownedMode,['deadline','null-deadline'],true)){
                $ownedReasons=[];for($cause=$ownedError;$cause instanceof Throwable;$cause=$cause->getPrevious()){
                    if($cause instanceof SecurityException){$ownedReasons[]=$cause->reason();}
                }
                Check::same(true,in_array('sql.timeout',$ownedReasons,true));Check::same($ownedMode==='deadline'?1:0,$ownedCallbacks);
                if($ownedMode==='null-deadline'){Check::same(true,$ownedDelayed);}
            }elseif($ownedMode==='wrong-pdo'){
                Check::same(ConfigurationException::class,get_class($ownedError));Check::same('configuration.factor_workers',$ownedError->reason());Check::same(0,$ownedRoots);Check::same(0,$ownedCallbacks);
            }else{Check::same('account.corrupt',$ownedError->reason());Check::same(0,$ownedCallbacks);Check::same(1,$ownedRoots);}
        }
        Check::same(false,$ownedPdo->inTransaction());Check::same($ownedBefore,$ownedSnapshot());
        echo 'PASS current registered worker read '.$ownedMode.' '.(Check::$assertions-$ownedAssertions).' assertions PHP '.PHP_VERSION.' '.$ownedBackend.'; initial independent authority only'.PHP_EOL;
    }finally{
        if($ownedPdo instanceof InboxTestConnection){
            $ownedPdo->beforeStatement=null;$ownedPdo->afterStatement=null;$ownedPdo->afterExec=null;
            $ownedPdo->beforeCommit=null;$ownedPdo->afterCommit=null;
            if($ownedPdo->inTransaction()){$ownedPdo->rollBack();}
            foreach(array_reverse($ownedCreated) as $table){$ownedPdo->exec('DROP TABLE '.$table);}
        }
        $ownedOther=null;$ownedPdo=null;gc_collect_cycles();
        if(is_dir($ownedDirectory.'/fence')){cleanDirectory($ownedDirectory.'/fence');}
        cleanDirectory($ownedDirectory);
    }
}
