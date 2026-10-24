<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\SqlTransaction;

require __DIR__.'/sql-enlistment-support.php';
$mysql=($argv[1] ?? '')==='mysql';

// No auto-BEGIN or implicit business commit; rejection precedes even the authority callback.
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
    $queries=$e->pdo->queries;$unit=$e->unit();Check::same($queries,$e->pdo->queries);$calls=0;
    enlistRefused('configuration.transaction',static function()use($unit,&$calls):void{$unit->enlist(static function()use(&$calls):void{++$calls;},static function()use(&$calls):bool{++$calls;return true;});});
    Check::same(0,$calls);Check::same([],$e->rows('intents',true));
    $e->begin();$e->business();$unit->enlist(static function()use($e,$unit):void{$e->intent($unit);});
    Check::same(false,$unit->committed());Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
    $e->pdo->exec('ROLLBACK');Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
});
// Empty and nonempty native/SQL host transactions, with both commit and rollback chosen by the host.
foreach(['native','sql'] as $mode){foreach([false,true] as $pending){foreach(['COMMIT','ROLLBACK'] as $ending){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($mode,$pending,$ending):void{
    $unit=$e->unit();$e->begin($mode);if($pending){$e->business();}
    $value=$unit->enlist(static function()use($e,$unit):string{$e->intent($unit);return 'provisional';});
    Check::same('provisional',$value);Check::same(false,$unit->committed());Check::same($pending?[1]:[],$e->rows('business'));Check::same([1],$e->rows('intents'));
    Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
    $e->pdo->exec($ending);Check::same($pending&&$ending==='COMMIT'?[1]:[],$e->rows('business',true));Check::same($ending==='COMMIT'?[1]:[],$e->rows('intents',true));
});}}}
// Stale PDO flags after a SQL COMMIT must not turn SAVEPOINT into a new outer SQLite transaction.
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
    $unit=$e->unit();$e->begin('native');$e->business();$e->pdo->exec('COMMIT');$calls=0;
    enlistRefused('configuration.transaction',static function()use($unit,&$calls):void{$unit->enlist(static function()use(&$calls):void{++$calls;});});
    Check::same(0,$calls);Check::same([1],$e->rows('business',true));Check::same([],$e->rows('intents',true));
});
if($mysql){foreach(['idle','write','manual'] as $mode){enlistCase(true,static function(EnlistmentEnvironment $e)use($mode):void{
    $unit=$e->unit();$e->pdo->exec('SET autocommit=0');if($mode==='manual'){$e->pdo->exec('START TRANSACTION');}if($mode!=='idle'){$e->business();}$calls=0;
    enlistRefused('configuration.transaction',static function()use($unit,&$calls):void{$unit->enlist(static function()use(&$calls):void{++$calls;},static function()use(&$calls):bool{++$calls;return true;});});
    Check::same(0,$calls);Check::same($mode==='idle'?[]:[1],$e->rows('business'));Check::same([],$e->rows('business',true));Check::same('0',(string)$e->pdo->query('SELECT @@SESSION.autocommit')->fetchColumn());
    $e->pdo->exec('ROLLBACK');$e->pdo->exec('SET autocommit=1');Check::same([],$e->rows('business',true));
});}}
// Denials and throwing callbacks cannot leak their own writes into the surrounding business transaction.
foreach([false,null,1,'true'] as $answer){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($answer):void{
    $unit=$e->unit();$e->begin();$e->business();$calls=0;
    $value=$unit->enlist(static function()use(&$calls):void{++$calls;},static function()use($e,$unit,$answer){$e->intent($unit);return $answer;});
    Check::same(null,$value);Check::same(0,$calls);Check::same([1],$e->rows('business'));Check::same([],$e->rows('intents'));
    $unit->enlist(static function()use($e,$unit):void{$e->intent($unit,2);});$e->pdo->exec('COMMIT');Check::same([1],$e->rows('business',true));Check::same([2],$e->rows('intents',true));
});}
foreach(['body','invoke','before-release'] as $phase){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($phase):void{
    $unit=$e->unit();$e->begin();$e->business();$e->pdo->exec('SAVEPOINT host_owned');
    enlistRefused($phase==='invoke'?'test.authority':'sql.unavailable',static function()use($e,$unit,$phase):void{
        $unit->enlist(static function()use($e,$unit,$phase):int{
            $e->intent($unit,1);
            for($id=2;$id<=4;++$id){$unit->invoke(static function()use($e,$unit,$id):bool{$e->intent($unit,$id);return true;},[],'test.authority');}
            if($phase==='body'){throw new RuntimeException('SYNTHETIC-SECRET');}
            if($phase==='invoke'){$unit->invoke(static function():void{throw new RuntimeException('SYNTHETIC-SECRET');},[],'test.authority');}
            return 7;
        },null,static function(int $result):void{Check::same(7,$result);throw new RuntimeException('SYNTHETIC-SECRET');});
    });
    Check::same([1],$e->rows('business'));Check::same([],$e->rows('intents'));Check::same([],$e->rows('business',true));
    $e->pdo->exec('ROLLBACK TO SAVEPOINT host_owned');$e->pdo->exec('RELEASE SAVEPOINT host_owned');
    $unit->enlist(static function()use($e,$unit):void{$e->intent($unit,5);});$e->pdo->exec('COMMIT');Check::same([1],$e->rows('business',true));Check::same([5],$e->rows('intents',true));
});}
// Expired time budgets / invalid clocks cannot skip rollback to the fixed local boundary.
foreach(['budget','shared-budget','clock'] as $failure){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($failure):void{
    $unit=$e->unit($failure==='budget'?20:1000);$e->begin();$e->business();$calls=0;$budget=$failure==='shared-budget'?new Deadline(20):null;
    Check::throws(StorageException::class,static function()use($e,$unit,$failure,&$calls,$budget):void{
        $unit->enlist(static function()use($e,$unit,$failure,&$calls):void{++$calls;$e->intent($unit);if($failure==='clock'){--$e->clock->time;}else{usleep(50000);}},null,null,$budget);
    });
    Check::same(1,$calls);Check::same([1],$e->rows('business'));Check::same([],$e->rows('intents'));Check::same([],$e->rows('business',true));
    if($failure==='clock'){++$e->clock->time;}$unit->enlist(static function()use($e,$unit):void{$e->intent($unit,2);});$e->pdo->exec('COMMIT');Check::same([2],$e->rows('intents',true));
});}
// Real database lock contention, rather than a sleeping callback. No failed write may become a committed intent.
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
    $unit=$e->unit(100);$e->observer->beginTransaction();$e->observer->exec('INSERT INTO enlistment_test_intents VALUES(9)');
    // SQLite has a database-wide writer lock, so its host remains a deferred read transaction until the blocker leaves.
    $e->begin('native');if($e->mysql){$e->business();}
    $calls=0;
    Check::throws(StorageException::class,static function()use($e,$unit,&$calls):void{$unit->enlist(static function()use($e,$unit,&$calls):void{++$calls;$e->intent($unit,9);});});
    Check::same(1,$calls);Check::same($e->mysql?[1]:[],$e->rows('business'));Check::same([],$e->rows('intents'));Check::same(false,$unit->committed());
    $e->observer->rollBack();Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
    if(!$e->mysql){$e->business();}$unit->enlist(static function()use($e,$unit):void{$e->intent($unit,2);});
    $e->pdo->exec('COMMIT');Check::same([1],$e->rows('business',true));Check::same([2],$e->rows('intents',true));
});
// Callbacks that end/replace a transaction are rejected; cleanup must never roll back the replacement transaction.
foreach(['COMMIT','ROLLBACK'] as $ending){foreach([false,true] as $throws){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($ending,$throws):void{
    $unit=$e->unit();$e->begin();$e->business();
    enlistRefused('sql.cleanup',static function()use($e,$unit,$ending,$throws):void{
        $unit->enlist(static function()use($e,$unit,$ending,$throws):void{
            $e->intent($unit);$e->pdo->exec($ending);$e->begin();$e->business(2);
            if($throws){throw new RuntimeException('SYNTHETIC-SECRET');}
        });
    });
    Check::same($ending==='COMMIT'?[1,2]:[2],$e->rows('business'));Check::same($ending==='COMMIT'?[1]:[],$e->rows('business',true));
    enlistRefused('sql.cleanup',static function()use($unit):void{$unit->enlist(static function():void{throw new RuntimeException('Must never run.');});});
    $e->pdo->exec('ROLLBACK');Check::same($ending==='COMMIT'?[1]:[],$e->rows('business',true));Check::same($ending==='COMMIT'?[1]:[],$e->rows('intents',true));
});}}
// Rolling back to an earlier host savepoint also invalidates our ownership, without ending the host transaction.
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
    $unit=$e->unit();$e->begin();$e->business();$e->pdo->exec('SAVEPOINT host_earlier');
    enlistRefused('sql.cleanup',static function()use($e,$unit):void{$unit->enlist(static function()use($e,$unit):void{$e->intent($unit);$e->pdo->exec('ROLLBACK TO SAVEPOINT host_earlier');$e->business(2);});});
    Check::same([1,2],$e->rows('business'));Check::same([],$e->rows('intents'));Check::same([],$e->rows('business',true));$e->pdo->exec('ROLLBACK');Check::same([],$e->rows('business',true));
});
// A missing fixed boundary is detected even on MySQL, where releasing it leaves the newer witness alive.
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
    $unit=$e->unit();$e->begin();$e->business();$boundary=null;
    $e->pdo->afterExec=static function(string $sql)use(&$boundary):void{if(strpos($sql,'SAVEPOINT sosecurity_enlisted_')===0){$boundary=substr($sql,10);}};
    enlistRefused('sql.cleanup',static function()use($e,$unit,&$boundary):void{$unit->enlist(static function()use($e,$unit,&$boundary):void{$e->intent($unit);$e->pdo->exec('RELEASE SAVEPOINT '.$boundary);});});
    $e->pdo->afterExec=null;Check::same([1],$e->rows('business'));Check::same([1],$e->rows('intents'));Check::same([],$e->rows('business',true));
    $e->pdo->exec('ROLLBACK');Check::same([],$e->rows('intents',true));
});
// Cleanup failures poison the service but preserve host ownership; the host can still abort everything.
foreach(['rollback','restore','release-ack','late-release'] as $failure){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($failure):void{
    $unit=$e->unit(100);$setting=$e->mysql?'SET SESSION innodb_lock_wait_timeout=9':'PRAGMA busy_timeout=4000';$e->pdo->exec($setting);$e->begin();$e->business();
    $e->pdo->afterExec=static function(string $sql)use($e,$failure,$setting):void{
        if($failure==='restore'&&$sql===$setting){throw new RuntimeException('SYNTHETIC-SECRET');}
        if($failure==='release-ack'&&strpos($sql,'RELEASE SAVEPOINT sosecurity_witness_')===0){$e->pdo->afterExec=null;throw new RuntimeException('SYNTHETIC-SECRET');}
        if($failure==='late-release'&&strpos($sql,'RELEASE SAVEPOINT sosecurity_enlisted_')===0){usleep(150000);}
    };
    if($failure==='rollback'){$e->pdo->beforeExec=static function(string $sql):void{if(strpos($sql,'ROLLBACK TO SAVEPOINT sosecurity_enlisted_')===0){throw new RuntimeException('SYNTHETIC-SECRET');}};}
    enlistRefused('sql.cleanup',static function()use($e,$unit,$failure):void{
        $unit->enlist(static function()use($e,$unit,$failure):void{
            $e->intent($unit);
            if($failure==='rollback'){throw new RuntimeException('SYNTHETIC-SECRET');}
        });
    });
    $e->pdo->afterExec=null;$e->pdo->beforeExec=null;Check::same([1],$e->rows('business'));Check::same([],$e->rows('business',true));
    enlistRefused('sql.cleanup',static function()use($unit):void{$unit->enlist(static function():void{});});
    $e->pdo->exec('ROLLBACK');Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
});}
// The borrowed scope restores the connection timeout on both success and a known local rollback.
foreach([false,true] as $throws){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($throws):void{
    $unit=$e->unit(250);$e->pdo->exec($e->mysql?'SET SESSION innodb_lock_wait_timeout=7':'PRAGMA busy_timeout=4321');$e->begin();$e->business();
    $body=static function()use($e,$unit,$throws):void{$timeout=(int)$e->pdo->query($e->mysql?'SELECT @@SESSION.innodb_lock_wait_timeout':'PRAGMA busy_timeout')->fetchColumn();Check::same(true,$timeout>=1&&$timeout<=($e->mysql?1:250));$e->intent($unit);if($throws){throw new RuntimeException('SYNTHETIC-SECRET');}};
    if($throws){enlistRefused('sql.unavailable',static function()use($unit,$body):void{$unit->enlist($body);});}else{$unit->enlist($body);}
    Check::same($e->mysql?'7':'4321',(string)$e->pdo->query($e->mysql?'SELECT @@SESSION.innodb_lock_wait_timeout':'PRAGMA busy_timeout')->fetchColumn());Check::same(false,$unit->committed());
    $e->pdo->exec('ROLLBACK');Check::same([],$e->rows('intents',true));
});}
// Actual nesting inside an owned security transaction commits or rolls back business and intent together.
foreach([false,true] as $throws){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($throws):void{
    $outer=$e->unit();$inner=$e->unit();$calls=0;
    $body=static function()use($e,$inner,$throws,&$calls):int{
        ++$calls;$e->business();$inner->enlist(static function()use($e,$inner):void{$e->intent($inner);});
        Check::same(false,$inner->committed());Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
        if($throws){throw new RuntimeException('SYNTHETIC-SECRET');}return 42;
    };
    if($throws){enlistRefused('sql.unavailable',static function()use($outer,$body):void{$outer->run($body);});}else{Check::same(42,$outer->run($body));}
    Check::same(1,$calls);Check::same(!$throws,$outer->committed());Check::same($throws?[]:[1],$e->rows('business',true));Check::same($throws?[]:[1],$e->rows('intents',true));
});}
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
    $outer=$e->unit();$inner=$e->unit();$e->begin();$e->business();
    enlistRefused('sql.unavailable',static function()use($e,$outer,$inner):void{$outer->enlist(static function()use($e,$outer,$inner):void{
        $e->intent($outer,1);$inner->enlist(static function()use($e,$inner):void{$e->intent($inner,2);});throw new RuntimeException('SYNTHETIC-SECRET');
    });});
    Check::same([1],$e->rows('business'));Check::same([],$e->rows('intents'));$e->pdo->exec('ROLLBACK');
});
// Reentry into the same unit is refused before a second callback can execute.
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
    $unit=$e->unit();$e->begin();$e->business();$calls=0;
    enlistRefused('test.reentry',static function()use($e,$unit,&$calls):void{$unit->enlist(static function()use($e,$unit,&$calls):void{
        $e->intent($unit);$unit->invoke(static function()use($unit,&$calls):void{$unit->enlist(static function()use(&$calls):void{++$calls;});},[],'test.reentry');
    });});
    Check::same(0,$calls);Check::same([1],$e->rows('business'));Check::same([],$e->rows('intents'));$e->pdo->exec('ROLLBACK');
});
if(($argv[2]??'')==='transaction-only'){echo 'PASS SQL enlistment transaction-only '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;return;}
// Compose with the actual public idempotency executor. Replays must never append a second delivery intent.
foreach(['success','handler-failure','revoked','lost-commit-ack'] as $mode){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($mode):void{
    $e->installIdempotency();$unit=$e->unit();$calls=0;$keys=new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('k',32)]);
    $authority=static function(string $phase)use($mode):bool{return $mode!=='revoked'||$phase!=='commit';};
    $create=static function(PDO $pdo)use($e,$keys,$authority):SoSecurity\Idempotency\SqlExecutor{return new SoSecurity\Idempotency\SqlExecutor($pdo,'enlistment-test',str_repeat('e',64),$keys,$authority,null,$e->clock,static function():bool{return true;});};
    $executor=$create($e->pdo);Check::same(true,$executor->initialize('tenant','alice','orders.create'));
    $request=new SoSecurity\Idempotency\Request('tenant','alice','orders.create','request-key-00000001','POST','/orders','{}');
    $handler=static function(PDO $pdo)use($e,$unit,$mode,&$calls):SoSecurity\Idempotency\Response{
        ++$calls;Check::same($e->pdo,$pdo);$e->business();$unit->enlist(static function()use($e,$unit):void{$e->intent($unit);});
        Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
        if($mode==='handler-failure'){throw new RuntimeException('SYNTHETIC-SECRET');}return new SoSecurity\Idempotency\Response(201,'saved');
    };
    if($mode==='lost-commit-ack'){$e->pdo->afterCommit=static function():void{throw new RuntimeException('SYNTHETIC-SECRET');};}
    if($mode==='success'){$first=$executor->execute($request,$handler);Check::same(false,$first->replayed());Check::same(true,$executor->execute($request,$handler)->replayed());}
    else{enlistRefused($mode==='handler-failure'?'idempotency.handler':($mode==='revoked'?'idempotency.denied':'sql.cleanup'),static function()use($executor,$request,$handler):void{$executor->execute($request,$handler);});}
    Check::same(1,$calls);Check::same(false,$unit->committed());$committed=in_array($mode,['success','lost-commit-ack'],true);
    Check::same($committed?[1]:[],$e->rows('business',true));Check::same($committed?[1]:[],$e->rows('intents',true));
    if($mode==='lost-commit-ack'){
        $e->pdo->afterCommit=null;$recovered=$create($e->observer)->execute($request,$handler);Check::same(true,$recovered->replayed());Check::same('saved',$recovered->response()->body());Check::same(1,$calls);
    }
});}
echo 'PASS SQL enlistment: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; provisional writes require host commit\n";
