<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/sql-enlistment-support.php';
use SoSecurity\Support\SqlTransactionGuard;
use SoSecurity\Support\Deadline;
$mysql=($argv[1]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned private MySQL required');}
$legacy=($argv[2]??'')==='legacy';
function contextEntryGuardLoss(bool $mysql):void{
 enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
  $e->begin('sql');$e->business();$unit=$e->unit();$guards=0;$calls=0;
  SoSecurity\Support\SqlStateAccess::bind($e->pdo,hash('sha256','context-guard-loss'),hash('sha256','context-guard-loss-binding'),static function()use($e,&$guards):void{if(++$guards===1){$e->pdo->exec('COMMIT');}});
  $error=null;try{$unit->inContext(static function()use($e,$unit,&$calls):void{++$calls;$e->intent($unit);});}catch(SoSecurity\Exception\ConfigurationException $caught){$error=$caught;}
  echo 'GUARD_CONTEXT_LOSS '.json_encode(['rejected'=>$error!==null,'body_calls'=>$calls,'framework_committed'=>$unit->committed(),'intent_rows'=>$e->rows('intents',true)]).PHP_EOL;
  Check::same(true,$error instanceof SoSecurity\Exception\ConfigurationException);Check::same('configuration.transaction',$error->reason());Check::same(0,$calls);Check::same(false,$unit->committed());Check::same([1],$e->rows('business',true));Check::same([],$e->rows('intents',true));
 });
}
if(($argv[2]??'')==='guard-loss-only'){contextEntryGuardLoss($mysql);echo 'PASS SQL context guard loss '.Check::$assertions.PHP_EOL;return;}

enlistCase($mysql,static function(EnlistmentEnvironment $e)use($legacy):void{
 $unit=$e->unit();$e->begin('sql');$probes=0;$e->pdo->beforeExec=static function(string $sql)use($e,&$probes):void{if($e->mysql?strpos($sql,'SAVEPOINT sosecurity_active_')===0:$sql==='BEGIN DEFERRED'){++$probes;}};
 $body=static function()use($e,$unit):int{$e->intent($unit);return 7;};
 if($legacy){SqlTransactionGuard::assertActive($e->pdo,$unit->driver(),new Deadline(1000));$value=$unit->enlist($body);}else{$value=$unit->inContext($body);}
 Check::same(7,$value);Check::same(false,$unit->committed());Check::same([],$e->rows('intents',true));
 echo 'CONTEXT_OWNERSHIP_PROBES '.json_encode(['legacy'=>$legacy,'probes'=>$probes]).PHP_EOL;Check::same(1,$probes);
 $e->pdo->beforeExec=null;$e->pdo->exec('ROLLBACK');Check::same([],$e->rows('intents',true));
});

// Owned work commits exactly once; its completion callback still runs before that commit.
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
 $unit=$e->unit();$calls=0;$finish=0;
 Check::same(42,$unit->inContext(static function()use($e,$unit,&$calls):int{++$calls;$e->intent($unit);return 42;},static function(int $value)use($e,&$finish):void{++$finish;Check::same(42,$value);Check::same([],$e->rows('intents',true));}));
 Check::same(1,$calls);Check::same(1,$finish);Check::same(true,$unit->committed());Check::same([1],$e->rows('intents',true));
});
foreach(['native','sql'] as $mode){foreach(['COMMIT','ROLLBACK'] as $ending){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($mode,$ending):void{
 $unit=$e->unit();$e->begin($mode);$e->business();$calls=0;
 Check::same(7,$unit->inContext(static function()use($e,$unit,&$calls):int{++$calls;$e->intent($unit);return 7;}));
 Check::same(1,$calls);Check::same(false,$unit->committed());Check::same([1],$e->rows('business'));Check::same([1],$e->rows('intents'));Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
 $e->pdo->exec($ending);Check::same($ending==='COMMIT'?[1]:[],$e->rows('business',true));Check::same($ending==='COMMIT'?[1]:[],$e->rows('intents',true));
});}}
foreach([false,true] as $host){foreach(['body','finish','clock','context-error'] as $failure){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($host,$failure):void{
 $unit=$e->unit();if($host){$e->begin();$e->business();}$calls=0;$caught=null;
 try{$unit->inContext(static function()use($e,$unit,$failure,&$calls):int{++$calls;$e->intent($unit);if($failure==='clock'){--$e->clock->time;}if($failure==='body'){throw new RuntimeException('SYNTHETIC-SECRET');}if($failure==='context-error'){throw new SoSecurity\Exception\ConfigurationException('Expected context refusal.','configuration.transaction');}return 7;},static function(int $value)use($failure):void{if($failure==='finish'){throw new RuntimeException('SYNTHETIC-SECRET');}});}catch(Throwable $error){$caught=$error;}
 Check::same(true,$caught instanceof SoSecurity\Exception\SecurityException||$caught instanceof SoSecurity\Exception\ConfigurationException);Check::same(1,$calls);Check::same(false,$unit->committed());Check::same([],$e->rows('intents'));Check::same([],$e->rows('intents',true));Check::same($host?[1]:[],$e->rows('business'));Check::same([],$e->rows('business',true));
 if($failure==='context-error'){Check::same('configuration.transaction',$caught->reason());}else{Check::same(false,strpos($caught->getMessage(),'SYNTHETIC-SECRET')!==false);}
 if($host){$e->pdo->exec('ROLLBACK');}
});}}
// A callback ending/replacing the host transaction cannot cause automatic owned execution.
foreach(['COMMIT','ROLLBACK'] as $ending){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($ending):void{
 $unit=$e->unit();$e->begin();$e->business();$calls=0;
 enlistRefused('sql.cleanup',static function()use($e,$unit,$ending,&$calls):void{$unit->inContext(static function()use($e,$unit,$ending,&$calls):void{++$calls;$e->intent($unit);$e->pdo->exec($ending);$e->begin();$e->business(2);});});
 Check::same(1,$calls);Check::same($ending==='COMMIT'?[1,2]:[2],$e->rows('business'));Check::same($ending==='COMMIT'?[1]:[],$e->rows('business',true));
 enlistRefused('sql.cleanup',static function()use($unit,&$calls):void{$unit->inContext(static function()use(&$calls):void{++$calls;});});Check::same(1,$calls);
 $e->pdo->exec('ROLLBACK');Check::same($ending==='COMMIT'?[1]:[],$e->rows('business',true));
});}
if($mysql){foreach(['idle','write','manual'] as $mode){enlistCase(true,static function(EnlistmentEnvironment $e)use($mode):void{
 $e->pdo->exec('SET autocommit=0');if($mode==='manual'){$e->pdo->exec('START TRANSACTION');}if($mode!=='idle'){$e->business();}$unit=$e->unit();$calls=0;
 enlistRefused('configuration.transaction',static function()use($unit,&$calls):void{$unit->inContext(static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);Check::same($mode==='idle'?[]:[1],$e->rows('business'));Check::same([],$e->rows('business',true));Check::same('0',(string)$e->pdo->query('SELECT @@SESSION.autocommit')->fetchColumn());
 $e->pdo->exec('ROLLBACK');$e->pdo->exec('SET autocommit=1');
});}}
// Entry registration assertions can change or delay context. The owned path must recheck and retain elapsed budget.
foreach(['new-host','elapsed-budget','denied'] as $mode){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($mode):void{
 $guardCalls=0;$bodyCalls=0;$unit=$e->unit($mode==='elapsed-budget'?20:1000);
 SoSecurity\Support\SqlStateAccess::bind($e->pdo,hash('sha256','context-'.$mode),hash('sha256','binding-'.$mode),static function()use($e,$mode,&$guardCalls):void{++$guardCalls;if($mode==='denied'){throw new SoSecurity\Storage\StorageException('Owned context denied.','account.state_required');}if($guardCalls===2){if($mode==='new-host'){$e->begin('sql');$e->business();}else{usleep(50000);}}});
 Check::throws($mode==='new-host'?SoSecurity\Exception\ConfigurationException::class:SoSecurity\Storage\StorageException::class,static function()use($unit,&$bodyCalls):void{$unit->inContext(static function()use(&$bodyCalls):void{++$bodyCalls;});});
 Check::same(0,$bodyCalls);Check::same($mode==='new-host'?[1]:[],$e->rows('business'));Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents',true));
 if($mode==='new-host'){$e->pdo->exec('ROLLBACK');}
});}
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
 $unit=SoSecurity\Support\SqlTransaction::forObservation($e->pdo,$e->clock,1000);$calls=0;
 enlistRefused('configuration.state_observation',static function()use($unit,&$calls):void{$unit->inContext(static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);
});
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
 $unit=$e->unit();$e->begin();$e->business();$calls=0;
 $e->pdo->beforeExec=static function(string $sql)use($e):void{if($e->mysql?strpos($sql,'SAVEPOINT sosecurity_active_')===0:$sql==='BEGIN DEFERRED'){throw new RuntimeException('SYNTHETIC-SECRET');}};
 enlistRefused('sql.cleanup',static function()use($unit,&$calls):void{$unit->inContext(static function()use(&$calls):void{++$calls;});});
 $e->pdo->beforeExec=null;enlistRefused('sql.cleanup',static function()use($unit,&$calls):void{$unit->inContext(static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);Check::same([1],$e->rows('business'));Check::same([],$e->rows('business',true));$e->pdo->exec('ROLLBACK');
});
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
 $unit=$e->unit();$e->begin();$e->business();$calls=0;$budget=new Deadline(20);
 Check::throws(SoSecurity\Storage\StorageException::class,static function()use($e,$unit,$budget,&$calls):void{$unit->inContext(static function()use($e,$unit,&$calls):void{++$calls;$e->intent($unit);usleep(50000);},null,$budget);});
 Check::same(1,$calls);Check::same(false,$unit->committed());Check::same([1],$e->rows('business'));Check::same([],$e->rows('business',true));Check::same([],$e->rows('intents'));$e->pdo->exec('ROLLBACK');
});
foreach([false,true] as $host){enlistCase($mysql,static function(EnlistmentEnvironment $e)use($host):void{
 $unit=$e->unit();$calls=0;if($host){$e->begin();$e->business();}
 enlistRefused('context.reentry',static function()use($e,$unit,&$calls):void{$unit->inContext(static function()use($e,$unit,&$calls):void{$e->intent($unit);$unit->invoke(static function()use($unit,&$calls):void{$unit->inContext(static function()use(&$calls):void{++$calls;});},[],'context.reentry');});});
 Check::same(0,$calls);Check::same([],$e->rows('intents'));Check::same([],$e->rows('intents',true));Check::same($host?[1]:[],$e->rows('business'));if($host){$e->pdo->exec('ROLLBACK');}
});}
// A custom guard is not assumed pure merely because it happens to return without changing state.
enlistCase($mysql,static function(EnlistmentEnvironment $e):void{
 $unit=$e->unit();$e->begin('sql');$probes=0;
 SoSecurity\Support\SqlStateAccess::bind($e->pdo,hash('sha256','context-custom'),hash('sha256','context-custom-binding'),static function():void{});
 Check::same(false,SoSecurity\Support\SqlStateAccess::pureEntryGuard($e->pdo));
 $e->pdo->beforeExec=static function(string $sql)use($e,&$probes):void{if($e->mysql?strpos($sql,'SAVEPOINT sosecurity_active_')===0:$sql==='BEGIN DEFERRED'){++$probes;}};
 Check::same(7,$unit->inContext(static function():int{return 7;}));Check::same(2,$probes);Check::same(false,$unit->committed());$e->pdo->beforeExec=null;$e->pdo->exec('ROLLBACK');
});
contextEntryGuardLoss($mysql);
echo 'PASS SQL context selection '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
