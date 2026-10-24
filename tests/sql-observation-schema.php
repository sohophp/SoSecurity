<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Outbox\Schema;
use SoSecurity\Exception\ConfigurationException;
foreach(['valid','missing-index','wrong-index','partial-index','extra-column','trigger','long-index','many-indexes','main-table','temp-table','main-list','temp-list','main-info','temp-info'] as $mode){outboxCase(false,static function(OutboxEnvironment $e)use($mode):void{
 if(in_array($mode,['missing-index','wrong-index','partial-index'],true)){$e->pdo->exec('DROP INDEX sosecurity_outbox_due');}
 if($mode==='wrong-index'){$e->pdo->exec('CREATE INDEX sosecurity_outbox_due ON sosecurity_outbox_records(namespace,order_no)');}
 if($mode==='partial-index'){$e->pdo->exec("CREATE INDEX sosecurity_outbox_due ON sosecurity_outbox_records(namespace,status,available_at,order_no) WHERE status='pending'");}
 if($mode==='extra-column'){$e->pdo->exec('ALTER TABLE sosecurity_outbox_records ADD COLUMN extra TEXT NOT NULL DEFAULT \'\'');}
 if($mode==='trigger'){$e->pdo->exec('CREATE TRIGGER owned_trigger AFTER INSERT ON sosecurity_outbox_records BEGIN SELECT 1; END');}
 if($mode==='long-index'){$e->pdo->exec('CREATE INDEX "'.str_repeat('i',257).'" ON sosecurity_outbox_records(namespace)');}
 if($mode==='many-indexes'){$e->pdo->beginTransaction();for($i=0;$i<129;++$i){$e->pdo->exec('CREATE INDEX owned_extra_'.$i.' ON sosecurity_outbox_records(namespace)');}$e->pdo->commit();}
 $parts=explode('-',$mode);if(in_array($parts[0],['main','temp'],true)){$name=['table'=>'pragma_table_info','list'=>'pragma_index_list','info'=>'pragma_index_info'][$parts[1]];$e->pdo->exec('CREATE '.($parts[0]==='temp'?'TEMP ':'').'TABLE '.$name.'(value TEXT)');}
 $unit=SqlTransaction::forObservation($e->pdo,$e->clock,10000);$run=static function()use($unit){$unit->run(static function()use($unit){Schema::verify($unit);});};
 if($mode==='valid'){
  $run();Check::same(0,$e->count(true));$called=false;
  $unit->run(static function()use($unit,&$called){
   Check::throws(ConfigurationException::class,static function()use($unit){$unit->query('DELETE FROM sosecurity_outbox_records');});
   Check::throws(ConfigurationException::class,static function()use($unit){$unit->query("PRAGMA main.table_info('sosecurity_outbox_records')");});
   Check::throws(ConfigurationException::class,static function()use($unit,&$called){$unit->invoke(static function()use(&$called){$called=true;},[],'owned.callback');});
  });Check::same(false,$called);
 }else{try{$run();throw new RuntimeException('Invalid observed schema accepted: '.$mode);}catch(ConfigurationException $error){Check::same('configuration.sql_schema',$error->reason());}Check::same(0,$e->count(true));}
});}
echo 'PASS read-only SQL schema checks: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
