<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $dir=$x->e->directory.'/entry-bound-fence';Check::same([],glob($dir.'/*.fence'));$fence=entryPromote($x);Check::same(true,$x->boundary->coversFence($fence));Check::same(true,$x->witness->coversFence($fence));Check::same(true,$x->source->coversFence($fence));$path=glob($dir.'/*.fence')[0];$raw=file_get_contents($path);$context=json_encode(['SoSecurity.Account.LocalEpochFence.2','managed-test','tenant',str_repeat('e',64),$x->boundary->binding()]);$parts=explode("\n",$raw);Check::same(true,$x->e->keys->verify($parts[1],$context."\n".$parts[0],hex2bin($parts[2])));$before=$x->inspect();$marker=0;$x->boundary->run('owned.worker.read',static function()use($fence,&$marker):void{$fence->work(static function()use(&$marker):void{++$marker;});});Check::same(1,$marker);$x->boundary->run('owned.worker.close_observe',static function()use($x,$fence):void{$fence->drain(static function()use($x):void{Check::same(64,strlen($x->source->digest()));});});$closed=$x->inspect();Check::same(false,$before['digest']===$closed['digest']);$files=entryFiles($x);file_put_contents($path,$raw);$called=0;witnessReason('account.witness_stale',static function()use($x,$fence,&$called):void{$x->boundary->run('owned.worker.rollback',static function()use($fence,&$called):void{$fence->work(static function()use(&$called):void{++$called;});});});Check::same(0,$called);Check::same($closed,$x->inspect());Check::same($files,entryFiles($x));
});
entryCase(static function(EntryEnvironment $x):void{
    $source=new SoSecurity\Account\CompositeStateSnapshot($x->e->pdo,['complete-sql'=>$x->sources['sql'],'sessions-and-factors'=>$x->sources['files']],30000);$dir=$x->e->directory.'/uncovered-witness';mkdir($dir,0700);$w=new SoSecurity\Account\LocalStateWitness($x->e->pdo,$dir,'managed-test','tenant',str_repeat('e',64),$x->e->keys,$source,'witnessPersist',30000);$b=new SoSecurity\Account\StateBoundary($w,static function():bool{return true;});$count=$x->e->pdo->queries;$physical=$x->e->directory.'/entry-bound-fence';$error=null;try{new SoSecurity\Account\LocalEpochFence($physical,'managed-test','tenant',str_repeat('e',64),$x->e->keys,'witnessPersist',5000,$b);}catch(SoSecurity\Exception\ConfigurationException $caught){$error=$caught;}Check::same(true,$error instanceof SoSecurity\Exception\ConfigurationException);Check::same('configuration.state_coverage',$error->reason());Check::same([],glob($physical.'/*.fence'));Check::same($count,$x->e->pdo->queries);Check::same([],glob($dir.'/*'));
});
entryCase(static function(EntryEnvironment $x):void{
    $fence=entryPromote($x);$path=glob($x->e->directory.'/entry-bound-fence/*.fence')[0];$open=file_get_contents($path);
    $x->boundary->run('owned.fresh.close',static function()use($fence):void{$fence->drain(static function():void{});});$before=$x->inspect();
    $meta=$x->e->directory.'/fence-probe.json';$target=['directory'=>$x->e->directory,'time'=>$x->e->clock->time,'secret'=>$x->e->secret,'backend'=>$x->e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME),'format'=>2];
    foreach([false,true] as $restored){
        if($restored){file_put_contents($path,$open);}
        file_put_contents($meta,json_encode(['target'=>$target,'source'=>$x->source->fingerprint(),'before'=>$before,'restored'=>$restored]));chmod($meta,0600);
        $command=escapeshellarg(PHP_BINARY).' -d memory_limit=16M '.escapeshellarg(__DIR__.'/fence-source-worker.php').' '.escapeshellarg($meta);$pipes=[];$p=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        if(!is_resource($p)){throw new RuntimeException('Owned fence reader unavailable.');}fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($p);
        if($code!==0){throw new RuntimeException('Owned fence reader failed: '.$errors.$output);}echo $output;Check::same(0,$code);Check::same($before,$x->inspect());
    }unlink($meta);
});
echo 'PASS complete fence source integration: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; actual declared authority directories, changing values, valid signed old open bytes rejected in original and fresh processes, omitted directory refused without provisioning\n";
