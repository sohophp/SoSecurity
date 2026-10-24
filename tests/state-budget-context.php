<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\StateExecutionContext;
use SoSecurity\Support\Deadline;
use SoSecurity\Storage\StorageException;
$cell=new StateExecutionContext();$cell->enter(new Deadline(1000));
$observe=static function()use($cell):float{$deadline=new Deadline(5000);$cell->restrictDeadline($deadline);return $deadline->remaining();};
Check::same(true,$observe()<=1.0);
Check::same(7,$cell->withinBudget(new Deadline(100),static function()use($observe):int{Check::same(true,$observe()<=0.1);return 7;}));
Check::same(true,$observe()>0.5);
try{$cell->withinBudget(new Deadline(100),static function():void{throw new RuntimeException('Owned scope abort');});throw new RuntimeException('Missing exception');}catch(RuntimeException $error){Check::same('Owned scope abort',$error->getMessage());}
Check::same(true,$observe()>0.5);
try{$cell->withinBudget(new Deadline(10),static function():void{usleep(30000);});throw new RuntimeException('Expired result returned');}catch(StorageException $error){Check::same('account.operation_timeout',$error->reason());}
Check::same(true,$observe()>0.5);$cell->leave();
try{$observe();throw new RuntimeException('Inactive authority accepted');}catch(StorageException $error){Check::same('account.state_required',$error->reason());}
$cell->enter();Check::same(true,$observe()>4.0);$cell->leave();
if(class_exists('Fiber',false)){
    $cell->enter(new Deadline(5000));$fiber=new Fiber(static function()use($cell):string{try{$cell->restrictDeadline(new Deadline(5000));return 'accepted';}catch(StorageException $error){return $error->reason();}});$fiber->start();Check::same('account.state_required',$fiber->getReturn());Check::same(true,$cell->active());$cell->leave();echo 'PASS budget scope foreign Fiber'.PHP_EOL;
}else{echo 'NOT RUN budget scope foreign Fiber: unavailable'.PHP_EOL;}
if(function_exists('pcntl_fork')){
    $directory=privateDirectory();$report=$directory.'/child-result';$cell->enter(new Deadline(5000));
    try{$pid=pcntl_fork();if($pid===-1){throw new RuntimeException('Owned fork failed');}if($pid===0){$reason='accepted';try{$cell->restrictDeadline(new Deadline(5000));}catch(StorageException $error){$reason=$error->reason();}file_put_contents($report,$reason);exit(0);}pcntl_waitpid($pid,$status);Check::same(true,pcntl_wifexited($status));Check::same(0,pcntl_wexitstatus($status));Check::same('account.state_required',file_get_contents($report));Check::same(true,$cell->active());echo 'PASS budget scope fork ownership'.PHP_EOL;}
    finally{$cell->leave();cleanDirectory($directory);}
}else{echo 'NOT RUN budget scope fork ownership: unavailable'.PHP_EOL;}
echo 'PASS bounded execution budget context '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
