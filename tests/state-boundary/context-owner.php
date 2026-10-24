<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $protected=$x->boundary->protect($x->store);$before=entryFiles($x);$report=$x->e->directory.'/owned-child-result';
    if(function_exists('pcntl_fork')&&function_exists('posix_kill')){
        $x->boundary->run('owned.context.fork',static function()use($x,$protected,$report):void{
            $pid=pcntl_fork();if($pid===-1){throw new RuntimeException('Owned fork failed');}
            if($pid===0){$result='written';try{$protected->transact(str_repeat('a',64),static function(){return new SoSecurity\Storage\Change(['forbidden'=>true],300,true);});}catch(SoSecurity\Exception\SecurityException $e){$result=$e->reason();}file_put_contents($report,$result);posix_kill(getmypid(),9);exit(99);}
            pcntl_waitpid($pid,$status);Check::same(true,pcntl_wifsignaled($status));
        });
        $result=file_get_contents($report);if($result==='written'){throw new RuntimeException('UNSAFE_INHERITED_STATE_AUTHORITY');}Check::same('account.state_required',$result);Check::same($before,entryFiles($x));
    }else{echo "NOT RUN process context ownership: pcntl/posix unavailable\n";}
    if(class_exists('Fiber')){
        $fiber=new Fiber(static function()use($x):void{$x->boundary->run('owned.context.fiber',static function():void{Fiber::suspend();});});$fiber->start();Check::same(false,$x->boundary->active());$caught=null;
        try{$x->boundary->run('owned.foreign.fiber',static function()use($protected):void{$protected->transact(str_repeat('b',64),static function(){return new SoSecurity\Storage\Change(['forbidden'=>true],300,true);});});}catch(SoSecurity\Exception\SecurityException $error){$caught=$error->reason();}
        $fiber->resume();if($caught===null){throw new RuntimeException('UNSAFE_INHERITED_STATE_AUTHORITY');}Check::same('account.state_context',$caught);Check::same($before,entryFiles($x));
    }else{echo "NOT RUN Fiber context ownership: PHP runtime has no Fiber\n";}
});
echo 'PASS operation context ownership: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; forked child and foreign Fiber cannot inherit active write authority\n";
