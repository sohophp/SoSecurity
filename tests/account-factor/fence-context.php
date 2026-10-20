<?php
declare(strict_types=1);
require __DIR__.'/fence-support.php';
if(getenv('SOSECURITY_FENCE_CONTEXT_BEFORE')){$loader=require dirname(__DIR__,2).'/vendor/autoload.php';$loader->addClassMap(['SoSecurity\Account\LocalEpochFence'=>getenv('SOSECURITY_FENCE_CONTEXT_BEFORE')]);}
$mode=$argv[2]??'work-process';$mysql=($argv[1]??'')==='mysql';
if(in_array($mode,['work-fiber','closed-fiber','fiber-cancel'],true)&&(PHP_VERSION_ID<80100||!class_exists('Fiber',false))){echo 'NOT RUN local fence context '.$mode.': native Fiber unavailable on PHP '.PHP_VERSION."\n";exit(0);}
if(in_array($mode,['work-process','closed-process','child-release'],true)&&(!function_exists('pcntl_fork')||!function_exists('posix_kill'))){echo 'NOT RUN local fence context '.$mode.': pcntl/posix unavailable'."\n";exit(0);}
function contextDatabase(string $directory,bool $mysql):array
{
    if(!$mysql){$dsn='sqlite:'.$directory.'/business.sqlite';$user=null;$password=null;}
    else{$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned local no-TCP MySQL required');}$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4';$user='sosecurity_test';$password='integration-only';}
    $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];$db=new PDO($dsn,$user,$password,$options);$db->exec('DROP TABLE IF EXISTS fence_context_probe');$db->exec('CREATE TABLE fence_context_probe(id INTEGER NOT NULL PRIMARY KEY)');if(!$mysql){chmod($directory.'/business.sqlite',0600);}$db=null;return [$dsn,$user,$password,$options];
}
function contextWrite(array $connection,int $id):void{$db=new PDO($connection[0],$connection[1],$connection[2],$connection[3]);$db->exec('INSERT INTO fence_context_probe(id) VALUES('.$id.')');}
function contextCount(array $connection):int{$db=new PDO($connection[0],$connection[1],$connection[2],$connection[3]);return (int)$db->query('SELECT COUNT(*) FROM fence_context_probe')->fetchColumn();}
function contextRead($stream):string{stream_set_timeout($stream,5);$v=fread($stream,1);if($v===false||$v===''){throw new RuntimeException('Owned IPC did not arrive');}return $v;}
function contextWait(int $pid):void{pcntl_waitpid($pid,$status);Check::same(true,pcntl_wifsignaled($status));Check::same(9,pcntl_wtermsig($status));}
function contextDenied(callable $work):void{fenceReason('factor.fence_context',$work);}
fenceCase(static function(string $dir)use($mode,$mysql):void{
    $connection=contextDatabase($dir,$mysql);$f=fence($dir);$f->initialize();$before=file_get_contents(fencePath($dir));
    if(in_array($mode,['work-process','closed-process'],true)){
        if(!function_exists('pcntl_fork')||!function_exists('posix_kill')){echo "NOT RUN process context: pcntl/posix unavailable\n";return;}
        $pair=stream_socket_pair(STREAM_PF_UNIX,STREAM_SOCK_STREAM,STREAM_IPPROTO_IP);if($pair===false){throw new RuntimeException('Owned socket pair failed');}$pid=null;$result=$dir.'/child-result';
        $spawn=static function()use(&$pid,$pair,$f,$connection,$result,$mode):void{
            $pid=pcntl_fork();if($pid<0){throw new RuntimeException('Owned fork failed');}
            if($pid===0){fclose($pair[0]);fwrite($pair[1],'r');contextRead($pair[1]);$status='written';try{if($mode==='work-process'){$f->work(static function()use($connection):void{contextWrite($connection,1);});}else{$f->closedWork(static function()use($connection):void{contextWrite($connection,1);});}}catch(SoSecurity\Storage\StorageException $e){$status=$e->reason();}file_put_contents($result,$status);posix_kill(getmypid(),9);exit(99);}
            fclose($pair[1]);contextRead($pair[0]);
        };
        if($mode==='work-process'){$f->work($spawn);$f->drain(static function():void{},static function():bool{return true;});}else{$f->drain($spawn,static function():bool{return true;});}
        fwrite($pair[0],'g');contextWait($pid);fclose($pair[0]);$status=file_get_contents($result);$count=contextCount($connection);if($count!==0){throw new RuntimeException('UNSAFE_FENCE_INHERITED_CAPABILITY_'.$mode);}
        Check::same('factor.fence_context',$status);Check::same(0,$count);fenceReason('factor.fence_closed',static function()use($f):void{$f->work(static function():void{});});
    }elseif(in_array($mode,['work-fiber','closed-fiber'],true)){
        if(!class_exists('Fiber')){echo "NOT RUN Fiber context: runtime has no Fiber\n";return;}
        $fiber=new Fiber(static function()use($mode,$f):void{$op=static function():void{Fiber::suspend();};if($mode==='work-fiber'){$f->work($op);}else{$f->drain($op,static function():bool{return true;});}});$fiber->start();$error=null;
        try{if($mode==='work-fiber'){$f->work(static function()use($connection):void{contextWrite($connection,1);});}else{$f->closedWork(static function()use($connection):void{contextWrite($connection,1);});}}catch(SoSecurity\Storage\StorageException $e){$error=$e->reason();}$fiber->resume();$count=contextCount($connection);if($count!==0){throw new RuntimeException('UNSAFE_FENCE_INHERITED_CAPABILITY_'.$mode);}Check::same('factor.fence_context',$error);Check::same(0,$count);
    }elseif($mode==='child-release'){
        if(!function_exists('pcntl_fork')||!function_exists('posix_kill')){echo "NOT RUN child cleanup context: pcntl/posix unavailable\n";return;}
        $pair=stream_socket_pair(STREAM_PF_UNIX,STREAM_SOCK_STREAM,STREAM_IPPROTO_IP);if($pair===false){throw new RuntimeException('Owned socket pair failed');}$isChild=false;$pid=null;$childResult='returned';
        try{$f->work(static function()use($f,$dir,$connection,$pair,&$isChild,&$pid):void{
            $pid=pcntl_fork();if($pid<0){throw new RuntimeException('Owned fork failed');}if($pid===0){$isChild=true;fclose($pair[0]);return;}
            fclose($pair[1]);contextRead($pair[0]);$error=null;
            try{fence($dir)->drain(static function()use($connection):void{contextWrite($connection,99);},static function():bool{return true;});}catch(SoSecurity\Storage\StorageException $e){$error=$e->reason();}
            fwrite($pair[0],'g');contextWait($pid);fclose($pair[0]);if(contextCount($connection)!==0){throw new RuntimeException('UNSAFE_FENCE_CHILD_RELEASED_PARENT_LOCK');}Check::same('factor.fence_timeout',$error);
        });}catch(SoSecurity\Storage\StorageException $error){if(!$isChild){throw $error;}$childResult=$error->reason();}
        if($isChild){file_put_contents($dir.'/child-cleanup-result',$childResult);fwrite($pair[1],'r');contextRead($pair[1]);posix_kill(getmypid(),9);exit(99);}
        Check::same('factor.fence_context',file_get_contents($dir.'/child-cleanup-result'));Check::same(0,contextCount($connection));$f->drain(static function():void{},static function():bool{return true;});
    }elseif($mode==='fiber-cancel'){
        if(!class_exists('Fiber')){echo "NOT RUN Fiber cancellation: runtime has no Fiber\n";return;}
        $fiber=new Fiber(static function()use($f):void{$f->work(static function():void{Fiber::suspend();});});$fiber->start();unset($fiber);gc_collect_cycles();Check::same(44,$f->work(static function():int{return 44;}));Check::same($before,file_get_contents(fencePath($dir)));
        $fiber=new Fiber(static function()use($f):void{$f->drain(static function():void{Fiber::suspend();},static function():bool{return true;});});$fiber->start();unset($fiber);gc_collect_cycles();fenceReason('factor.fence_closed_context',static function()use($f):void{$f->closedWork(static function():void{});});Check::same(45,$f->drain(static function():int{return 45;},static function():bool{return true;}));
    }elseif($mode==='clone-work'){
        $copy=null;$f->work(static function()use($f,&$copy):void{$copy=clone $f;});$f->drain(static function():void{},static function():bool{return true;});$error=null;
        try{$copy->work(static function()use($connection):void{contextWrite($connection,1);});}catch(SoSecurity\Storage\StorageException $e){$error=$e->reason();}if(contextCount($connection)!==0){throw new RuntimeException('UNSAFE_FENCE_CLONED_ACTIVE_SCOPE');}Check::same('factor.fence_context',$error);Check::same(0,contextCount($connection));
    }elseif($mode==='same-context'){
        Check::same(42,$f->work(static function()use($f):int{return $f->work(static function():int{return 42;});}));Check::same($before,file_get_contents(fencePath($dir)));
        Check::same(43,$f->drain(static function()use($f):int{return $f->closedWork(static function()use($f):int{return $f->closedWork(static function():int{return 43;});});},static function():bool{return true;}));
        fenceReason('factor.fence_closed_context',static function()use($f):void{$f->closedWork(static function():void{});});
    }else{throw new RuntimeException('Unknown owned context mode');}
});
echo 'PASS local fence context '.$mode.': '.Check::$assertions.' assertions '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."\n";
