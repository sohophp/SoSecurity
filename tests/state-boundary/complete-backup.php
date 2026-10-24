<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';

require __DIR__.'/complete-backup-support.php';
foreach(['session','password','factor','recovery'] as $mode){
    entryCase(static function(EntryEnvironment $x)use($mode):void{
        $e=$x->e;$login=$x->login();$token=$login->credential()->token();$remember=$x->remember->issue('tenant','user',$token,'Owned backup device');Check::same(true,$remember!==null);
        $input=['mysql'=>$e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql','time'=>$e->clock->time,'session'=>$token,'remember'=>$remember->token(),'mode'=>$mode,'recovery'=>$e->codes[0],'factor'=>null];
        $backup=completeBackup($x);
        if($mode==='session'){Check::same(true,$x->sessions->revoke('tenant','user',$login->credential()->id()));}
        elseif($mode==='password'){
            $next=(new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]))->hash('Owned changed password after backup 49!');
            $changed=$x->boundary->run('owned.password.change',static function()use($e,$next){return $e->accounts->replacePassword($e->accounts->find('tenant','user'),$next);});Check::same(true,$changed!==null);
        }else{
            $result=$x->boundary->run('owned.factor.'.$mode,static function()use($x,$mode):array{$review=$x->operations->review($mode==='factor'?'disable':'regenerate','user','owned-backup-review');return $x->operations->execute($review,'owned-backup-change',normalProof(),normalFactor($x->e));});Check::same(true,$result['completed']);
        }
        if($mode==='recovery'){
            Check::same(false,$x->boundary->run('owned.old-recovery.refuse',static function()use($e,$input):bool{$slot=$e->registry->current('user');return $e->factors->verifyBound($slot->slotScope(),$slot->slotSubject(),$slot->factorId(),$input['recovery'],true);}));
        }else{Check::same(null,$x->sessions->verify('tenant','user',$token,2));}
        $current=$x->inspect();Check::same(false,$backup['digest']===$current['digest']);completeRestore($x,$backup);Check::same($current,$x->inspect());
        $lookups=$x->lookups;$calls=0;
        witnessReason('account.witness_stale',static function()use($x,$token):void{$x->sessions->verify('tenant','user',$token,2);});
        witnessReason('account.witness_stale',static function()use($x,$input):void{$x->remember->resume('tenant',$input['remember']);});
        witnessReason('account.witness_stale',static function()use($x,&$calls):void{$x->boundary->run('owned.must-not-write',static function()use(&$calls):void{++$calls;});});
        Check::same(0,$calls);Check::same($lookups,$x->lookups);Check::same($current,$x->inspect());
        // Separate process removes the protection, preserving the same real restored database/files.
        file_put_contents($e->directory.'/owned-state-backup-test','Owned complete authentication backup test');$path=$e->directory.'/negative-control.json';file_put_contents($path,json_encode($input));chmod($path,0600);
        $pipes=[];$command=escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/backup-without-boundary.php').' '.escapeshellarg($path);$process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        if(!is_resource($process)){throw new RuntimeException('Cannot start owned negative control.');}fclose($pipes[0]);$out=stream_get_contents($pipes[1],4096);$error=stream_get_contents($pipes[2],4096);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($process);
        if($code!==0){throw new RuntimeException('Owned negative control failed: '.$error);}$result=json_decode($out,true);Check::same(true,$result['session']);Check::same(true,$result['remember']);if($mode==='recovery'){Check::same(true,$result['recovery']);}
        echo 'PASS complete backup case '.$mode.': seven declared SQL tables and actual factor/session/remembered files restored; enabled witness refuses before business, omitted-witness control accepts old credentials',PHP_EOL;
    });
}
echo 'PASS complete authentication backup: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; independent witness retained, actual invalidation/rotation and dangerous unprotected control for four fixed scenarios',PHP_EOL;
