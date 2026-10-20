<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-recovery-support.php';
use SoSecurity\Examples\Outbox as Receiver;

recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    recoveryRefused(static function()use($e):void{$e->receive();});Check::same(0,$e->count());
    recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});
    $pdo=$e->pdo();$pdo->exec("UPDATE outbox_example_actors SET roles='[\"receiver_worker\"]'");
    recoveryRefused(static function()use($e):void{Receiver\receiverInitialize($e->settings());});
    $pdo->exec("UPDATE outbox_example_actors SET roles='[\"receiver_worker\",\"receiver_admin\"]'");
    Check::same(true,Receiver\receiverInitialize($e->settings()));Check::same(false,Receiver\receiverInitialize($e->settings()));
    Check::same(false,Receiver\receiverRecover($e->settings()));$status=Receiver\receiverInspect($e->settings());Check::same(0,$status['entries']);Check::same(0,$status['sequence']);Check::same(64,strlen($status['root_hash']));
    $confirmation=$e->receive();Check::same(true,$confirmation['committed']);Check::same($e->delivery($e->body()),$confirmation['delivery_id']);Check::same(1,$e->count());
},false);

// Exercise actual initialization/rotation methods when COMMIT reports failure before or after durability.
foreach(['initialize','epoch'] as $operation){foreach(['witness-before','witness-after','business-after'] as $stage){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($operation,$stage):void{
    $status=$operation==='epoch'?Receiver\receiverInspect($e->settings()):null;
    if($operation==='epoch'){$e->configure(['epoch'=>str_repeat('f',64)]);}
    $s=$e->settings();$witness=strpos($stage,'witness-')===0;$key=$witness?'checkpoint_pdo':'pdo';
    $fault=new ReceiverRecoveryCommitFault('sqlite:'.$e->config[$witness?'checkpoint_database':'database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$fault->phase=$stage==='witness-before'?'before':'after';$s[$key]=$fault;
    Check::throws(RuntimeException::class,static function()use($operation,$s,$status):void{if($operation==='initialize'){Receiver\receiverInitialize($s);}else{Receiver\receiverRotateEpoch($s,$status['epoch'],$status['root_hash']);}});
    $s=null;$fault=null;recoveryRefused(static function()use($e):void{$e->receive();});
    if($stage==='witness-before'){
        if($operation==='initialize'){Check::same(true,Receiver\receiverInitialize($e->settings()));}
        else{Check::same(true,Receiver\receiverRotateEpoch($e->settings(),$status['epoch'],$status['root_hash']));}
    }else{Check::same(true,Receiver\receiverRecover($e->settings()));}
    Check::same(false,Receiver\receiverRecover($e->settings()));Check::same(0,Receiver\receiverInspect($e->settings())['entries']);Check::same(true,$e->receive()['committed']);Check::same(1,$e->count());
},$operation!=='initialize');}}

foreach(['prepared','business-uncommitted','business-committed','witness-committed'] as $phase){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($phase):void{
    recoveryKill($e,$phase);$committed=in_array($phase,['business-committed','witness-committed'],true);Check::same($committed?1:0,$e->count());
    if($phase!=='witness-committed'){recoveryRefused(static function()use($e):void{$e->receive();});}
    else{Check::same(true,$e->receive()['committed']);}
    Check::same($phase!=='witness-committed',Receiver\receiverRecover($e->settings()));Check::same(false,Receiver\receiverRecover($e->settings()));
    Check::same(true,$e->receive()['committed']);Check::same(1,$e->count());Check::same(1,(int)$e->pdo()->query('SELECT SUM(deliveries) FROM outbox_example_projection')->fetchColumn());
    Check::same($e->delivery($e->body()),$e->pdo()->query('SELECT delivery_id FROM outbox_example_effects')->fetchColumn());
});}

// Actual whole-file business restore. The independently committed witness is not restored.
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $empty=$e->backup('empty');$first=$e->receive();$one=$e->backup('one');$second=$e->receive(2);$witnessBefore=Receiver\receiverRead($e->pdo(true),'checkpoint');
    $e->restore($empty);Check::same(0,$e->count());
    foreach(['receiverInitialize','receiverRecover'] as $action){recoveryRefused(static function()use($e,$action):void{$call='SoSecurity\\Examples\\Outbox\\'.$action;$call($e->settings());});}
    recoveryRefused(static function()use($e):void{$e->receive(2);});Check::same(0,$e->count());
    $e->restore($one);recoveryRefused(static function()use($e):void{$e->receive(2);});Check::same(true,Receiver\receiverRecover($e->settings()));Check::same(2,$e->count());
    Check::same($first,$e->receive());Check::same($second,$e->receive(2));Check::same(2,(int)$e->pdo()->query('SELECT SUM(deliveries) FROM outbox_example_projection')->fetchColumn());
    Check::same($witnessBefore,Receiver\receiverRead($e->pdo(true),'checkpoint'));
});

// Partial restores cannot be blessed by --recover, even when the sealed root survived.
foreach(['DELETE FROM outbox_example_effects','DELETE FROM outbox_example_projection','UPDATE outbox_example_projection SET amount=amount+1','UPDATE outbox_example_projection SET deliveries=2'] as $change){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($change):void{
    $e->receive();$e->pdo()->exec($change);$before=Receiver\receiverRead($e->pdo(true),'checkpoint');
    recoveryRefused(static function()use($e):void{$e->receive();});recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});
    recoveryRefused(static function()use($e):void{Receiver\receiverInitialize($e->settings());});Check::same($before,Receiver\receiverRead($e->pdo(true),'checkpoint'));
});}
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $old=$e->backup('old-witness',true);$e->receive();$e->restore($old,true);
    recoveryRefused(static function()use($e):void{$e->receive();});recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});Check::same(1,$e->count());
});
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    recoveryPrepared($e);$e->configure(['epoch'=>str_repeat('f',64)]);recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});
    // Deployment control restores the original generation only after stopping workers, finishes its known intent, then advances.
    $e->configure(['epoch'=>str_repeat('e',64)]);Check::same(true,Receiver\receiverRecover($e->settings()));$status=Receiver\receiverInspect($e->settings());
    $e->configure(['epoch'=>str_repeat('f',64)]);Check::same(true,Receiver\receiverRotateEpoch($e->settings(),$status['epoch'],$status['root_hash']));Check::same(true,$e->receive()['committed']);Check::same(1,$e->count());
});

// A deployment epoch is changed outside both databases; rotation requires the independently retained root hash.
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $e->receive();$old=$e->settings();$status=Receiver\receiverInspect($old);$business=$e->backup('before-epoch');$witness=$e->backup('before-epoch-witness',true);
    $e->configure(['epoch'=>str_repeat('f',64)]);$new=$e->settings();
    recoveryRefused(static function()use($old):void{Receiver\receiverCurrent($old);});recoveryRefused(static function()use($new):void{Receiver\receiverCurrent($new);});
    recoveryRefused(static function()use($new,$status):void{Receiver\receiverRotateEpoch($new,$status['epoch'],str_repeat('0',64));});
    Check::same(true,Receiver\receiverRotateEpoch($new,$status['epoch'],$status['root_hash']));$updated=Receiver\receiverInspect($new);Check::same(1,$updated['entries']);Check::same($status['sequence']+1,$updated['sequence']);Check::same(str_repeat('f',64),$updated['epoch']);
    recoveryRefused(static function()use($new,$updated):void{Receiver\receiverRotateEpoch($new,$updated['epoch'],$updated['root_hash']);});Check::same(true,$e->receive()['committed']);
    $old=null;$new=null;$e->restore($business);recoveryRefused(static function()use($e):void{$e->receive();});Check::same(true,Receiver\receiverRecover($e->settings()));
    // Restoring both old databases remains rejected under the independently advanced configuration.
    $e->restore($business);$e->restore($witness,true);recoveryRefused(static function()use($e):void{$e->receive();});recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});
});

// Prepared replay retains current management, route, owner and worker authorization.
foreach(["UPDATE outbox_example_actors SET roles='[\"receiver_worker\"]'","UPDATE outbox_example_actors SET roles='[\"receiver_admin\"]'",'UPDATE outbox_example_actors SET enabled=0',"UPDATE outbox_example_actors SET version='2'",'UPDATE outbox_example_routes SET enabled=0','UPDATE outbox_example_owners SET enabled=0'] as $change){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($change):void{
    recoveryPrepared($e);$e->pdo()->exec($change);$before=Receiver\receiverRead($e->pdo(true),'checkpoint');
    recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});Check::same(0,$e->count());Check::same($before,Receiver\receiverRead($e->pdo(true),'checkpoint'));
});}

// SQL-only replay must participate in a real active business transaction and roll back together.
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $plan=recoveryPrepared($e);$s=$e->settings();
    recoveryRefused(static function()use($s,$plan):void{Receiver\receiverApplyPlan($s,$plan);});Check::same(0,$e->count());
    Check::throws(RuntimeException::class,static function()use($s,$plan):void{Receiver\receiverTransaction($s['pdo'],static function()use($s,$plan):void{Receiver\receiverApplyPlan($s,$plan);throw new RuntimeException('test rollback');});});
    Check::same(0,$e->count());Check::same(true,Receiver\receiverRecover($s));Check::same(true,$e->receive()['committed']);Check::same(1,$e->count());
});

// Bounded SQL projections reject corrupt sealed metadata before allocating the large field in PHP.
foreach([['business','outbox_example_receiver_root','payload',"CAST(x'00'||zeroblob(16777216) AS TEXT)"],['witness','outbox_example_receiver_checkpoint','payload','zeroblob(16777216)'],['business','outbox_example_receiver_root','seal_key',"CAST('a'||x'00'||zeroblob(16777216) AS TEXT)"],['business','outbox_example_effects','subject',"CAST('a'||x'00'||zeroblob(16777216) AS TEXT)"],['business','outbox_example_effects','amount',"CAST('1'||x'00'||zeroblob(16777216) AS TEXT)"]] as $case){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($case):void{
    $e->receive();$e->pdo($case[0]==='witness')->exec('UPDATE '.$case[1].' SET '.$case[2].'='.$case[3]);
    recoveryRefused(static function()use($e):void{Receiver\receiverInspect($e->settings());});recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});Check::same(1,$e->count());Check::same(true,memory_get_peak_usage(true)<8388608);
});}

// Current open handles are invalidated when a business, witness or lock file is replaced.
foreach(['database','checkpoint_database','checkpoint_lock'] as $field){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($field):void{
    $old=$e->settings();$path=$e->config[$field];$copy=$path.'.replacement';copy($path,$copy);chmod($copy,0600);rename($copy,$path);
    recoveryRefused(static function()use($old):void{Receiver\receiverInspect($old);});Check::same(0,Receiver\receiverInspect($e->settings())['entries']);
});}

// Missing history/keys cannot be silently reinitialized, adopted or re-sealed under a new key.
foreach(['DELETE FROM outbox_example_receiver_root','DELETE FROM outbox_example_receiver_checkpoint'] as $change){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($change):void{
    $e->receive();$e->pdo(strpos($change,'checkpoint')!==false)->exec($change);
    recoveryRefused(static function()use($e):void{Receiver\receiverInitialize($e->settings());});recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});Check::same(1,$e->count());
});}
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $e->receive();$old=json_decode(file_get_contents($e->config['seals']),true);recoveryJson($e->config['seals'],['current'=>'new','keys'=>['new'=>base64_encode(str_repeat('n',32))]]);
    recoveryRefused(static function()use($e):void{Receiver\receiverRecover($e->settings());});Check::same(1,$e->count());
    $retained=['current'=>'new','keys'=>$old['keys']+['new'=>base64_encode(str_repeat('n',32))]];recoveryJson($e->config['seals'],$retained);Check::same(true,$e->receive(2)['committed']);Check::same(2,$e->count());
});
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $e->receive();$e->pdo()->exec('DELETE FROM outbox_example_receiver_root');$e->pdo(true)->exec('DELETE FROM outbox_example_receiver_checkpoint');
    recoveryRefused(static function()use($e):void{Receiver\receiverInitialize($e->settings());});Check::same(1,$e->count());
});
foreach(['checkpoint_database','checkpoint_lock'] as $field){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($field):void{
    $e->configure([$field=>$e->config['database']]);Check::throws(RuntimeException::class,static function()use($e):void{$e->settings();});
});}
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $link=$e->directory.'/hardlink.sqlite';Check::same(true,link($e->config['database'],$link));$e->configure(['checkpoint_database'=>$link]);Check::throws(RuntimeException::class,static function()use($e):void{$e->settings();});
});
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $s=$e->settings();$wire=json_decode(file_get_contents($e->config['wire_keys']),true);recoveryJson($e->config['wire_keys'],json_decode(file_get_contents($e->config['seals']),true));
    recoveryRefused(static function()use($s):void{Receiver\receiverInspect($s);});recoveryJson($e->config['wire_keys'],$wire);Check::same(0,Receiver\receiverInspect($s)['entries']);
});

// Host transactions, durability loss, triggers and a busy management lock fail closed.
foreach([false,true] as $checkpoint){recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($checkpoint):void{
    $s=$e->settings();$pdo=$s[$checkpoint?'checkpoint_pdo':'pdo'];$pdo->exec('CREATE TABLE host_effects(id INTEGER NOT NULL)');$pdo->exec('BEGIN IMMEDIATE');$pdo->exec('INSERT INTO host_effects VALUES(1)');
    recoveryRefused(static function()use($s):void{Receiver\receiverRecover($s);});Check::same(0,(int)$e->pdo($checkpoint)->query('SELECT COUNT(*) FROM host_effects')->fetchColumn());$pdo->exec('COMMIT');Check::same(1,(int)$e->pdo($checkpoint)->query('SELECT COUNT(*) FROM host_effects')->fetchColumn());
    $pdo->exec('PRAGMA synchronous=OFF');recoveryRefused(static function()use($s):void{Receiver\receiverInspect($s);});$pdo->exec('PRAGMA synchronous=FULL');
});}
recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $s=$e->settings();$s['pdo']->exec('CREATE TRIGGER forbidden_root AFTER UPDATE ON outbox_example_receiver_root BEGIN SELECT 1; END');
    recoveryRefused(static function()use($s):void{Receiver\receiverInspect($s);});$s['pdo']->exec('DROP TRIGGER forbidden_root');
    $lock=fopen($e->config['checkpoint_lock'],'rb');flock($lock,LOCK_EX);
    try{$before=microtime(true);recoveryRefused(static function()use($s):void{Receiver\receiverRecover($s);});Check::same(true,microtime(true)-$before<3);}
    finally{flock($lock,LOCK_UN);fclose($lock);}
    Check::same(0,Receiver\receiverInspect($s)['entries']);
});

echo 'PASS native Outbox receiver recovery: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; real backups, independent witness, four live SIGKILL stages, epoch/file fencing and bounded corrupt state\n";
