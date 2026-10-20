<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-recovery-support.php';
require __DIR__.'/outbox-resolution-support.php';
use SoSecurity\Examples\Outbox as Adapter;
use SoSecurity\Exception\SecurityException;

function authorityTestDatabase(string $directory,string $actor='receiver'):array
{
    $path=$directory.'/authority-'.$actor.'.sqlite';$pdo=new PDO('sqlite:'.$path,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($path,0600);$pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/outbox-example-authority-sqlite.sql'));
    $roles=$actor==='receiver'?['receiver_worker','receiver_admin','receiver_reconciler']:['orders_writer','outbox_worker','outbox_admin','outbox_reconciler'];$q=$pdo->prepare('INSERT INTO outbox_example_actors VALUES(:actor,\'1\',1,:roles)');$q->execute(['actor'=>$actor,'roles'=>json_encode($roles)]);$q->closeCursor();
    $pdo->exec("INSERT INTO outbox_example_routes VALUES('outbox-publisher','outbox-example',1)");$pdo->exec("INSERT INTO outbox_example_owners VALUES('alice',1)");return [$path,$pdo];
}
function authorityTestCase(callable $work):void
{
    recoveryCase(static function(ReceiverRecoveryEnvironment $e)use($work):void{list($path,$authority)=authorityTestDatabase($e->directory);$e->configure(['authority_database'=>$path]);$work($e,$authority);});
}

if(!class_exists('SQLite3',false)){
    recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{list($path,$authority)=authorityTestDatabase($e->directory);$e->configure(['authority_database'=>$path]);Check::throws(SecurityException::class,static function()use($e):void{$e->settings();});unset($e->config['authority_database']);$e->configure([]);Check::same(true,$e->receive()['committed']);});
    if(getenv('SOSECURITY_REQUIRE_AUTHORITY')==='1'){throw new RuntimeException('Required ext-sqlite3 is missing.');}
    echo 'NOT RUN independent authority lifecycle: ext-sqlite3 required; '.Check::$assertions." capability/legacy assertions passed\n";return;
}

// All current authority comes from the independent source, even when local permission rows disappear.
authorityTestCase(static function(ReceiverRecoveryEnvironment $e,PDO $authority):void{
    $pdo=$e->pdo();foreach(['actors','routes','owners'] as $table){$pdo->exec('DELETE FROM outbox_example_'.$table);}$pdo=null;
    $s=$e->settings();Check::same(true,Adapter\principal($s,'receiver_worker'));Check::same(true,$e->receive()['committed']);Check::same(true,$e->receive(2)['committed']);Check::same(2,$e->count());
    // This INSERT ... SELECT is syntactically valid with LIMIT 2. Actual OPEN_READONLY must reject it.
    Check::throws(SecurityException::class,static function()use($s):void{Adapter\authorityRow($s,'INSERT INTO main.outbox_example_owners SELECT :subject,1',['subject'=>'intruder']);});Check::same(1,(int)$authority->query('SELECT COUNT(*) FROM outbox_example_owners')->fetchColumn());
    $authority->exec('BEGIN EXCLUSIVE');$started=microtime(true);try{Check::throws(SecurityException::class,static function()use($s):void{Adapter\principal($s,'receiver_worker');});}finally{$authority->exec('ROLLBACK');}Check::same(true,microtime(true)-$started<2.5);Check::same(true,Adapter\principal($s,'receiver_worker'));
});

// Restoring business permissions cannot undo current source revocation, route removal or identity versions.
foreach(["UPDATE outbox_example_actors SET enabled=0","UPDATE outbox_example_actors SET version='2'","UPDATE outbox_example_actors SET roles='[]'","UPDATE outbox_example_owners SET enabled=0","DELETE FROM outbox_example_owners","UPDATE outbox_example_routes SET enabled=0","UPDATE outbox_example_routes SET tenant='other'"] as $change){authorityTestCase(static function(ReceiverRecoveryEnvironment $e,PDO $authority)use($change):void{
    $backup=$e->backup('enabled-business');$s=$e->settings();$root=Adapter\receiverRead($s['pdo'],'root');$witness=Adapter\receiverRead($s['checkpoint_pdo'],'checkpoint');$s=null;$authority->exec($change);$e->restore($backup);
    Check::throws(SecurityException::class,static function()use($e):void{$e->receive();});Check::same(0,$e->count());$s=$e->settings();Check::same($root,Adapter\receiverRead($s['pdo'],'root'));Check::same($witness,Adapter\receiverRead($s['checkpoint_pdo'],'checkpoint'));Check::same(1,(int)$e->pdo()->query('SELECT enabled FROM outbox_example_actors')->fetchColumn());
});}

// A known last transition may be replayed only after current source authority permits it again.
authorityTestCase(static function(ReceiverRecoveryEnvironment $e,PDO $authority):void{
    $backup=$e->backup('before-effect');$e->receive();$authority->exec('UPDATE outbox_example_owners SET enabled=0');$e->restore($backup);
    Check::throws(SecurityException::class,static function()use($e):void{Adapter\receiverRecover($e->settings());});Check::same(0,$e->count());
    $authority->exec('UPDATE outbox_example_owners SET enabled=1');Check::same(true,Adapter\receiverRecover($e->settings()));Check::same(false,Adapter\receiverRecover($e->settings()));Check::same(1,$e->count());
    $authority->exec("UPDATE outbox_example_actors SET roles='[\"receiver_worker\"]'");Check::throws(SecurityException::class,static function()use($e):void{Adapter\receiverInspect($e->settings());});
});

// Explicit historical closure retains its existing disabled-owner rule, but never a missing association.
authorityTestCase(static function(ReceiverRecoveryEnvironment $e,PDO $authority):void{
    $s=$e->settings();$authority->exec('UPDATE outbox_example_owners SET enabled=0');Check::same(true,Adapter\resolutionReceiverAuthority($s,'alice'));Check::same(false,Adapter\associated($s,Adapter\mapped($e->body(),$e->delivery($e->body()))));
    $authority->exec('DELETE FROM outbox_example_owners');Check::same(false,Adapter\resolutionReceiverAuthority($s,'alice'));$authority->exec("INSERT INTO outbox_example_owners VALUES('alice',1)");$authority->exec("UPDATE outbox_example_actors SET roles='[\"receiver_admin\"]'");Check::same(false,Adapter\resolutionReceiverAuthority($s,'alice'));
});

// Source changes are visible while the business transaction still retains its own old snapshot.
authorityTestCase(static function(ReceiverRecoveryEnvironment $e,PDO $authority):void{
    $s=$e->settings();$s['pdo']->exec('BEGIN');$s['pdo']->query('SELECT * FROM outbox_example_actors')->fetchAll();try{Check::same(true,Adapter\principal($s,'receiver_worker'));$authority->exec('UPDATE outbox_example_actors SET enabled=0');Check::same(false,Adapter\principal($s,'receiver_worker'));}finally{$s['pdo']->exec('ROLLBACK');}
});

authorityTestCase(static function(ReceiverRecoveryEnvironment $e,PDO $authority):void{
    $s=$e->settings();$authority->exec("UPDATE outbox_example_actors SET roles=CAST('x'||x'00'||zeroblob(16777216) AS TEXT)");Check::same(false,Adapter\principal($s,'receiver_worker'));Check::same(true,memory_get_peak_usage(true)<8388608);
    $authority->exec("UPDATE outbox_example_actors SET roles='[\"receiver_worker\"]'");$authority->exec('ALTER TABLE outbox_example_actors RENAME TO old_actors');$authority->exec('CREATE TABLE outbox_example_actors AS SELECT * FROM old_actors');$authority->exec('INSERT INTO outbox_example_actors SELECT * FROM old_actors');Check::throws(SecurityException::class,static function()use($s):void{Adapter\principal($s,'receiver_worker');});
});

// No cached adoption or local-table fallback after deployment changes, source loss, or file replacement.
authorityTestCase(static function(ReceiverRecoveryEnvironment $e,PDO $authority):void{
    $s=$e->settings();unset($e->config['authority_database']);$e->configure([]);Check::throws(SecurityException::class,static function()use($s):void{Adapter\principal($s,'receiver_worker');});
    $e->configure(['authority_database'=>$s['authority_database']]);$authority=null;$copy=$e->directory.'/replacement.sqlite';Check::same(true,copy($s['authority_database'],$copy));chmod($copy,0600);Check::same(true,rename($copy,$s['authority_database']));Check::throws(SecurityException::class,static function()use($s):void{Adapter\principal($s,'receiver_worker');});Check::same(true,Adapter\principal($e->settings(),'receiver_worker'));
    $s=$e->settings();unlink($s['authority_database']);Check::throws(SecurityException::class,static function()use($s):void{Adapter\principal($s,'receiver_worker');});Check::same(false,is_file($s['authority_database']));
});

recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
    $legacy=$e->settings();list($path,$authority)=authorityTestDatabase($e->directory);$e->configure(['authority_database'=>$path]);Check::throws(SecurityException::class,static function()use($legacy):void{Adapter\principal($legacy,'receiver_worker');});
    foreach([null,false,$e->config['database'],$e->config['checkpoint_database'],$e->config['checkpoint_lock'],$e->directory.'/missing.sqlite'] as $bad){$e->configure(['authority_database'=>$bad]);Check::throws(Throwable::class,static function()use($e):void{$e->settings();});}
    $alias=$e->directory.'/business-hardlink.sqlite';Check::same(true,link($e->config['database'],$alias));$e->configure(['authority_database'=>$alias]);Check::throws(SecurityException::class,static function()use($e):void{$e->settings();});
    $alias=$e->directory.'/authority-symlink.sqlite';Check::same(true,symlink($path,$alias));$e->configure(['authority_database'=>$alias]);Check::throws(Throwable::class,static function()use($e):void{$e->settings();});
});


// Composite roles and object associations must all belong to the same committed authority state.
function authorityTestRace(array $settings,PDO $authority,string $mode,callable $decision):void
{
    Check::same('wal',strtolower($authority->query('PRAGMA journal_mode=WAL')->fetchColumn()));$authority->exec('CREATE TABLE authority_test_progress(revision INTEGER NOT NULL)');$authority->exec('INSERT INTO authority_test_progress VALUES(0)');
    $command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/outbox-authority-worker.php').' '.escapeshellarg($settings['authority_database']).' '.escapeshellarg($mode).' '.escapeshellarg($settings['actor']);
    $process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot start owned authority writer.');}stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);$output='';$errors='';$exit=null;
    try{
        $deadline=microtime(true)+8;
        do{$output.=stream_get_contents($pipes[1]);$errors.=stream_get_contents($pipes[2]);$status=proc_get_status($process);if(strpos($output,"\n")!==false){break;}if(!$status['running']||strlen($output)>512||strlen($errors)>512){throw new RuntimeException('Authority writer failed before ready.');}usleep(10000);}while(microtime(true)<$deadline);
        $marker=json_decode(trim($output),true);Check::same($mode,$marker['mode'] ?? null);Check::same(true,$status['running']);Check::same($status['pid'],$marker['pid'] ?? null);$before=(int)$authority->query('SELECT revision FROM authority_test_progress')->fetchColumn();$accepted=0;
        for($i=0;$i<1000;++$i){if($decision()) {++$accepted;}}
        Check::same(0,$accepted);Check::same(true,(int)$authority->query('SELECT revision FROM authority_test_progress')->fetchColumn()>$before);
    }finally{
        @fwrite($pipes[0],"stop\n");fclose($pipes[0]);$deadline=microtime(true)+4;
        do{$status=proc_get_status($process);if(!$status['running']){$exit=$status['exitcode'];break;}usleep(10000);}while(microtime(true)<$deadline);
        if($status['running']){proc_terminate($process,9);}$errors.=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$closed=proc_close($process);if($exit===null){$exit=$closed;}
    }
    Check::same(0,$exit);Check::same('',$errors);
    $roles=$mode==='sender'?['outbox_admin','outbox_reconciler']:['receiver_worker','receiver_admin','receiver_reconciler'];$authority->prepare('UPDATE outbox_example_actors SET roles=?')->execute([json_encode($roles)]);$authority->exec('UPDATE outbox_example_routes SET enabled=1');Check::same(true,$decision());
}
foreach(['receiver','association'] as $mode){authorityTestCase(static function(ReceiverRecoveryEnvironment $e,PDO $authority)use($mode):void{$s=$e->settings();$message=Adapter\mapped($e->body(),$e->delivery($e->body()));authorityTestRace($s,$authority,$mode,static function()use($s,$message,$mode):bool{return $mode==='receiver'?Adapter\resolutionReceiverAuthority($s,'alice'):Adapter\associated($s,$message);});});}
if(function_exists('sodium_crypto_sign_detached')){nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{list($path,$authority)=authorityTestDatabase($e->receiver->directory,'alice');$e->configure(['authority_database'=>$path]);$s=$e->settings();authorityTestRace($s,$authority,'sender',static function()use($s):bool{return Adapter\resolutionPrincipal($s);});});}

// Actual terminal proof, native management CLIs and sender audit all use the same current source.
if(function_exists('sodium_crypto_sign_detached')){nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    list($senderPath,$senderAuthority)=authorityTestDatabase($e->receiver->directory,'alice');list($receiverPath,$receiverAuthority)=authorityTestDatabase($e->receiver->directory);$e->configure(['authority_database'=>$senderPath]);$e->receiver->configure(['authority_database'=>$receiverPath]);
    $e->pdo()->exec('DELETE FROM outbox_example_actors');foreach(['actors','routes','owners'] as $table){$e->receiver->pdo()->exec('DELETE FROM outbox_example_'.$table);}
    $proof=$e->proof();$senderAuthority->exec("UPDATE outbox_example_actors SET roles='[\"outbox_admin\"]'");Check::throws(SecurityException::class,static function()use($e,$proof):void{Adapter\resolutionImport($e->settings(),$e->id,$proof);});Check::same('dead',$e->pdo()->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());
    $senderAuthority->exec("UPDATE outbox_example_actors SET roles='[\"outbox_admin\",\"outbox_reconciler\"]'");Check::same('resolved',Adapter\resolutionImport($e->settings(),$e->id,$proof)['state']);Check::same('cancelled',Adapter\resolutionStatus($e->settings(),$e->id)['outcome']);
    $cli=nativeResolutionCli($e->file,'outbox-admin',['--resolution-status='.$e->id]);Check::same(0,$cli['code']);Check::same('',$cli['error']);Check::same('cancelled',json_decode($cli['output'],true)['outcome']);
    $senderAuthority->exec('UPDATE outbox_example_actors SET enabled=0');$cli=nativeResolutionCli($e->file,'outbox-admin',['--resolution-status='.$e->id]);Check::same(1,$cli['code']);Check::same('',$cli['output']);
    $cli=nativeResolutionCli($e->receiver->file,'outbox-receiver-admin',['--status']);Check::same(0,$cli['code']);$receiverAuthority->exec('UPDATE outbox_example_actors SET enabled=0');$cli=nativeResolutionCli($e->receiver->file,'outbox-receiver-admin',['--status']);Check::same(1,$cli['code']);Check::same('',$cli['output']);
});}else{if(getenv('SOSECURITY_REQUIRE_CRYPTO')==='1'){throw new RuntimeException('Required ext-sodium is missing.');}echo "NOT RUN independent-authority signed terminal integration: ext-sodium required\n";}
echo 'PASS native Outbox independent authority: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; current permissions after actual business restore, read-only source, fresh decisions, known recovery, CLI and bounded fields\n";
