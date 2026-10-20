<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-resolution-support.php';
use SoSecurity\Examples\Outbox as Resolution;

if(!function_exists('sodium_crypto_sign_detached')){
    recoveryCase(static function(ReceiverRecoveryEnvironment $e):void{
        $e->pdo()->exec("UPDATE outbox_example_actors SET roles='[\"receiver_worker\",\"receiver_admin\",\"receiver_reconciler\"]'");recoveryJson($e->directory.'/seeds.json',['current'=>'old','keys'=>['old'=>base64_encode(str_repeat('q',32))]]);$e->configure(['resolution_keys'=>$e->directory.'/seeds.json']);$before=Resolution\receiverInspect($e->settings());
        nativeResolutionRefused(static function()use($e):void{Resolution\resolutionPublicKeys($e->settings());});Check::same($before,Resolution\receiverInspect($e->settings()));Check::same(0,$e->count());
    });
    if(getenv('SOSECURITY_REQUIRE_CRYPTO')==='1'){throw new RuntimeException('Required ext-sodium is missing.');}
    echo 'NOT RUN signed native Outbox lifecycle: ext-sodium required; '.Check::$assertions.' explicit-denial assertions passed on PHP '.PHP_VERSION."\n";return;
}

foreach([false,true] as $cancel){nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($cancel):void{
    Check::same(false,Resolution\resolutionInitialize($e->settings()));$request=$e->request();Check::same($request,$e->request());
    if(!$cancel){nativeResolutionRefused(static function()use($e,$request):void{Resolution\resolutionTerminal($e->receiver->settings(),$request);});Check::same(true,$e->receive()['committed']);}
    $proof=Resolution\resolutionTerminal($e->receiver->settings(),$request,$cancel);$outcome=$cancel?'cancelled':'received';
    $result=Resolution\resolutionImport($e->settings(),$e->id,$proof);Check::same('resolved',$result['state']);Check::same($outcome,$result['outcome']);Check::same(hash('sha256',$proof),$result['evidence_digest']);Check::same($result,Resolution\resolutionImport($e->settings(),$e->id,$proof));
    Check::same($cancel?0:1,$e->receiver->count());Check::same($cancel?1:0,(int)$e->receiver->pdo()->query('SELECT COUNT(*) FROM outbox_example_cancellations')->fetchColumn());
    if($cancel){nativeResolutionRefused(static function()use($e):void{$e->receive();});Check::same(0,(int)$e->receiver->pdo()->query('SELECT COUNT(*) FROM sosecurity_webhook_inbox')->fetchColumn());}
    else{nativeResolutionRefused(static function()use($e,$request):void{Resolution\resolutionTerminal($e->receiver->settings(),$request,true);});Check::same(true,$e->receive()['committed']);}
    Check::same(1,Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice')['purged']);$status=Resolution\resolutionStatus($e->settings(),$e->id);Check::same(false,$status['queue_present']);Check::same($outcome,$status['outcome']);Check::same(1,(int)$e->pdo()->query('SELECT COUNT(*) FROM outbox_example_resolutions')->fetchColumn());
    Check::same($status,Resolution\resolutionImport($e->settings(),$e->id,$proof));
});}

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $proof=$e->proof();$before=Resolution\resolutionRead($e->settings());
    foreach(['site'=>'another','scope'=>'other','producer'=>'other','event_id'=>SoSecurity\Outbox\Message::identifier('other',time()),'delivery_id'=>str_repeat('b',64),'fingerprint'=>str_repeat('b',64),'body_digest'=>str_repeat('b',64),'challenge'=>str_repeat('b',64),'receiver_epoch'=>str_repeat('b',64),'destination_hash'=>str_repeat('b',64),'outcome'=>'unknown','root_hash'=>'wrong','sequence'=>0,'issued_at'=>time()+30,'expires_at'=>time()-1] as $field=>$value){
        $bad=nativeResolutionAlter($e,$proof,[$field=>$value]);nativeResolutionRefused(static function()use($e,$bad):void{Resolution\resolutionImport($e->settings(),$e->id,$bad);});Check::same('prepared',Resolution\resolutionStored($e->settings(),$e->id)['state']);Check::same($before,Resolution\resolutionRead($e->settings()));
    }
    $envelope=json_decode($proof,true);$envelope['signature']=base64_encode(str_repeat('x',64));$bad=json_encode($envelope);nativeResolutionRefused(static function()use($e,$bad):void{Resolution\resolutionImport($e->settings(),$e->id,$bad);});
    Resolution\resolutionImport($e->settings(),$e->id,$proof);$other=nativeResolutionAlter($e,$proof,['root_hash'=>str_repeat('c',64)]);nativeResolutionRefused(static function()use($e,$other):void{Resolution\resolutionImport($e->settings(),$e->id,$other);});
});

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $proof=$e->proof();
    foreach([['issued_at'=>time()+30,'expires_at'=>time()+330],['issued_at'=>time()-301,'expires_at'=>time()-1]] as $times){$bad=nativeResolutionAlter($e,$proof,$times);nativeResolutionRefused(static function()use($e,$bad):void{Resolution\resolutionImport($e->settings(),$e->id,$bad);});}
    $old=file_get_contents($e->config['resolution_keys']);$pair=sodium_crypto_sign_seed_keypair(str_repeat('n',32));recoveryJson($e->config['resolution_keys'],['current'=>'new','keys'=>['new'=>base64_encode(sodium_crypto_sign_publickey($pair))]]);
    nativeResolutionRefused(static function()use($e,$proof):void{Resolution\resolutionImport($e->settings(),$e->id,$proof);});file_put_contents($e->config['resolution_keys'],$old);Resolution\resolutionImport($e->settings(),$e->id,$proof);
    recoveryJson($e->config['resolution_keys'],['current'=>'new','keys'=>['new'=>base64_encode(sodium_crypto_sign_publickey($pair))]]);
    Check::same('cancelled',Resolution\resolutionStatus($e->settings(),$e->id)['outcome']);Check::same('resolved',Resolution\resolutionImport($e->settings(),$e->id,$proof)['state']);Check::same(1,Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice')['purged']);
});

foreach(['statement','before-commit','after-commit'] as $stage){nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($stage):void{
    $proof=$e->proof();$s=$e->settings();$fault=new InboxTestConnection('sqlite:'.$e->config['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$fault->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$fault]]);$s['pdo']=$fault;
    $stop=static function():void{throw new RuntimeException('owned test SQL failure');};
    if($stage==='statement'){$fault->afterStatement=static function(string $sql)use($stop):void{if(strpos($sql,'UPDATE main.sosecurity_outbox_records SET')===0){$stop();}};}
    elseif($stage==='before-commit'){$fault->beforeCommit=$stop;}else{$fault->afterCommit=$stop;}
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s,$e,$proof):void{Resolution\resolutionImport($s,$e->id,$proof);});
    $fault->afterStatement=null;$fault->beforeCommit=null;$fault->afterCommit=null;$s=null;$fault=null;$committed=$stage==='after-commit';
    Check::same($committed?'resolved':'dead',$e->pdo()->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same($committed?'resolved':'prepared',Resolution\resolutionStored($e->settings(),$e->id)['state']);
    Check::same('resolved',Resolution\resolutionImport($e->settings(),$e->id,$proof)['state']);
});}

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $backup=$e->receiver->backup('before-cancel');$request=$e->request();$proof=Resolution\resolutionTerminal($e->receiver->settings(),$request,true);Check::same(2,Resolution\receiverRootValue($e->receiver->settings(),Resolution\receiverRead($e->receiver->pdo(),'root'))['format']);
    $e->receiver->restore($backup);recoveryRefused(static function()use($e):void{$e->receive();});Check::same(true,Resolution\receiverRecover($e->receiver->settings()));Check::same(0,$e->receiver->count());Check::same(1,(int)$e->receiver->pdo()->query('SELECT COUNT(*) FROM outbox_example_cancellations')->fetchColumn());nativeResolutionRefused(static function()use($e):void{$e->receive();});
    Check::same('cancelled',Resolution\resolutionImport($e->settings(),$e->id,$proof)['outcome']);
    $e->pdo()->exec('DELETE FROM outbox_example_resolutions');nativeResolutionRefused(static function()use($e):void{Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice');});Check::same('resolved',$e->pdo()->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());
    $e->pdo()->exec('DELETE FROM outbox_example_resolution_root');nativeResolutionRefused(static function()use($e):void{Resolution\resolutionInitialize($e->settings());});
});

foreach(['payload','seal_key','event_id'] as $field){nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($field):void{
    $e->request();$e->pdo()->exec('UPDATE outbox_example_resolutions SET '.$field."=CAST('x'||x'00'||zeroblob(16777216) AS TEXT)");nativeResolutionRefused(static function()use($e):void{$e->request();});Check::same('dead',$e->pdo()->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same(true,memory_get_peak_usage(true)<8388608);
});}

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $export=nativeResolutionCli($e->file,'outbox-admin',['--export-resolution='.$e->id]);Check::same(0,$export['code']);Check::same('',$export['error']);$request=rtrim($export['output'],"\r\n");Check::same($e->request(),$request);
    $file=$e->receiver->directory.'/request.json';file_put_contents($file,$request."\n");chmod($file,0600);
    $attest=nativeResolutionCli($e->receiver->file,'outbox-receiver-admin',['--attest='.$file]);Check::same(1,$attest['code']);Check::same('', $attest['output']);Check::same("outbox_receiver_admin.unavailable\n",$attest['error']);
    $result=nativeResolutionCli($e->receiver->file,'outbox-receiver-admin',['--cancel='.$file]);Check::same(0,$result['code']);Check::same('',$result['error']);$proof=rtrim($result['output'],"\r\n");$file=$e->receiver->directory.'/proof.json';file_put_contents($file,$proof."\n");chmod($file,0600);
    $result=nativeResolutionCli($e->file,'outbox-admin',['--import-resolution='.$e->id,$file]);Check::same(0,$result['code']);Check::same('resolved',json_decode($result['output'],true)['state']);Check::same('',$result['error']);
    $result=nativeResolutionCli($e->file,'outbox-admin',['--resolution-status='.$e->id]);Check::same(0,$result['code']);Check::same('cancelled',json_decode($result['output'],true)['outcome']);
    chmod($file,0644);$result=nativeResolutionCli($e->file,'outbox-admin',['--import-resolution='.$e->id,$file]);Check::same(1,$result['code']);Check::same("outbox_admin.unavailable\n",$result['error']);chmod($file,0600);
});

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $request=$e->request();$r=$e->receiver;$witness=Resolution\receiverRead($r->pdo(true),'checkpoint');
    foreach([['outbox_example_actors',"enabled=0",'enabled=1'],['outbox_example_actors',"version='2'","version='1'"],['outbox_example_actors',"roles='[\"receiver_admin\"]'","roles='[\"receiver_worker\",\"receiver_admin\",\"receiver_reconciler\"]'"],['outbox_example_routes',"tenant='other'","tenant='outbox-example'"]] as $change){
        $r->pdo()->exec('UPDATE '.$change[0].' SET '.$change[1]);nativeResolutionRefused(static function()use($r,$request):void{Resolution\resolutionTerminal($r->settings(),$request,true);});Check::same($witness,Resolution\receiverRead($r->pdo(true),'checkpoint'));Check::same(0,(int)$r->pdo()->query('SELECT COUNT(*) FROM outbox_example_cancellations')->fetchColumn());$r->pdo()->exec('UPDATE '.$change[0].' SET '.$change[2]);
    }
    $r->pdo()->exec("UPDATE outbox_example_actors SET roles='[\"receiver_admin\",\"receiver_reconciler\"]'");$r->pdo()->exec('UPDATE outbox_example_routes SET enabled=0');$r->pdo()->exec('UPDATE outbox_example_owners SET enabled=0');
    $proof=Resolution\resolutionTerminal($r->settings(),$request,true);Check::same(1,(int)$r->pdo()->query('SELECT COUNT(*) FROM outbox_example_cancellations')->fetchColumn());
    foreach(["enabled=0","version='2'","roles='[\"outbox_admin\"]'"] as $change){$e->pdo()->exec('UPDATE outbox_example_actors SET '.$change);nativeResolutionRefused(static function()use($e,$proof):void{Resolution\resolutionImport($e->settings(),$e->id,$proof);});Check::same('dead',$e->pdo()->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());$e->pdo()->exec("UPDATE outbox_example_actors SET enabled=1,version='1',roles='[\"orders_writer\",\"outbox_worker\",\"outbox_admin\",\"outbox_reconciler\"]'");}
    $e->pdo()->exec("INSERT INTO outbox_example_actors VALUES('admin','1',1,'[\"outbox_admin\",\"outbox_reconciler\"]')");$e->pdo()->exec("UPDATE outbox_example_actors SET enabled=0 WHERE subject='alice'");$e->configure(['actor'=>'admin']);Check::same('cancelled',Resolution\resolutionImport($e->settings(),$e->id,$proof)['outcome']);
    $e->pdo()->exec("UPDATE outbox_example_actors SET roles='[\"outbox_admin\"]' WHERE subject='admin'");nativeResolutionRefused(static function()use($e):void{Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'admin');});Check::same('resolved',$e->pdo()->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());
    $r->pdo()->exec('DELETE FROM outbox_example_cancellations');recoveryRefused(static function()use($r):void{Resolution\receiverRecover($r->settings());});
});

foreach(['prepared','business-uncommitted','business-committed','witness-committed'] as $phase){nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($phase):void{
    $request=$e->request();recoveryKill($e->receiver,$phase,true);Check::same(0,$e->receiver->count());Check::same(in_array($phase,['business-committed','witness-committed'],true)?1:0,(int)$e->receiver->pdo()->query('SELECT COUNT(*) FROM outbox_example_cancellations')->fetchColumn());
    Check::same($phase!=='witness-committed',Resolution\receiverRecover($e->receiver->settings()));nativeResolutionRefused(static function()use($e):void{$e->receive();});$proof=Resolution\resolutionTerminal($e->receiver->settings(),$request);Check::same('cancelled',Resolution\resolutionImport($e->settings(),$e->id,$proof)['outcome']);
});}
foreach(['before-commit','after-commit'] as $phase){nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($phase):void{
    $proof=$e->proof();nativeResolutionKill($e,$proof,$phase);$committed=$phase==='after-commit';Check::same($committed?'resolved':'dead',$e->pdo()->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same($committed?'resolved':'prepared',Resolution\resolutionStored($e->settings(),$e->id)['state']);Check::same('resolved',Resolution\resolutionImport($e->settings(),$e->id,$proof)['state']);
});}

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $receiver=$e->receiver->pdo();$sender=$e->pdo();$before=Resolution\receiverInspect($e->receiver->settings());$columns=$receiver->query('PRAGMA table_info(outbox_example_cancellations)')->fetchAll(PDO::FETCH_ASSOC);
    $receiver->exec('DROP TABLE outbox_example_cancellations');$sender->exec('DROP TABLE outbox_example_resolution_root');$sender->exec('DROP TABLE outbox_example_resolutions');
    foreach(['receiver'=>$receiver,'sender'=>$sender] as $role=>$pdo){$pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/outbox-example-resolution-'.$role.'-sqlite.sql'));}
    Check::same($columns,$receiver->query('PRAGMA table_info(outbox_example_cancellations)')->fetchAll(PDO::FETCH_ASSOC));Check::same($before,Resolution\receiverInspect($e->receiver->settings()));Check::same(1,(int)$sender->query('SELECT COUNT(*) FROM outbox_example_orders')->fetchColumn());Check::same(true,Resolution\resolutionInitialize($e->settings()));$proof=$e->proof();Check::same('cancelled',Resolution\resolutionImport($e->settings(),$e->id,$proof)['outcome']);
});

echo 'PASS native Outbox terminal reconciliation: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; real Ed25519 receipts, permanent cancellation, current authority, sealed audit, migrations, backups, six SIGKILL stages, CLI and atomic resolution\n";
