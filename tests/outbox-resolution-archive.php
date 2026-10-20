<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-resolution-support.php';
use SoSecurity\Examples\Outbox as Resolution;

if(!function_exists('sodium_crypto_sign_detached')){if(getenv('SOSECURITY_REQUIRE_CRYPTO')==='1'){throw new RuntimeException('Required ext-sodium is missing.');}echo "NOT RUN native audit archive: ext-sodium required\n";return;}
function auditArchiveEnable(NativeResolutionEnvironment $e):void
{
    $baseline=Resolution\resolutionAuditStatus($e->settings())['root_hash'];$e->configure(['resolution_archive'=>true]);Check::same(true,Resolution\resolutionArchiveInitialize($e->settings(),$baseline));Check::same(false,Resolution\resolutionArchiveInitialize($e->settings(),$baseline));
}
function auditArchiveResolved(NativeResolutionEnvironment $e,bool $purge=true):string
{
    $proof=$e->proof();Resolution\resolutionImport($e->settings(),$e->id,$proof);if($purge){Check::same(1,Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice')['purged']);}return $proof;
}
nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $old=$e->settings();$e->configure(['resolution_archive'=>null]);Check::throws(RuntimeException::class,static function()use($e):void{$e->settings();});nativeResolutionRefused(static function()use($old):void{Resolution\resolutionAuditStatus($old);});$e->configure(['resolution_archive'=>false]);Check::same(false,Resolution\resolutionAuditStatus($e->settings())['archive_enabled']);
});

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $proof=auditArchiveResolved($e,false);$old=$e->settings();$baseline=Resolution\resolutionAuditStatus($old)['root_hash'];$e->configure(['resolution_archive'=>true]);nativeResolutionRefused(static function()use($old,$e):void{Resolution\resolutionStatus($old,$e->id);});nativeResolutionRefused(static function()use($e):void{Resolution\resolutionRoot($e->settings());});
    nativeResolutionRefused(static function()use($e):void{Resolution\resolutionArchiveInitialize($e->settings(),str_repeat('0',64));});Check::same(true,Resolution\resolutionArchiveInitialize($e->settings(),$baseline));Check::same(false,Resolution\resolutionArchiveInitialize($e->settings(),$baseline));Check::same(0,Resolution\resolutionArchive($e->settings())['archived']);Check::same(false,Resolution\resolutionStatus($e->settings(),$e->id)['archived']);
    Check::same(1,Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice')['purged']);$raw=Resolution\resolutionRead($e->settings(),$e->id);$before=Resolution\resolutionQueueVerify($e->settings());$moved=Resolution\resolutionArchive($e->settings());Check::same(1,$moved['archived']);Check::same(true,$moved['complete']);Check::same(null,Resolution\resolutionRead($e->settings(),$e->id));Check::same($raw,Resolution\resolutionRead($e->settings(),$e->id,true));Check::same($before,Resolution\resolutionQueueVerify($e->settings()));
    $root=Resolution\resolutionRoot($e->settings());Check::same(0,$root['entries']);Check::same(1,$root['archive_entries']);Check::same(true,Resolution\resolutionStatus($e->settings(),$e->id)['archived']);Check::same(0,Resolution\resolutionArchive($e->settings())['archived']);
    $list=Resolution\resolutionAuditList($e->settings(),true);Check::same(1,count($list['records']));Check::same(hash('sha256',$proof),$list['records'][0]['evidence_digest']);Check::same([],Resolution\resolutionAuditList($e->settings())['records']);Check::same([],Resolution\resolutionAuditList($e->settings(),true,20,$list['next_cursor'])['records']);Check::same(false,array_key_exists('evidence',$list['records'][0]));
    $e->pdo()->exec('DELETE FROM outbox_example_orders');Check::same('cancelled',Resolution\resolutionImport($e->settings(),$e->id,$proof)['outcome']);$export=Resolution\resolutionAuditExport($e->settings(),$e->id);Check::same($proof,$export['audit']['evidence']);Check::same(true,$export['archived']);
    $e->configure(['resolution_archive'=>false]);nativeResolutionRefused(static function()use($e):void{Resolution\resolutionStatus($e->settings(),$e->id);});
});

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $e->request();auditArchiveEnable($e);$s=$e->settings();$template=Resolution\resolutionStored($s,$e->id);$root=Resolution\resolutionRoot($s);$s['pdo']->beginTransaction();try{for($i=0;$i<21;++$i){$row=$template;$id=SoSecurity\Outbox\Message::identifier('rekey-page-'.$i,SoSecurity\Outbox\State::idTime($e->id));$row['event_id']=$id;$row['delivery_id']=Resolution\resolutionDelivery($id);Resolution\resolutionWrite($s,Resolution\resolutionSeal($s,'record',$row),$id);}Resolution\resolutionSync($s,$root);$s['pdo']->commit();}catch(Throwable $error){$s['pdo']->rollBack();throw $error;}
    recoveryJson($e->config['seals'],['current'=>'new','keys'=>['old'=>base64_encode(str_repeat('t',32)),'new'=>base64_encode(str_repeat('n',32))]]);$first=Resolution\resolutionRekey($e->settings());Check::same(20,$first['examined']);Check::same(20,$first['rekeyed']);Check::same(false,$first['complete']);$second=Resolution\resolutionRekey($e->settings(),false,20,$first['next_cursor']);Check::same(2,$second['examined']);Check::same(2,$second['rekeyed']);Check::same(true,$second['complete']);Check::same(0,Resolution\resolutionRekey($e->settings())['rekeyed']);Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice');
    recoveryJson($e->config['seals'],['current'=>'new','keys'=>['new'=>base64_encode(str_repeat('n',32))]]);Check::same('prepared',Resolution\resolutionStatus($e->settings(),$e->id)['state']);Check::same(22,Resolution\resolutionAuditStatus($e->settings())['active_entries']);
});

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    auditArchiveEnable($e);Check::same(0,Resolution\resolutionArchive($e->settings())['archived']);$e->request();Check::same(0,Resolution\resolutionArchive($e->settings())['archived']);$before=Resolution\resolutionRead($e->settings());
    foreach([0,21] as $limit){nativeResolutionRefused(static function()use($e,$limit):void{Resolution\resolutionArchive($e->settings(),$limit);});}
    nativeResolutionRefused(static function()use($e):void{Resolution\resolutionArchive($e->settings(),20,"o1.0.\0");});Check::same($before,Resolution\resolutionRead($e->settings()));Check::same(0,(int)$e->pdo()->query('SELECT COUNT(*) FROM outbox_example_resolution_archives')->fetchColumn());
});

foreach(['before','after','statement'] as $phase){nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($phase):void{
    auditArchiveResolved($e);auditArchiveEnable($e);$s=$e->settings();$fault=new InboxTestConnection('sqlite:'.$e->config['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$fault->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$fault]]);$s['pdo']=$fault;$stop=static function():void{throw new RuntimeException('owned archive failure');};
    if($phase==='before'){$fault->beforeCommit=$stop;}elseif($phase==='after'){$fault->afterCommit=$stop;}else{$fault->afterStatement=static function(string $sql)use($stop):void{if(strpos($sql,'DELETE FROM main.outbox_example_resolutions')===0){$stop();}};}
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s):void{Resolution\resolutionArchive($s);});$fault->beforeCommit=null;$fault->afterCommit=null;$fault->afterStatement=null;$s=null;$fault=null;
    Check::same($phase==='after'?0:1,(int)$e->pdo()->query('SELECT COUNT(*) FROM outbox_example_resolutions')->fetchColumn());Check::same($phase==='after'?1:0,(int)$e->pdo()->query('SELECT COUNT(*) FROM outbox_example_resolution_archives')->fetchColumn());Check::same('cancelled',Resolution\resolutionStatus($e->settings(),$e->id)['outcome']);Check::same($phase==='after'?0:1,Resolution\resolutionArchive($e->settings())['archived']);
});}

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    auditArchiveResolved($e);auditArchiveEnable($e);$s=$e->settings();$before=Resolution\resolutionRead($s);$fault=new InboxTestConnection('sqlite:'.$e->config['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$fault->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$fault]]);$s['pdo']=$fault;
    $fault->afterStatement=static function(string $sql)use($fault):void{if(strpos($sql,'DELETE FROM main.outbox_example_resolutions')===0){$fault->exec("UPDATE outbox_example_actors SET roles='[\"outbox_admin\"]'");}};
    nativeResolutionRefused(static function()use($s):void{Resolution\resolutionArchive($s);});$fault->afterStatement=null;$s=null;$fault=null;Check::same($before,Resolution\resolutionRead($e->settings()));Check::same(1,Resolution\resolutionAuditStatus($e->settings())['active_entries']);Check::same(0,Resolution\resolutionAuditStatus($e->settings())['archived_entries']);
});

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $proof=auditArchiveResolved($e);auditArchiveEnable($e);Resolution\resolutionArchive($e->settings());$old=Resolution\resolutionRead($e->settings(),$e->id,true);
    recoveryJson($e->config['seals'],['current'=>'new','keys'=>['old'=>base64_encode(str_repeat('t',32)),'new'=>base64_encode(str_repeat('n',32))]]);Check::same(1,Resolution\resolutionRekey($e->settings(),true)['rekeyed']);Check::same('new',Resolution\resolutionRead($e->settings(),$e->id,true)['seal_key']);Check::same($old['payload'],Resolution\resolutionRead($e->settings(),$e->id,true)['payload']);Resolution\resolutionRekey($e->settings());Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice');
    recoveryJson($e->config['seals'],['current'=>'new','keys'=>['new'=>base64_encode(str_repeat('n',32))]]);Check::same('cancelled',Resolution\resolutionStatus($e->settings(),$e->id)['outcome']);Check::same($proof,Resolution\resolutionAuditExport($e->settings(),$e->id)['audit']['evidence']);
});

foreach(['DELETE FROM outbox_example_resolution_archives',"UPDATE outbox_example_resolution_archives SET payload=CAST('x'||x'00'||zeroblob(16777216) AS TEXT)","UPDATE outbox_example_resolution_archives SET seal_key=CAST('x'||x'00'||zeroblob(16777216) AS TEXT)","UPDATE outbox_example_resolution_archives SET payload=CAST(REPLACE(CAST(payload AS TEXT),'cancelled','received') AS BLOB)"] as $change){nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($change):void{
    auditArchiveResolved($e);auditArchiveEnable($e);Resolution\resolutionArchive($e->settings());$e->pdo()->exec($change);nativeResolutionRefused(static function()use($e):void{Resolution\resolutionStatus($e->settings(),$e->id);});nativeResolutionRefused(static function()use($e):void{Resolution\resolutionRekey($e->settings(),true);});Check::same(true,memory_get_peak_usage(true)<8388608);
});}

foreach(['before-commit','after-commit'] as $phase){nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($phase):void{
    $proof=auditArchiveResolved($e);auditArchiveEnable($e);nativeResolutionKill($e,$proof,$phase,true);$committed=$phase==='after-commit';Check::same($committed?0:1,(int)$e->pdo()->query('SELECT COUNT(*) FROM outbox_example_resolutions')->fetchColumn());Check::same($committed?1:0,(int)$e->pdo()->query('SELECT COUNT(*) FROM outbox_example_resolution_archives')->fetchColumn());Check::same($committed,Resolution\resolutionStatus($e->settings(),$e->id)['archived']);Check::same($committed?0:1,Resolution\resolutionArchive($e->settings())['archived']);
});}

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    auditArchiveResolved($e);$raw=Resolution\resolutionRead($e->settings(),$e->id);$before=Resolution\resolutionRead($e->settings());$baseline=Resolution\resolutionRootHash($before);Resolution\resolutionWrite($e->settings(),$raw,$e->id,true);$e->configure(['resolution_archive'=>true]);nativeResolutionRefused(static function()use($e,$baseline):void{Resolution\resolutionArchiveInitialize($e->settings(),$baseline);});Check::same($before,Resolution\resolutionRead($e->settings()));
});

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $proof=auditArchiveResolved($e);auditArchiveEnable($e);$root=Resolution\resolutionRoot($e->settings());$template=Resolution\resolutionStored($e->settings(),$e->id);$template['state']='prepared';foreach(['outcome','evidence','verification_key','resolved_by'] as $field){$template[$field]='';}$template['verified_at']=0;$template['updated_at']=$template['created_at'];$created=SoSecurity\Outbox\State::idTime($e->id)+1;
    // Synthetic sealed pending metadata fills the active budget; the moved/next intents are real native flows.
    $s=$e->settings();$pdo=$s['pdo'];$pdo->beginTransaction();try{for($i=0;$i<999;++$i){$id=SoSecurity\Outbox\Message::identifier('capacity-'.$i,$created);$row=$template;$row['event_id']=$id;$row['delivery_id']=Resolution\resolutionDelivery($id);Resolution\resolutionWrite($s,Resolution\resolutionSeal($s,'record',$row),$id);}Resolution\resolutionSync($s,$root);$pdo->commit();}catch(Throwable $error){$pdo->rollBack();throw $error;}
    $s=$e->settings();Resolution\idempotency($s)->initialize(Resolution\SCOPE,'alice','orders.create');$new=Resolution\produce($s,'archive-capacity-next-001','next',202);sleep(2);Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice');$id=$new['result']['event_id'];
    nativeResolutionRefused(static function()use($e,$id):void{Resolution\resolutionExport($e->settings(),$id);});Check::same(1000,Resolution\resolutionRoot($e->settings())['entries']);Check::same(1,Resolution\resolutionArchive($e->settings())['archived']);Check::same(999,Resolution\resolutionRoot($e->settings())['entries']);$request=Resolution\resolutionExport($e->settings(),$id);Check::same($id,Resolution\resolutionRequestValue($request)['event']['event_id']);Check::same(1000,Resolution\resolutionRoot($e->settings())['entries']);Check::same('cancelled',Resolution\resolutionImport($e->settings(),$e->id,$proof)['outcome']);Check::same(true,memory_get_peak_usage(true)<8388608);
});

nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    auditArchiveResolved($e);$baseline=Resolution\resolutionAuditStatus($e->settings())['root_hash'];$e->configure(['resolution_archive'=>true]);$r=nativeResolutionCli($e->file,'outbox-admin',['--initialize-resolution-archive='.$baseline]);Check::same(0,$r['code']);Check::same(true,json_decode($r['output'],true)['initialized']);Check::same('',$r['error']);$r=nativeResolutionCli($e->file,'outbox-admin',['--archive-resolution']);Check::same(0,$r['code']);Check::same(1,json_decode($r['output'],true)['archived']);Check::same('',$r['error']);$r=nativeResolutionCli($e->file,'outbox-admin',['--export-resolution-audit='.$e->id]);Check::same(0,$r['code']);Check::same(true,json_decode($r['output'],true)['archived']);Check::same('cancelled',json_decode($r['output'],true)['audit']['outcome']);$r=nativeResolutionCli($e->file,'outbox-admin',['--resolution-audit-status']);Check::same(0,$r['code']);$stats=json_decode($r['output'],true);Check::same(0,$stats['active_entries']);Check::same(1,$stats['archived_entries']);Check::same(100000,$stats['archive_capacity']);
    $r=nativeResolutionCli($e->file,'outbox-admin',['--resolution-audit-list=archived']);Check::same(0,$r['code']);Check::same($e->id,json_decode($r['output'],true)['records'][0]['event_id']);Check::same('',$r['error']);
});
nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $e->pdo()->exec('DELETE FROM outbox_example_resolution_root');$e->configure(['resolution_archive'=>true]);Check::same(true,Resolution\resolutionInitialize($e->settings()));Check::same(2,Resolution\resolutionRoot($e->settings())['format']);Check::same(false,Resolution\resolutionInitialize($e->settings()));
});
nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    auditArchiveResolved($e);$raw=Resolution\resolutionRead($e->settings(),$e->id);Resolution\resolutionWrite($e->settings(),$raw,$e->id,true);$e->pdo()->exec('DELETE FROM outbox_example_resolutions');$e->pdo()->exec('DELETE FROM outbox_example_resolution_root');$e->configure(['resolution_archive'=>true]);nativeResolutionRefused(static function()use($e):void{Resolution\resolutionInitialize($e->settings());});Check::same(null,Resolution\resolutionRead($e->settings()));
});
echo 'PASS native Outbox audit archive: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; same-PDO archive, retained proof, capacity release, rekey, rollback and bounded reads\n";
