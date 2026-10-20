<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Outbox;

use PDO;
use SoSecurity\Outbox\Policy;
use SoSecurity\Outbox\Schema;
use SoSecurity\Outbox\State;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

// Inert same-database audit tier. No evidence is deleted and no external files are created.
function resolutionAuditSchema(PDO $pdo):void
{
    // Keep introspection in main and reject a stored object that shadows the built-in pragma function.
    $q=$pdo->query("SELECT 1 FROM main.sqlite_master WHERE name COLLATE NOCASE='pragma_foreign_key_list' LIMIT 1");$shadow=$q->fetchColumn()!==false;$q->closeCursor();if($shadow){resolutionDenied();}
    $protected="('outbox_example_resolution_root','outbox_example_resolutions','outbox_example_resolution_archives')";
    $q=$pdo->query("SELECT 1 FROM main.sqlite_master m JOIN main.pragma_foreign_key_list(m.name,'main') f WHERE m.type='table' AND (m.name COLLATE NOCASE IN ".$protected.' OR f."table" COLLATE NOCASE IN '.$protected.') LIMIT 1');$related=$q->fetchColumn()!==false;$q->closeCursor();if($related){resolutionDenied();}
}
function resolutionArchiveReady(array $settings):void
{
    resolutionSenderCurrent($settings);if(($settings['resolution_archive'] ?? false)!==true){resolutionDenied();}
}
/** Authenticate the queue membership while the enclosing native transaction holds SQLite's writer lock. */
function resolutionQueueVerify(array $settings,?SqlTransaction $unit=null):array
{
    resolutionSenderCurrent($settings);
    if($unit===null){$owned=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);return $owned->run(static function()use($settings,$owned):array{return resolutionQueueVerify($settings,$owned);});}if($unit->connection()!==$settings['pdo']){resolutionDenied();}Schema::verify($unit);
    $policy=new Policy($settings['policy']);$namespace=State::namespace(SITE,SCOPE,PRODUCER);$keys=sealingKeys($settings['seals']);
    $q=$settings['pdo']->prepare('SELECT '.SqlSchema::boundedProjection('sqlite',Schema::rootTypes()).' FROM main.sosecurity_outbox_roots WHERE namespace=:namespace');$q->execute(['namespace'=>$namespace]);$raw=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();if(!is_array($raw)){resolutionDenied();}$root=State::root($raw,$keys,$policy,$namespace,$settings['epoch'],time());
    $types=Schema::recordTypes();unset($types['payload_body']);$hash=hash_init('sha256');hash_update($hash,State::historyPrefix($namespace));$cursor=null;$count=0;$maximum=0;$resolved=false;
    do{
        $q=$settings['pdo']->prepare('SELECT '.SqlSchema::boundedProjection('sqlite',$types).','.SqlSchema::blobLength('sqlite','payload_body').' AS body_length FROM main.sosecurity_outbox_records WHERE namespace=:namespace'.($cursor===null?'':' AND key_hash>:after').' ORDER BY sosecurity_outbox_records.key_hash LIMIT 64');$q->execute($cursor===null?['namespace'=>$namespace]:['namespace'=>$namespace,'after'=>$cursor]);$rows=$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();
        foreach($rows as $row){$row=State::record($row,$keys,$policy,$namespace,$settings['epoch'],SCOPE,PRODUCER,time());if(++$count>$policy->maximumEntries()){resolutionDenied();}hash_update($hash,json_encode([$row['key_hash'],$row['order_no'],$row['seal']]));$maximum=max($maximum,$row['order_no']);$resolved=$resolved||$row['format']===2;$cursor=$row['key_hash'];}
    }while(count($rows)===64);
    if($root['entries']!==$count||$root['last_order']<$maximum||($root['format']===1&&$resolved)||!hash_equals($root['history_digest'],hash_final($hash))){resolutionDenied();}return $root;
}
function resolutionRootHash(array $row):string {return hash('sha256','SoSecurity.OutboxExample.AuditBaseline.1.'.SITE.'.'.SCOPE.'.'.PRODUCER.'.'.$row['payload']."\0".$row['seal_key']."\0".$row['seal']);}
function resolutionArchiveInitialize(array $settings,string $expectedRootHash):bool
{
    resolutionArchiveReady($settings);if(!preg_match('/\A[a-f0-9]{64}\z/D',$expectedRootHash)){resolutionDenied();}$unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    return $unit->run(static function()use($settings,$expectedRootHash):bool{
        resolutionArchiveReady($settings);$root=resolutionRoot($settings,false,true);if($root['format']===2){return false;}$raw=resolutionRead($settings);if($raw===null||!hash_equals($expectedRootHash,resolutionRootHash($raw))){resolutionDenied();}$archive=resolutionHistory($settings,true);if($archive['entries']!==0){resolutionDenied();}
        $root['format']=2;$root['archive_entries']=0;$root['archive_digest']=$archive['history_digest'];resolutionSync($settings,$root);return true;
    },null,static function()use($settings):void{resolutionArchiveReady($settings);resolutionRoot($settings);});
}
function resolutionArchiveIds(array $settings,bool $archived,int $limit,string $after):array
{
    if($limit<1||$limit>20){resolutionDenied();}if($after!==''){resolutionEventId($after);}
    $table=$archived?'outbox_example_resolution_archives':'outbox_example_resolutions';$q=$settings['pdo']->prepare("SELECT CASE WHEN typeof(event_id)='text' AND length(CAST(event_id AS BLOB))<=96 THEN event_id ELSE NULL END AS event_id FROM main.".$table.($after===''?'':' WHERE event_id>:after').' ORDER BY '.$table.'.event_id LIMIT '.$limit);$q->execute($after===''?[]:['after'=>$after]);$rows=$q->fetchAll(PDO::FETCH_COLUMN);$q->closeCursor();
    foreach($rows as $id){if(!is_string($id)){resolutionDenied();}resolutionEventId($id);}return $rows;
}
function resolutionArchive(array $settings,int $limit=20,string $after=''):array
{
    resolutionArchiveReady($settings);if($limit<1||$limit>20){resolutionDenied();}if($after!==''){resolutionEventId($after);}
    $unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    $state=$unit->run(static function()use($settings,$limit,$after,$unit):array{
        resolutionArchiveReady($settings);$root=resolutionRoot($settings);$queue=resolutionQueueVerify($settings,$unit);$ids=resolutionArchiveIds($settings,false,$limit,$after);$cursor=$after;$moved=0;
        foreach($ids as $id){
            $cursor=$id;$row=resolutionStored($settings,$id,true);if($row===null){resolutionDenied();}
            if($row['state']!=='resolved'||$row['verified_at']+$settings['policy']['retention_seconds']>time()||resolutionQueueRecord($settings,$id)!==null){continue;}
            if($root['archive_entries']+$moved>=100000||resolutionRead($settings,$id,true)!==null){resolutionDenied();}$raw=resolutionRead($settings,$id);if($raw===null){resolutionDenied();}
            resolutionWrite($settings,$raw,$id,true);$q=$settings['pdo']->prepare('DELETE FROM main.outbox_example_resolutions WHERE event_id=:id AND seal_key=:key AND seal=:seal');$q->execute(['id'=>$id,'key'=>$raw['seal_key'],'seal'=>$raw['seal']]);if($q->rowCount()!==1){resolutionDenied();}$q->closeCursor();if(resolutionRead($settings,$id)!==null||resolutionRead($settings,$id,true)!==$raw){resolutionDenied();}++$moved;
        }
        $final=resolutionSync($settings,$root);if($final['entries']!==$root['entries']-$moved||$final['archive_entries']!==$root['archive_entries']+$moved){resolutionDenied();}return ['queue'=>$queue,'result'=>['examined'=>count($ids),'archived'=>$moved,'next_cursor'=>$cursor,'complete'=>count($ids)<$limit]];
    },null,static function(array $state)use($settings,$unit):void{resolutionArchiveReady($settings);resolutionRoot($settings);if(resolutionQueueVerify($settings,$unit)!==$state['queue']){resolutionDenied();}});
    return $state['result'];
}
function resolutionRekey(array $settings,bool $archived=false,int $limit=20,string $after=''):array
{
    resolutionSenderCurrent($settings);if($archived){resolutionArchiveReady($settings);}if($limit<1||$limit>20){resolutionDenied();}if($after!==''){resolutionEventId($after);}
    $unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    return $unit->run(static function()use($settings,$archived,$limit,$after):array{
        resolutionSenderCurrent($settings);$root=resolutionRoot($settings);$ids=resolutionArchiveIds($settings,$archived,$limit,$after);$cursor=$after;$changed=0;$key=sealingKeys($settings['seals'])->currentId();
        foreach($ids as $id){$cursor=$id;$row=resolutionStored($settings,$id,true);$raw=resolutionRead($settings,$id,$archived);if($row===null||$raw===null){resolutionDenied();}if($raw['seal_key']!==$key){resolutionWrite($settings,resolutionSeal($settings,'record',$row),$id,$archived);++$changed;}}
        $final=resolutionSync($settings,$root);if($final['entries']!==$root['entries']||($final['archive_entries'] ?? 0)!==($root['archive_entries'] ?? 0)){resolutionDenied();}return ['examined'=>count($ids),'rekeyed'=>$changed,'next_cursor'=>$cursor,'complete'=>count($ids)<$limit];
    },null,static function()use($settings):void{resolutionSenderCurrent($settings);resolutionRoot($settings);});
}
function resolutionAuditExport(array $settings,string $id):array
{
    resolutionEventId($id);resolutionSenderCurrent($settings);$unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    return $unit->run(static function()use($settings,$id):array{
        resolutionSenderCurrent($settings);$row=resolutionStored($settings,$id);if($row===null||$row['state']!=='resolved'){resolutionDenied();}
        $archived=($settings['resolution_archive'] ?? false)===true&&resolutionRead($settings,$id,true)!==null;return ['format'=>1,'site'=>SITE,'scope'=>SCOPE,'producer'=>PRODUCER,'archived'=>$archived,'audit'=>$row];
    },null,static function()use($settings):void{resolutionSenderCurrent($settings);resolutionRoot($settings);});
}
function resolutionAuditStatus(array $settings):array
{
    resolutionSenderCurrent($settings);$unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    return $unit->run(static function()use($settings):array{resolutionSenderCurrent($settings);$root=resolutionRoot($settings);$raw=resolutionRead($settings);if($raw===null){resolutionDenied();}return ['format'=>$root['format'],'active_entries'=>$root['entries'],'active_capacity'=>1000,'archive_enabled'=>$root['format']===2,'archived_entries'=>$root['archive_entries'] ?? 0,'archive_capacity'=>$root['format']===2?100000:0,'revision'=>$root['revision'],'root_hash'=>resolutionRootHash($raw)];},null,static function()use($settings):void{resolutionSenderCurrent($settings);resolutionRoot($settings);});
}
function resolutionAuditList(array $settings,bool $archived=false,int $limit=20,string $after=''):array
{
    resolutionSenderCurrent($settings);if($archived){resolutionArchiveReady($settings);}if($limit<1||$limit>20){resolutionDenied();}if($after!==''){resolutionEventId($after);}$unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    return $unit->run(static function()use($settings,$archived,$limit,$after):array{
        resolutionSenderCurrent($settings);resolutionRoot($settings);$ids=resolutionArchiveIds($settings,$archived,$limit,$after);$cursor=$after;$records=[];
        foreach($ids as $id){$cursor=$id;$row=resolutionStored($settings,$id,true);if($row===null){resolutionDenied();}$records[]=['event_id'=>$id,'state'=>$row['state'],'outcome'=>$row['outcome'],'requested_by'=>$row['requested_by'],'resolved_by'=>$row['resolved_by'],'verified_at'=>$row['verified_at'],'evidence_digest'=>$row['state']==='resolved'?hash('sha256',$row['evidence']):null];}
        return ['archived'=>$archived,'records'=>$records,'next_cursor'=>$cursor,'complete'=>count($ids)<$limit];
    },null,static function()use($settings):void{resolutionSenderCurrent($settings);resolutionRoot($settings);});
}
