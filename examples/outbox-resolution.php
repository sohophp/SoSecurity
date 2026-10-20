<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Outbox;

use PDO;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Outbox\State;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;
require_once __DIR__.'/outbox-resolution-archive.php';

// Inert optional native profile. Signing is enabled only by explicit reconciliation operations.
/** @return never */
function resolutionDenied():void {throw new SecurityException('Current authenticated terminal evidence and audit required.','outbox_example.resolution');}
function resolutionPrincipal(array $settings):bool {return authorityAllows($settings,['outbox_admin','outbox_reconciler']);}
function resolutionSenderCurrent(array $settings):void
{
    if(($settings['role'] ?? null)!=='sender'||!resolutionPrincipal($settings)){resolutionDenied();}
    $file=privateFile($settings['configuration_file'],$settings['document_root']);$current=jsonFile($file);
    foreach(['role','document_root','database','storage','actor','version','epoch','seals','wire_keys','idempotency_keys','url','resolution_keys','receiver_epoch','authority_database'] as $field){if(($current[$field] ?? null)!==($settings[$field] ?? null)){resolutionDenied();}}
    $archive=array_key_exists('resolution_archive',$current)?$current['resolution_archive']:false;$knownArchive=array_key_exists('resolution_archive',$settings)?$settings['resolution_archive']:false;
    if(!is_bool($archive)||!is_bool($knownArchive)||$archive!==$knownArchive){resolutionDenied();}
    if((new \SoSecurity\Outbox\Policy(array_replace(['maximum_payload_bytes'=>8192],$current['policy'] ?? [])))->options()!==$settings['policy']){resolutionDenied();}
    clearstatcache(true,$settings['database']);privateFile($settings['database'],$settings['document_root']);$stat=stat($settings['database']);if($stat['dev'].':'.$stat['ino']!==$settings['sender_file_identity']){resolutionDenied();}
    $sets=[];foreach(['seals','wire_keys','idempotency_keys'] as $field){clearstatcache(true,$settings[$field]);$sets[]=keyData(privateFile($settings[$field],$settings['document_root']))['keys'];}
    foreach($sets as $i=>$keys){foreach($sets as $j=>$others){if($j<=$i){continue;}foreach($keys as $key){foreach($others as $other){if(hash_equals($key,$other)){resolutionDenied();}}}}}
    receiverDurable($settings['pdo'],['outbox_example_resolution_root','outbox_example_resolutions']);
    if(($settings['resolution_archive'] ?? false)===true){receiverDurable($settings['pdo'],['outbox_example_resolution_archives']);}
    resolutionAuditSchema($settings['pdo']);
}
/** @phpstan-impure Reads current management roles and historical object associations. */
function resolutionReceiverAuthority(array $settings,string $subject):bool
{
    // Historical closure permits disabled associations, while both current roles must coexist.
    return authorityAllows($settings,['receiver_admin','receiver_reconciler'],$subject,true);
}
function resolutionKeys(array $settings,bool $signing):array
{
    if(!function_exists('sodium_crypto_sign_seed_keypair')||!function_exists('sodium_crypto_sign_detached')||!function_exists('sodium_crypto_sign_verify_detached')){resolutionDenied();}
    $keys=keyData(privateFile($settings['resolution_keys'] ?? null,$settings['document_root']));
    if($signing){foreach(['seals','wire_keys'] as $purpose){foreach(keyData($settings[$purpose])['keys'] as $key){foreach($keys['keys'] as $seed){if(hash_equals($key,$seed)){resolutionDenied();}}}}}
    return $keys;
}
function resolutionPublicKeys(array $settings):array
{
    return receiverLocked($settings,static function()use($settings):array{
        if(!principal($settings,'receiver_admin')||!principal($settings,'receiver_reconciler')){resolutionDenied();}receiverCurrent($settings);$keys=resolutionKeys($settings,true);$public=[];
        foreach($keys['keys'] as $id=>$seed){$public[$id]=base64_encode(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)));}
        return ['current'=>$keys['current'],'keys'=>$public];
    });
}
function resolutionDelivery(string $event):string {return State::delivery(State::namespace(SITE,SCOPE,PRODUCER),$event);}
function resolutionRequestValue(string $raw):array
{
    $data=strlen($raw)<=12000?json_decode($raw,true,5):null;
    if(!is_array($data)||array_keys($data)!==['format','challenge','body','delivery_id']||json_encode($data)!==$raw||$data['format']!==1||!is_string($data['challenge'])||!preg_match('/\A[a-f0-9]{64}\z/D',$data['challenge'])||!is_string($data['body'])||!is_string($data['delivery_id'])){resolutionDenied();}
    $body=base64_decode($data['body'],true);if(!is_string($body)||base64_encode($body)!==$data['body']){resolutionDenied();}$event=event($body);
    if($data['delivery_id']!==resolutionDelivery($event['event_id'])){resolutionDenied();}return $data+['original_body'=>$body,'event'=>$event];
}
function resolutionInputFile(array $settings,string $path,int $maximum):string
{
    $raw=file_get_contents(privateFile($path,$settings['document_root']),false,null,0,$maximum+1);if(!is_string($raw)||strlen($raw)>$maximum){resolutionDenied();}return rtrim($raw,"\r\n");
}
function resolutionTerminal(array $settings,string $raw,bool $cancel=false):string
{
    $request=resolutionRequestValue($raw);$body=$request['original_body'];$event=$request['event'];$delivery=$request['delivery_id'];
    return receiverLocked($settings,static function()use($settings,$request,$body,$event,$delivery,$cancel):string{
        if(!resolutionReceiverAuthority($settings,$event['subject'])){resolutionDenied();}$keys=resolutionKeys($settings,true);$root=receiverCurrent($settings);$history=receiverVerifyRoot($settings,$root);
        if($cancel){
            $plan=receiverPlan($settings,$root,$body,$delivery,'cancelled');
            if($plan!==null){receiverSaveWitness($settings,$plan,'prepared');receiverTransaction($settings['pdo'],static function()use($settings,$plan,$event):void{if(!resolutionReceiverAuthority($settings,$event['subject'])){resolutionDenied();}receiverApplyPlan($settings,$plan);});if(!resolutionReceiverAuthority($settings,$event['subject'])){resolutionDenied();}receiverSaveWitness($settings,$plan,'committed');}
            $root=receiverCurrent($settings);$history=receiverVerifyRoot($settings,$root);
        }
        $record=$history[$event['event_id']] ?? null;
        if(!is_array($record)||$record!==receiverEventRow($body,$delivery,$record['outcome'])){resolutionDenied();}
        $value=receiverRootValue($settings,$root);$now=time();
        $payload=json_encode(['format'=>1,'site'=>SITE,'scope'=>SCOPE,'producer'=>PRODUCER,'event_id'=>$event['event_id'],'delivery_id'=>$delivery,'fingerprint'=>message($event,$body)->fingerprint(),'body_digest'=>hash('sha256',$body),'outcome'=>$record['outcome'],'challenge'=>$request['challenge'],'receiver_epoch'=>$settings['epoch'],'root_hash'=>receiverRowHash($root),'sequence'=>$value['sequence'],'issued_at'=>$now,'expires_at'=>$now+300,'destination_hash'=>hash('sha256',$settings['url'])]);
        if(!is_string($payload)||strlen($payload)>2048){resolutionDenied();}
        $current=resolutionKeys($settings,true);if($current!==$keys||!resolutionReceiverAuthority($settings,$event['subject'])||receiverCurrent($settings)!==$root){resolutionDenied();}
        $secret=sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($keys['keys'][$keys['current']]));
        return json_encode(['payload'=>base64_encode($payload),'key_id'=>$keys['current'],'signature'=>base64_encode(sodium_crypto_sign_detached('SoSecurity.OutboxExample.TerminalReceipt.1.'.$payload,$secret))]);
    });
}
function resolutionReceipt(string $raw,string $public):array
{
    if(!function_exists('sodium_crypto_sign_verify_detached')||strlen($public)!==32){resolutionDenied();}$envelope=strlen($raw)<=4096?json_decode($raw,true,4):null;
    if(!is_array($envelope)||array_keys($envelope)!==['payload','key_id','signature']||json_encode($envelope)!==$raw||!is_string($envelope['payload'])||!is_string($envelope['key_id'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$envelope['key_id'])||!is_string($envelope['signature'])){resolutionDenied();}
    $payload=base64_decode($envelope['payload'],true);$signature=base64_decode($envelope['signature'],true);
    if(!is_string($payload)||strlen($payload)>2048||base64_encode($payload)!==$envelope['payload']||!is_string($signature)||strlen($signature)!==64||base64_encode($signature)!==$envelope['signature']||!sodium_crypto_sign_verify_detached($signature,'SoSecurity.OutboxExample.TerminalReceipt.1.'.$payload,$public)){resolutionDenied();}
    $data=json_decode($payload,true,4);$fields=['format','site','scope','producer','event_id','delivery_id','fingerprint','body_digest','outcome','challenge','receiver_epoch','root_hash','sequence','issued_at','expires_at','destination_hash'];
    if(!is_array($data)||array_keys($data)!==$fields||json_encode($data)!==$payload||$data['format']!==1||$data['site']!==SITE||$data['scope']!==SCOPE||$data['producer']!==PRODUCER||!in_array($data['outcome'],['received','cancelled'],true)){resolutionDenied();}
    foreach(['delivery_id','fingerprint','body_digest','challenge','receiver_epoch','root_hash','destination_hash'] as $field){if(!is_string($data[$field])||!preg_match('/\A[a-f0-9]{64}\z/D',$data[$field])){resolutionDenied();}}
    foreach(['sequence','issued_at','expires_at'] as $field){if(!is_int($data[$field])||$data[$field]<0||$data[$field]>=PHP_INT_MAX-301){resolutionDenied();}}
    if(!is_string($data['event_id'])||$data['delivery_id']!==resolutionDelivery($data['event_id'])||$data['sequence']<1||$data['issued_at']<1||$data['expires_at']!==$data['issued_at']+300){resolutionDenied();}return $data+['key_id'=>$envelope['key_id']];
}
function resolutionSeal(array $settings,string $kind,array $data):array
{
    $payload=json_encode($data);if(!is_string($payload)||strlen($payload)>8192){resolutionDenied();}$keys=sealingKeys($settings['seals']);
    return ['payload'=>$payload,'seal_key'=>$keys->currentId(),'seal'=>bin2hex($keys->sign('SoSecurity.OutboxExample.Resolution.1.'.$kind.'.'.SITE.'.'.SCOPE.'.'.PRODUCER.'.'.$payload))];
}
function resolutionValue(array $settings,string $kind,array $row):array
{
    if(array_keys($row)!==['payload','seal_key','seal']||!is_string($row['payload'])||strlen($row['payload'])>8192||!is_string($row['seal_key'])||!is_string($row['seal'])||!preg_match('/\A[a-f0-9]{64}\z/D',$row['seal'])){resolutionDenied();}
    if(!sealingKeys($settings['seals'])->verify($row['seal_key'],'SoSecurity.OutboxExample.Resolution.1.'.$kind.'.'.SITE.'.'.SCOPE.'.'.PRODUCER.'.'.$row['payload'],hex2bin($row['seal']))){resolutionDenied();}
    $data=json_decode($row['payload'],true,5);if(!is_array($data)||json_encode($data)!==$row['payload']){resolutionDenied();}return $data;
}
function resolutionColumns(int $maximum=8192):string
{
    return "CASE WHEN typeof(payload)='blob' AND length(payload)<=".$maximum." THEN payload ELSE NULL END AS payload,CASE WHEN typeof(seal_key)='text' AND length(CAST(seal_key AS BLOB))<=32 THEN seal_key ELSE NULL END AS seal_key,CASE WHEN typeof(seal)='text' AND length(CAST(seal AS BLOB))=64 THEN seal ELSE NULL END AS seal";
}
/** @phpstan-impure Reads current SQL state, including changes made in this transaction. */
function resolutionRead(array $settings,?string $id=null,bool $archived=false):?array
{
    if($archived&&$id===null){resolutionDenied();}
    if($id===null){$sql='SELECT CASE WHEN typeof(slot)=\'integer\' AND slot=1 THEN 1 ELSE NULL END AS slot,'.resolutionColumns(2048).' FROM main.outbox_example_resolution_root LIMIT 2';$params=[];}
    else{$sql='SELECT '.resolutionColumns().' FROM main.'.($archived?'outbox_example_resolution_archives':'outbox_example_resolutions').' WHERE event_id=:id';$params=['id'=>$id];}
    $q=$settings['pdo']->prepare($sql);$q->execute($params);$rows=$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();if(!$rows){return null;}if(count($rows)!==1){resolutionDenied();}
    if($id===null){if(receiverSqlInteger($rows[0]['slot'],1)!==1){resolutionDenied();}unset($rows[0]['slot']);}return $rows[0];
}
function resolutionHistory(array $settings,bool $archived=false):array
{
    $hash=hash_init('sha256');hash_update($hash,($archived?'SoSecurity.OutboxExample.ResolutionArchive.1.':'SoSecurity.OutboxExample.ResolutionHistory.1.').SITE.'.'.SCOPE.'.'.PRODUCER);$count=0;$cursor=null;$keys=$archived?keyData($settings['seals'])['keys']:[];
    do{
        $columns=$archived?"CASE WHEN typeof(payload)='blob' AND length(payload)<=8192 THEN 1 ELSE NULL END AS bounded,CASE WHEN typeof(seal_key)='text' AND length(CAST(seal_key AS BLOB))<=32 THEN seal_key ELSE NULL END AS seal_key,CASE WHEN typeof(seal)='text' AND length(CAST(seal AS BLOB))=64 THEN seal ELSE NULL END AS seal":resolutionColumns();
        $table=$archived?'outbox_example_resolution_archives':'outbox_example_resolutions';
        $q=$settings['pdo']->prepare("SELECT CASE WHEN typeof(event_id)='text' AND length(CAST(event_id AS BLOB))<=96 THEN event_id ELSE NULL END AS event_id,".$columns.' FROM main.'.$table.($cursor===null?'':' WHERE event_id>:after').' ORDER BY '.$table.'.event_id LIMIT 64');
        $q->execute($cursor===null?[]:['after'=>$cursor]);$rows=$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();
        foreach($rows as $row){
            if(++$count>($archived?100000:1000)||!is_string($row['event_id'])||!preg_match('/\Ao1\.(?:0|[1-9][0-9]{0,18})\.[a-f0-9]{64}\z/D',$row['event_id'])){resolutionDenied();}$id=$row['event_id'];unset($row['event_id']);
            if($archived){if(receiverSqlInteger($row['bounded'],1)!==1||!is_string($row['seal_key'])||!isset($keys[$row['seal_key']])||!is_string($row['seal'])||!preg_match('/\A[a-f0-9]{64}\z/D',$row['seal'])){resolutionDenied();}}
            else{$value=resolutionValue($settings,'record',$row);if(($value['event_id'] ?? null)!==$id||($value['epoch'] ?? null)!==$settings['epoch']){resolutionDenied();}}
            hash_update($hash,json_encode([$id,$row['seal_key'],$row['seal']]));$cursor=$id;
        }
    }while(count($rows)===64);
    return ['entries'=>$count,'history_digest'=>hash_final($hash)];
}
function resolutionRoot(array $settings,bool $optional=false,bool $upgrade=false):?array
{
    $row=resolutionRead($settings);if($row===null){if($optional){return null;}resolutionDenied();}$root=resolutionValue($settings,'root',$row);
    $fields=['format','epoch','entries','history_digest','revision','created_at','observed_at'];if(($root['format'] ?? null)===2){$fields=array_merge($fields,['archive_entries','archive_digest']);}
    if(array_keys($root)!==$fields||!in_array($root['format'],[1,2],true)||$root['epoch']!==$settings['epoch']||!is_int($root['entries'])||!is_int($root['revision'])||$root['revision']<1||$root['revision']>=PHP_INT_MAX-1||!is_int($root['created_at'])||!is_int($root['observed_at'])||$root['created_at']<1||$root['created_at']>$root['observed_at']||$root['observed_at']>time()||!is_string($root['history_digest'])){resolutionDenied();}
    if(($root['format']===2)!==(($settings['resolution_archive'] ?? false)===true)&&!($upgrade&&$root['format']===1)){resolutionDenied();}
    $history=resolutionHistory($settings);if($root['entries']!==$history['entries']||!hash_equals($root['history_digest'],$history['history_digest'])){resolutionDenied();}
    if($root['format']===2){$archive=resolutionHistory($settings,true);if(!is_int($root['archive_entries'])||$root['archive_entries']!==$archive['entries']||!is_string($root['archive_digest'])||!hash_equals($root['archive_digest'],$archive['history_digest'])){resolutionDenied();}}return $root;
}
function resolutionWrite(array $settings,array $row,?string $id=null,bool $archived=false):void
{
    if($archived&&$id===null){resolutionDenied();}$table=$archived?'outbox_example_resolution_archives':'outbox_example_resolutions';
    $q=$settings['pdo']->prepare($id===null?'INSERT INTO main.outbox_example_resolution_root VALUES(1,:payload,:key,:seal) ON CONFLICT(slot) DO UPDATE SET payload=excluded.payload,seal_key=excluded.seal_key,seal=excluded.seal':'INSERT INTO main.'.$table.' VALUES(:id,:payload,:key,:seal) ON CONFLICT(event_id) DO UPDATE SET payload=excluded.payload,seal_key=excluded.seal_key,seal=excluded.seal');
    if($id!==null){$q->bindValue(':id',$id);}$q->bindValue(':payload',$row['payload'],PDO::PARAM_LOB);$q->bindValue(':key',$row['seal_key']);$q->bindValue(':seal',$row['seal']);$q->execute();$q->closeCursor();if(resolutionRead($settings,$id,$archived)!==$row){resolutionDenied();}
}
function resolutionSync(array $settings,array $root):array
{
    $history=resolutionHistory($settings);$root['entries']=$history['entries'];$root['history_digest']=$history['history_digest'];if($root['format']===2){$archive=resolutionHistory($settings,true);$root['archive_entries']=$archive['entries'];$root['archive_digest']=$archive['history_digest'];}++$root['revision'];$root['observed_at']=time();if($root['revision']>=PHP_INT_MAX-1){resolutionDenied();}resolutionWrite($settings,resolutionSeal($settings,'root',$root));if(resolutionRoot($settings)!==$root){resolutionDenied();}return $root;
}
function resolutionStored(array $settings,string $id,bool $rootChecked=false):?array
{
    if(!$rootChecked){resolutionRoot($settings);}$raw=resolutionRead($settings,$id);$archive=($settings['resolution_archive'] ?? false)===true?resolutionRead($settings,$id,true):null;
    if($raw!==null&&$archive!==null){resolutionDenied();}$raw=$raw ?? $archive;if($raw===null){return null;}$row=resolutionValue($settings,'record',$raw);
    $fields=['format','epoch','event_id','delivery_id','fingerprint','body_digest','challenge','receiver_epoch','destination_hash','state','outcome','evidence','verification_key','requested_by','resolved_by','created_at','verified_at','updated_at'];
    if(array_keys($row)!==$fields||$row['format']!==1||$row['epoch']!==$settings['epoch']||$row['event_id']!==$id||!in_array($row['state'],['prepared','resolved'],true)){resolutionDenied();}
    foreach(['delivery_id','fingerprint','body_digest','challenge','receiver_epoch','destination_hash'] as $field){if(!is_string($row[$field])||!preg_match('/\A[a-f0-9]{64}\z/D',$row[$field])){resolutionDenied();}}
    foreach(['created_at','verified_at','updated_at'] as $field){if(!is_int($row[$field])||$row[$field]<0||$row[$field]>time()){resolutionDenied();}}
    if($row['created_at']<1||$row['updated_at']<$row['created_at']||$row['delivery_id']!==resolutionDelivery($id)){resolutionDenied();}identifier($row['requested_by']);
    if($row['state']==='prepared'){if($row['outcome']!==''||$row['evidence']!==''||$row['verification_key']!==''||$row['resolved_by']!==''||$row['verified_at']!==0||$row['updated_at']!==$row['created_at']){resolutionDenied();}}
    else{
        identifier($row['resolved_by']);if(!is_string($row['evidence'])||!is_string($row['verification_key'])||$row['updated_at']!==$row['verified_at']||$row['verified_at']<$row['created_at']){resolutionDenied();}
        $public=base64_decode($row['verification_key'],true);if(!is_string($public)||base64_encode($public)!==$row['verification_key']){resolutionDenied();}$proof=resolutionReceipt($row['evidence'],$public);resolutionBind($row,$proof);
        if($row['verified_at']<$proof['issued_at']||$row['verified_at']>=$proof['expires_at']){resolutionDenied();}
    }
    if($archive!==null&&$row['state']!=='resolved'){resolutionDenied();}return $row;
}
function resolutionBind(array $row,array $proof):void
{
    foreach(['event_id','delivery_id','fingerprint','body_digest','challenge','receiver_epoch','destination_hash'] as $field){if($proof[$field]!==$row[$field]){resolutionDenied();}}
    if($row['state']==='resolved'&&$row['outcome']!==$proof['outcome']){resolutionDenied();}
}
function resolutionFresh(array $settings,array $row,string $raw):array
{
    resolutionSenderCurrent($settings);$keys=resolutionKeys($settings,false);$envelope=strlen($raw)<=4096?json_decode($raw,true,4):null;$id=is_array($envelope)?($envelope['key_id'] ?? null):null;
    if(!is_string($id)||!isset($keys['keys'][$id])){resolutionDenied();}$public=$keys['keys'][$id];$proof=resolutionReceipt($raw,$public);resolutionBind($row,$proof);
    if($proof['issued_at']>time()||$proof['expires_at']<=time()||$proof['receiver_epoch']!==($settings['receiver_epoch'] ?? null)||$proof['destination_hash']!==hash('sha256',$settings['url'])){resolutionDenied();}return ['proof'=>$proof,'public'=>$public];
}
function resolutionOriginal(array $settings,string $id):array
{
    $data=order($settings,$id);if($data===null){resolutionDenied();}$original=message($data,$data['body']);return ['original'=>$original,'data'=>$data];
}
function resolutionEventId(string $id):void
{
    try{State::idTime($id);}catch(\Throwable $failure){resolutionDenied();}
}
function resolutionQueueRecord(array $settings,string $id):?array
{
    $types=\SoSecurity\Outbox\Schema::recordTypes();unset($types['payload_body']);$namespace=State::namespace(SITE,SCOPE,PRODUCER);
    $q=$settings['pdo']->prepare('SELECT '.\SoSecurity\Support\SqlSchema::boundedProjection('sqlite',$types).','.\SoSecurity\Support\SqlSchema::blobLength('sqlite','payload_body').' AS body_length FROM main.sosecurity_outbox_records WHERE namespace=:namespace AND key_hash=:key');$q->execute(['namespace'=>$namespace,'key'=>hash('sha256',$id)]);$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();
    return is_array($row)?State::record($row,sealingKeys($settings['seals']),new \SoSecurity\Outbox\Policy($settings['policy']),$namespace,$settings['epoch'],SCOPE,PRODUCER,time()):null;
}
function resolutionInitialize(array $settings):bool
{
    resolutionSenderCurrent($settings);$unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    return $unit->run(static function()use($settings):bool{
        resolutionSenderCurrent($settings);if(resolutionRoot($settings,true,true)!==null){return false;}if(resolutionHistory($settings)['entries']!==0){resolutionDenied();}
        $namespace=State::namespace(SITE,SCOPE,PRODUCER);$q=$settings['pdo']->prepare('SELECT 1 FROM main.sosecurity_outbox_records WHERE namespace=:namespace AND status=:status LIMIT 1');$q->execute(['namespace'=>$namespace,'status'=>'resolved']);$orphan=$q->fetchColumn()!==false;$q->closeCursor();if($orphan){resolutionDenied();}
        $now=time();$history=resolutionHistory($settings);$root=['format'=>1,'epoch'=>$settings['epoch'],'entries'=>0,'history_digest'=>$history['history_digest'],'revision'=>1,'created_at'=>$now,'observed_at'=>$now];if(($settings['resolution_archive'] ?? false)===true){$archive=resolutionHistory($settings,true);if($archive['entries']!==0){resolutionDenied();}$root['format']=2;$root['archive_entries']=0;$root['archive_digest']=$archive['history_digest'];}resolutionWrite($settings,resolutionSeal($settings,'root',$root));resolutionRoot($settings);return true;
    },null,static function()use($settings):void{resolutionSenderCurrent($settings);resolutionRoot($settings);});
}
function resolutionExport(array $settings,string $id):string
{
    resolutionEventId($id);resolutionSenderCurrent($settings);$original=resolutionOriginal($settings,$id)['original'];$status=outbox($settings)->status(SCOPE,PRODUCER,$id,$settings['actor']);
    if($status===null||$status->state()!=='dead'||$original->createdAt()+$settings['policy']['recovery_age']>time()||!is_string($settings['receiver_epoch'] ?? null)||!preg_match('/\A[a-f0-9]{64}\z/D',$settings['receiver_epoch'])){resolutionDenied();}
    $challenge=bin2hex(random_bytes(32));$unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    $row=$unit->run(static function()use($settings,$id,$original,$challenge):array{
        resolutionSenderCurrent($settings);if(resolutionOriginal($settings,$id)['original']->fingerprint()!==$original->fingerprint()){resolutionDenied();}$queueRow=resolutionQueueRecord($settings,$id);if($queueRow===null||$queueRow['status']!=='dead'||$queueRow['payload_present']!==0||$queueRow['fingerprint']!==$original->fingerprint()){resolutionDenied();}$root=resolutionRoot($settings);$row=resolutionStored($settings,$id);if($row!==null){if($row['state']!=='prepared'||$row['fingerprint']!==$original->fingerprint()||$row['receiver_epoch']!==$settings['receiver_epoch']||$row['destination_hash']!==hash('sha256',$settings['url'])){resolutionDenied();}return $row;}
        if($root['entries']>=1000){resolutionDenied();}$now=time();$row=['format'=>1,'epoch'=>$settings['epoch'],'event_id'=>$id,'delivery_id'=>resolutionDelivery($id),'fingerprint'=>$original->fingerprint(),'body_digest'=>hash('sha256',$original->body()),'challenge'=>$challenge,'receiver_epoch'=>$settings['receiver_epoch'],'destination_hash'=>hash('sha256',$settings['url']),'state'=>'prepared','outcome'=>'','evidence'=>'','verification_key'=>'','requested_by'=>$settings['actor'],'resolved_by'=>'','created_at'=>$now,'verified_at'=>0,'updated_at'=>$now];
        resolutionWrite($settings,resolutionSeal($settings,'record',$row),$id);resolutionSync($settings,$root);return $row;
    },null,static function()use($settings):void{resolutionSenderCurrent($settings);resolutionRoot($settings);});
    return json_encode(['format'=>1,'challenge'=>$row['challenge'],'body'=>base64_encode($original->body()),'delivery_id'=>$row['delivery_id']]);
}
function resolutionGcAllowed(array $settings,array $metadata):bool
{
    resolutionSenderCurrent($settings);if(!is_string($metadata['id'] ?? null)){return false;}$row=resolutionStored($settings,$metadata['id']);
    return $row!==null&&$row['state']==='resolved'&&($metadata['resolution'] ?? null)===$row['outcome']&&($metadata['fingerprint'] ?? null)===$row['fingerprint']&&($metadata['payload_digest'] ?? null)===$row['body_digest']&&($metadata['evidence_digest'] ?? null)===hash('sha256',$row['evidence']);
}
function resolutionImport(array $settings,string $id,string $raw):array
{
    resolutionEventId($id);resolutionSenderCurrent($settings);$row=resolutionStored($settings,$id);if($row===null){resolutionDenied();}
    if($row['state']==='resolved'){if($row['evidence']!==$raw){resolutionDenied();}return resolutionStatus($settings,$id);}
    $original=resolutionOriginal($settings,$id)['original'];if($row['fingerprint']!==$original->fingerprint()){resolutionDenied();}
    resolutionFresh($settings,$row,$raw);$unit=new SqlTransaction($settings['pdo'],new SystemClock(),$settings['policy']['io_milliseconds']);
    $unit->run(static function()use($settings,$id,$raw,$original):void{
        resolutionSenderCurrent($settings);if(resolutionOriginal($settings,$id)['original']->fingerprint()!==$original->fingerprint()){resolutionDenied();}$root=resolutionRoot($settings);$row=resolutionStored($settings,$id);if($row===null||$row['state']!=='prepared'||$row['fingerprint']!==$original->fingerprint()){resolutionDenied();}$verified=resolutionFresh($settings,$row,$raw);$proof=$verified['proof'];
        $row['state']='resolved';$row['outcome']=$proof['outcome'];$row['evidence']=$raw;$row['verification_key']=base64_encode($verified['public']);$row['resolved_by']=$settings['actor'];$row['verified_at']=time();$row['updated_at']=$row['verified_at'];
        resolutionWrite($settings,resolutionSeal($settings,'record',$row),$id);resolutionSync($settings,$root);
        $guard=static function(string $phase,array $metadata)use($settings,$id,$raw):bool{
            resolutionSenderCurrent($settings);$current=resolutionStored($settings,$id);if($current===null||$current['state']!=='resolved'||$current['resolved_by']!==$settings['actor']||$current['evidence']!==$raw||resolutionOriginal($settings,$id)['original']->fingerprint()!==$current['fingerprint']){return false;}resolutionFresh($settings,$current,$raw);
            return ($metadata['fingerprint'] ?? null)===$current['fingerprint']&&($metadata['delivery_id'] ?? null)===$current['delivery_id']&&($metadata['payload_digest'] ?? null)===$current['body_digest']&&($metadata['outcome'] ?? null)===$current['outcome']&&($metadata['evidence_digest'] ?? null)===hash('sha256',$raw);
        };
        if(!outbox($settings)->reconcile($original,$settings['actor'],$row['outcome'],hash('sha256',$raw),$guard)){resolutionDenied();}
    },null,static function()use($settings,$id,$raw):void{resolutionSenderCurrent($settings);$row=resolutionStored($settings,$id);if($row===null||$row['state']!=='resolved'||$row['evidence']!==$raw||resolutionOriginal($settings,$id)['original']->fingerprint()!==$row['fingerprint']){resolutionDenied();}resolutionFresh($settings,$row,$raw);});
    return resolutionStatus($settings,$id);
}
function resolutionStatus(array $settings,string $id):array
{
    resolutionEventId($id);resolutionSenderCurrent($settings);$row=resolutionStored($settings,$id);if($row===null){resolutionDenied();}$status=outbox($settings)->status(SCOPE,PRODUCER,$id,$settings['actor']);
    if($row['state']==='resolved'&&$status!==null&&($status->state()!=='resolved'||$status->resolution()!==$row['outcome'])){resolutionDenied();}
    if($row['state']==='resolved'){$queueRow=resolutionQueueRecord($settings,$id);if(($queueRow===null)!==($status===null)||($queueRow!==null&&($queueRow['status']!=='resolved'||$queueRow['fingerprint']!==$row['fingerprint']||$queueRow['payload_digest']!==$row['body_digest']||$queueRow['token_digest']!==hash('sha256',$row['evidence'])))){resolutionDenied();}}
    resolutionSenderCurrent($settings);$result=['event_id'=>$id,'state'=>$row['state'],'outcome'=>$row['outcome'],'evidence_digest'=>$row['state']==='resolved'?hash('sha256',$row['evidence']):null,'verified_at'=>$row['verified_at'],'queue_present'=>$status!==null];if(($settings['resolution_archive'] ?? false)===true){$result['archived']=resolutionRead($settings,$id,true)!==null;}return $result;
}
