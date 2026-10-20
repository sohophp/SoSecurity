<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Outbox;

use PDO;
use SoSecurity\Exception\SecurityException;

// Inert host adapter. The witness lives outside business-database backup/restore.
/** @return never */
function receiverDenied():void {throw new SecurityException('Receiver checkpoint requires controlled recovery.','outbox_example.recovery_required');}
function receiverDeployment(array $settings):void
{
    if(!is_string($settings['configuration_file'] ?? null)){receiverDenied();}clearstatcache(true,$settings['configuration_file']);$current=jsonFile(privateFile($settings['configuration_file'],$settings['document_root']));
    foreach(['role','document_root','database','storage','actor','version','epoch','seals','wire_keys','url','checkpoint_database','checkpoint_lock','resolution_keys','authority_database'] as $field){if(($current[$field] ?? null)!==($settings[$field] ?? null)){receiverDenied();}}
    foreach(['database','checkpoint_database','checkpoint_lock'] as $field){$path=$settings[$field];clearstatcache(true,$path);privateFile($path,$settings['document_root']);$stat=stat($path);$identity=$stat['dev'].':'.$stat['ino'];if(($settings['receiver_files'][$path] ?? null)!==$identity){receiverDenied();}}
    foreach(['seals','wire_keys'] as $field){clearstatcache(true,$settings[$field]);privateFile($settings[$field],$settings['document_root']);}
    $seals=keyData($settings['seals'])['keys'];$wire=keyData($settings['wire_keys'])['keys'];foreach($seals as $key){foreach($wire as $other){if(hash_equals($key,$other)){receiverDenied();}}}
}
function receiverEmptyRoot():string {return hash('sha256','SoSecurity.OutboxExample.ReceiverHistory.1.'.SITE.'.'.SCOPE.'.'.PUBLISHER);}
function receiverRowHash(array $row):string {return hash('sha256',$row['payload']."\0".$row['seal_key']."\0".$row['seal']);}
function receiverSeal(array $settings,string $kind,array $value):array
{
    $payload=json_encode($value);if(!is_string($payload)||strlen($payload)>($kind==='root'?2048:15000)){receiverDenied();}
    $keys=sealingKeys($settings['seals']);$input='SoSecurity.OutboxExample.Receiver.1.'.$kind.'.'.SITE.'.'.SCOPE.'.'.PUBLISHER.'.'.$payload;
    return ['payload'=>$payload,'seal_key'=>$keys->currentId(),'seal'=>bin2hex($keys->sign($input))];
}
function receiverValue(array $settings,string $kind,array $row):array
{
    if(array_keys($row)!==['payload','seal_key','seal']||!is_string($row['payload'])||strlen($row['payload'])>($kind==='root'?2048:15000)||!is_string($row['seal_key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$row['seal_key'])||!is_string($row['seal'])||!preg_match('/\A[a-f0-9]{64}\z/D',$row['seal'])){receiverDenied();}
    $input='SoSecurity.OutboxExample.Receiver.1.'.$kind.'.'.SITE.'.'.SCOPE.'.'.PUBLISHER.'.'.$row['payload'];
    if(!sealingKeys($settings['seals'])->verify($row['seal_key'],$input,hex2bin($row['seal']))){receiverDenied();}
    $value=json_decode($row['payload'],true,8);if(!is_array($value)||json_encode($value)!==$row['payload']){receiverDenied();}return $value;
}
function receiverTable(string $kind):string
{
    if(!in_array($kind,['root','checkpoint'],true)){receiverDenied();}return 'outbox_example_receiver_'.$kind;
}
function receiverSqlInteger($value,int $maximum):int
{
    if(is_int($value)&&$value>=0&&$value<=$maximum){return $value;}
    if(is_string($value)&&preg_match('/\A(?:0|[1-9][0-9]{0,6})\z/D',$value)&&(int)$value<=$maximum){return (int)$value;}receiverDenied();
}
function receiverRead(PDO $pdo,string $kind):?array
{
    $maximum=$kind==='root'?2048:15000;$table=receiverTable($kind);
    $query=$pdo->query("SELECT CASE WHEN typeof(slot)='integer' AND slot=1 THEN slot ELSE NULL END AS slot,CASE WHEN typeof(payload)='blob' AND length(payload)<=".$maximum." THEN payload ELSE NULL END AS payload,CASE WHEN typeof(seal_key)='text' AND length(CAST(seal_key AS BLOB))<=32 THEN seal_key ELSE NULL END AS seal_key,CASE WHEN typeof(seal)='text' AND length(CAST(seal AS BLOB))=64 THEN seal ELSE NULL END AS seal FROM ".$table.' LIMIT 2');
    $rows=$query->fetchAll(PDO::FETCH_ASSOC);$query->closeCursor();if(!$rows){return null;}if(count($rows)!==1||receiverSqlInteger($rows[0]['slot'],1)!==1){receiverDenied();}unset($rows[0]['slot']);return $rows[0];
}
function receiverWrite(PDO $pdo,string $kind,array $row):void
{
    $table=receiverTable($kind);$query=$pdo->prepare('INSERT INTO '.$table.' VALUES(1,:payload,:key,:seal) ON CONFLICT(slot) DO UPDATE SET payload=excluded.payload,seal_key=excluded.seal_key,seal=excluded.seal');
    $query->bindValue(':payload',$row['payload'],PDO::PARAM_LOB);$query->bindValue(':key',$row['seal_key']);$query->bindValue(':seal',$row['seal']);$query->execute();$query->closeCursor();
    if(receiverRead($pdo,$kind)!==$row){receiverDenied();}
}
function receiverIdle(PDO $pdo):void
{
    if($pdo->inTransaction()){receiverDenied();}
    try{$pdo->exec('BEGIN DEFERRED');}
    catch(\PDOException $failure){receiverDenied();}
    $pdo->exec('ROLLBACK');
}
function receiverTransaction(PDO $pdo,callable $work):void
{
    receiverIdle($pdo);$owned=false;
    try{$pdo->beginTransaction();$owned=true;$work();$pdo->commit();$owned=false;}
    finally{if($owned&&$pdo->inTransaction()){$pdo->rollBack();}}
}
function receiverActive(PDO $pdo):void
{
    try{$pdo->exec('BEGIN DEFERRED');}
    catch(\PDOException $failure){$info=$failure->errorInfo;if(isset($info[1],$info[2])&&(int)$info[1]===1&&$info[2]==='cannot start a transaction within a transaction'){return;}receiverDenied();}
    $pdo->exec('ROLLBACK');receiverDenied();
}
function receiverDurable(PDO $pdo,array $tables):void
{
    if($pdo->getAttribute(PDO::ATTR_DRIVER_NAME)!=='sqlite'||(int)$pdo->getAttribute(PDO::ATTR_ERRMODE)!==PDO::ERRMODE_EXCEPTION||(int)$pdo->query('PRAGMA main.synchronous')->fetchColumn()<2||!in_array(strtolower($pdo->query('PRAGMA main.journal_mode')->fetchColumn()),['delete','truncate','persist','wal'],true)){receiverDenied();}
    foreach($tables as $table){
        foreach(['main','temp'] as $schema){$query=$pdo->prepare('SELECT 1 FROM '.$schema.'.sqlite_master WHERE type=:type AND tbl_name=:table LIMIT 1');$query->execute(['type'=>'trigger','table'=>$table]);$found=$query->fetchColumn()!==false;$query->closeCursor();if($found){receiverDenied();}}
    }
}
function receiverLocked(array $settings,callable $work)
{
    if(($settings['role'] ?? null)!=='receiver'||!isset($settings['checkpoint_pdo'])){receiverDenied();}
    receiverDeployment($settings);
    receiverIdle($settings['pdo']);receiverIdle($settings['checkpoint_pdo']);
    $path=privateFile($settings['checkpoint_lock'],$settings['document_root']);$handle=fopen($path,'rb');if(!is_resource($handle)){receiverDenied();}$locked=false;
    try{
        $until=microtime(true)+1;
        do{$locked=flock($handle,LOCK_EX|LOCK_NB);if(!$locked){usleep(10000);}}while(!$locked&&microtime(true)<$until);
        if(!$locked){receiverDenied();}
        receiverDeployment($settings);
        $stat=fstat($handle);$current=stat($path);if($stat['dev']!==$current['dev']||$stat['ino']!==$current['ino']){receiverDenied();}
        receiverDurable($settings['pdo'],['outbox_example_receiver_root','outbox_example_effects','outbox_example_projection','outbox_example_cancellations']);receiverDurable($settings['checkpoint_pdo'],['outbox_example_receiver_checkpoint']);
        return $work();
    }finally{if($locked){flock($handle,LOCK_UN);}fclose($handle);}
}
function receiverHistory(array $settings):array
{
    $pdo=$settings['pdo'];$count=(int)$pdo->query('SELECT COUNT(*) FROM outbox_example_effects')->fetchColumn();$projections=(int)$pdo->query('SELECT COUNT(*) FROM outbox_example_projection')->fetchColumn();
    if($count<0||$count>1000||$projections!==$count){receiverDenied();}
    $fields=['publisher'=>64,'event_id'=>96,'delivery_id'=>64,'body_digest'=>64,'order_id'=>32,'subject'=>64];$columns=[];
    foreach($fields as $name=>$maximum){$columns[]="CASE WHEN typeof(e.".$name.")='text' AND length(CAST(e.".$name.' AS BLOB))<='.$maximum.' THEN e.'.$name.' ELSE NULL END AS '.$name;}
    $columns[]="CASE WHEN typeof(e.amount)='integer' AND e.amount BETWEEN 1 AND 1000000 THEN e.amount ELSE NULL END AS amount";
    $columns[]="CASE WHEN typeof(p.amount)='integer' AND p.amount=e.amount AND typeof(p.deliveries)='integer' AND p.deliveries=1 THEN 1 ELSE NULL END AS projected";
    $query=$pdo->query('SELECT '.implode(',',$columns).' FROM outbox_example_effects e LEFT JOIN outbox_example_projection p ON p.subject=e.subject AND p.order_id=e.order_id ORDER BY e.event_id LIMIT 1001');$rows=$query->fetchAll(PDO::FETCH_ASSOC);$query->closeCursor();
    if(count($rows)!==$count){receiverDenied();}$records=[];
    foreach($rows as $row){
        foreach($fields as $name=>$maximum){if(!is_string($row[$name])){receiverDenied();}}
        if($row['publisher']!==PUBLISHER||!preg_match('/\Ao1\.(0|[1-9][0-9]{0,17})\.[a-f0-9]{64}\z/D',$row['event_id'],$match)||!preg_match('/\A[a-f0-9]{32}\z/D',$row['order_id'])||$row['event_id']!==\SoSecurity\Outbox\Message::identifier($row['order_id'],(int)$match[1])||!preg_match('/\A[a-f0-9]{64}\z/D',$row['delivery_id'])||!preg_match('/\A[a-f0-9]{64}\z/D',$row['body_digest'])||receiverSqlInteger($row['projected'],1)!==1){receiverDenied();}
        try{identifier($row['subject']);}catch(\Throwable $failure){receiverDenied();}$row['amount']=receiverSqlInteger($row['amount'],1000000);unset($row['projected']);$records[$row['event_id']]=$row;
    }
    $cancelCount=(int)$pdo->query('SELECT COUNT(*) FROM main.outbox_example_cancellations')->fetchColumn();if($cancelCount<0||$count+$cancelCount>1000){receiverDenied();}
    foreach($records as &$record){$record['outcome']='received';}unset($record);
    $cancelColumns=[];foreach($fields as $name=>$maximum){$cancelColumns[]="CASE WHEN typeof(".$name.")='text' AND length(CAST(".$name.' AS BLOB))<='.$maximum.' THEN '.$name.' ELSE NULL END AS '.$name;}
    $cancelColumns[]="CASE WHEN typeof(amount)='integer' AND amount BETWEEN 1 AND 1000000 THEN amount ELSE NULL END AS amount";
    $query=$pdo->query('SELECT '.implode(',',$cancelColumns).' FROM main.outbox_example_cancellations ORDER BY event_id LIMIT 1001');$cancelRows=$query->fetchAll(PDO::FETCH_ASSOC);$query->closeCursor();if(count($cancelRows)!==$cancelCount){receiverDenied();}
    foreach($cancelRows as $row){
        foreach($fields as $name=>$maximum){if(!is_string($row[$name])){receiverDenied();}}
        if($row['publisher']!==PUBLISHER||!preg_match('/\Ao1\.(0|[1-9][0-9]{0,17})\.[a-f0-9]{64}\z/D',$row['event_id'],$match)||!preg_match('/\A[a-f0-9]{32}\z/D',$row['order_id'])||$row['event_id']!==\SoSecurity\Outbox\Message::identifier($row['order_id'],(int)$match[1])||!preg_match('/\A[a-f0-9]{64}\z/D',$row['delivery_id'])||!preg_match('/\A[a-f0-9]{64}\z/D',$row['body_digest'])){receiverDenied();}
        try{identifier($row['subject']);}catch(\Throwable $failure){receiverDenied();}$row['amount']=receiverSqlInteger($row['amount'],1000000);$row['outcome']='cancelled';
        foreach($records as $old){if($old['event_id']===$row['event_id']||$old['order_id']===$row['order_id']||$old['delivery_id']===$row['delivery_id']){receiverDenied();}}
        $records[$row['event_id']]=$row;
    }
    return $records;
}
function receiverHistoryDigest(array $records):string
{
    ksort($records,SORT_STRING);$hash=hash_init('sha256');hash_update($hash,receiverEmptyRoot());foreach($records as $record){$outcome=$record['outcome'];unset($record['outcome']);hash_update($hash,($outcome==='cancelled'?'cancelled.':'').json_encode(array_values($record)));}return hash_final($hash);
}
function receiverRootValue(array $settings,array $row):array
{
    $root=receiverValue($settings,'root',$row);$fields=['format','epoch','sequence','entries','history_digest','parent_hash','created_at','updated_at'];
    if(array_keys($root)!==$fields||!in_array($root['format'],[1,2],true)){receiverDenied();}
    foreach(['sequence','entries','created_at','updated_at'] as $field){if(!is_int($root[$field])||$root[$field]<0||$root[$field]>=PHP_INT_MAX-31536001){receiverDenied();}}
    foreach(['epoch','history_digest','parent_hash'] as $field){if(!is_string($root[$field])||!preg_match('/\A[a-f0-9]{64}\z/D',$root[$field])){receiverDenied();}}
    if($root['entries']>1000||$root['entries']>$root['sequence']||$root['created_at']>$root['updated_at']||$root['updated_at']>time()){receiverDenied();}return $root;
}
function receiverVerifyRoot(array $settings,array $expected):array
{
    $actual=receiverRead($settings['pdo'],'root');if($actual!==$expected){receiverDenied();}$value=receiverRootValue($settings,$actual);$history=receiverHistory($settings);
    if($value['entries']!==count($history)||!hash_equals($value['history_digest'],receiverHistoryDigest($history))){receiverDenied();}
    if($value['format']===1){foreach($history as $record){if($record['outcome']==='cancelled'){receiverDenied();}}}return $history;
}
function receiverWitness(array $settings,?string $expectedEpoch=null):array
{
    $row=receiverRead($settings['checkpoint_pdo'],'checkpoint');if($row===null){receiverDenied();}$data=receiverValue($settings,'checkpoint',$row);
    if(array_keys($data)!==['format','state','kind','previous','current','body','delivery']||$data['format']!==1||!in_array($data['state'],['prepared','committed'],true)||!in_array($data['kind'],['initialize','event','epoch','cancel'],true)||!is_array($data['current'])||($data['previous']!==null&&!is_array($data['previous']))||!is_string($data['body'])||!is_string($data['delivery'])){receiverDenied();}
    $current=receiverRootValue($settings,$data['current']);if($current['epoch']!==($expectedEpoch ?? $settings['epoch'])){receiverDenied();}
    if($data['kind']==='initialize'){if($data['previous']!==null||$current['format']!==1||$current['sequence']!==0||$current['entries']!==0||$current['parent_hash']!==str_repeat('0',64)||$data['body']!==''||$data['delivery']!==''){receiverDenied();}}
    else{
        if($data['previous']===null){receiverDenied();}$previous=receiverRootValue($settings,$data['previous']);
        if($current['sequence']!==$previous['sequence']+1||$current['created_at']!==$previous['created_at']||$current['updated_at']<$previous['updated_at']||$current['parent_hash']!==receiverRowHash($data['previous'])){receiverDenied();}
        if(($data['kind']==='cancel'&&$current['format']!==2)||($data['kind']!=='cancel'&&$current['format']!==$previous['format'])){receiverDenied();}
        if($data['kind']==='epoch'){if($data['body']!==''||$data['delivery']!==''||$current['entries']!==$previous['entries']||$current['history_digest']!==$previous['history_digest']||$current['epoch']===$previous['epoch']){receiverDenied();}}
        else{if($current['epoch']!==$previous['epoch']||$current['entries']!==$previous['entries']+1||!preg_match('/\A[a-f0-9]{64}\z/D',$data['delivery'])){receiverDenied();}$body=base64_decode($data['body'],true);if(!is_string($body)||base64_encode($body)!==$data['body']){receiverDenied();}event($body);}
    }
    return $data;
}
function receiverSaveWitness(array $settings,array $plan,string $state):void
{
    receiverDeployment($settings);
    $plan['state']=$state;$row=receiverSeal($settings,'checkpoint',$plan);receiverTransaction($settings['checkpoint_pdo'],static function()use($settings,$row):void{receiverWrite($settings['checkpoint_pdo'],'checkpoint',$row);});
    if(receiverWitness($settings)!==$plan){receiverDenied();}
}
function receiverCurrent(array $settings,?string $expectedEpoch=null):array
{
    receiverDeployment($settings);$witness=receiverWitness($settings,$expectedEpoch);if($witness['state']!=='committed'){receiverDenied();}receiverVerifyRoot($settings,$witness['current']);return $witness['current'];
}
function receiverEventRow(string $body,string $delivery,string $outcome='received'):array
{
    if(!in_array($outcome,['received','cancelled'],true)){receiverDenied();}$data=event($body);mapped($body,$delivery);return ['publisher'=>PUBLISHER,'event_id'=>$data['event_id'],'delivery_id'=>$delivery,'body_digest'=>hash('sha256',$body),'order_id'=>$data['order_id'],'subject'=>$data['subject'],'amount'=>$data['amount'],'outcome'=>$outcome];
}
function receiverPlan(array $settings,array $previous,string $body,string $delivery,string $outcome='received'):?array
{
    $history=receiverVerifyRoot($settings,$previous);$value=receiverRootValue($settings,$previous);$record=receiverEventRow($body,$delivery,$outcome);
    if(isset($history[$record['event_id']])){if($history[$record['event_id']]!==$record){throw new SecurityException('Receiver business event conflict.','outbox_example.conflict');}return null;}
    foreach($history as $old){if($old['delivery_id']===$delivery||$old['order_id']===$record['order_id']){throw new SecurityException('Receiver business event conflict.','outbox_example.conflict');}}
    if(count($history)>=1000||$value['sequence']>=PHP_INT_MAX-31536002){receiverDenied();}$history[$record['event_id']]=$record;++$value['sequence'];++$value['entries'];$value['history_digest']=receiverHistoryDigest($history);$value['parent_hash']=receiverRowHash($previous);$value['updated_at']=time();
    if($outcome==='cancelled'){$value['format']=2;}
    return ['format'=>1,'state'=>'prepared','kind'=>$outcome==='cancelled'?'cancel':'event','previous'=>$previous,'current'=>receiverSeal($settings,'root',$value),'body'=>base64_encode($body),'delivery'=>$delivery];
}
function receiverApplyPlan(array $settings,array $plan):void
{
    receiverDeployment($settings);
    receiverActive($settings['pdo']);
    if($plan['previous']!==null){receiverVerifyRoot($settings,$plan['previous']);}
    elseif(receiverRead($settings['pdo'],'root')!==null||receiverHistory($settings)||(int)$settings['pdo']->query('SELECT COUNT(*) FROM sosecurity_webhook_inbox')->fetchColumn()!==0||(int)$settings['pdo']->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn()!==0){receiverDenied();}
    if($plan['kind']==='event'){$body=base64_decode($plan['body'],true);$message=mapped($body,$plan['delivery']);if(!associated($settings,$message)){receiverDenied();}apply($settings['pdo'],$message,$body);}
    elseif($plan['kind']==='cancel'){$body=base64_decode($plan['body'],true);$record=receiverEventRow($body,$plan['delivery'],'cancelled');if(!resolutionReceiverAuthority($settings,$record['subject'])){receiverDenied();}unset($record['outcome']);$q=$settings['pdo']->prepare('INSERT INTO main.outbox_example_cancellations VALUES(:publisher,:event_id,:delivery_id,:body_digest,:order_id,:subject,:amount)');$q->execute($record);$q->closeCursor();}
    receiverWrite($settings['pdo'],'root',$plan['current']);receiverVerifyRoot($settings,$plan['current']);
}
function receiverInitialize(array $settings):bool
{
    return receiverLocked($settings,static function()use($settings):bool{
        if(!principal($settings,'receiver_admin')){receiverDenied();}
        $old=receiverRead($settings['checkpoint_pdo'],'checkpoint');
        if($old!==null){receiverCurrent($settings);return false;}
        if(receiverRead($settings['pdo'],'root')!==null||receiverHistory($settings)||(int)$settings['pdo']->query('SELECT COUNT(*) FROM sosecurity_webhook_inbox')->fetchColumn()!==0||(int)$settings['pdo']->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn()!==0){receiverDenied();}
        $now=time();$root=receiverSeal($settings,'root',['format'=>1,'epoch'=>$settings['epoch'],'sequence'=>0,'entries'=>0,'history_digest'=>receiverHistoryDigest([]),'parent_hash'=>str_repeat('0',64),'created_at'=>$now,'updated_at'=>$now]);
        $plan=['format'=>1,'state'=>'prepared','kind'=>'initialize','previous'=>null,'current'=>$root,'body'=>'','delivery'=>''];receiverSaveWitness($settings,$plan,'prepared');receiverTransaction($settings['pdo'],static function()use($settings,$plan):void{if(!principal($settings,'receiver_admin')){receiverDenied();}receiverApplyPlan($settings,$plan);});if(!principal($settings,'receiver_admin')){receiverDenied();}receiverSaveWitness($settings,$plan,'committed');return true;
    });
}
function receiverRecover(array $settings):bool
{
    return receiverLocked($settings,static function()use($settings):bool{
        if(!principal($settings,'receiver_admin')){receiverDenied();}$plan=receiverWitness($settings);if($plan['kind']==='cancel'&&!resolutionReceiverAuthority($settings,event(base64_decode($plan['body'],true))['subject'])){receiverDenied();}$root=receiverRead($settings['pdo'],'root');
        if($root===$plan['current']){receiverVerifyRoot($settings,$root);if($plan['state']==='committed'){return false;}}
        elseif($root===$plan['previous']){receiverTransaction($settings['pdo'],static function()use($settings,$plan):void{if(!principal($settings,'receiver_admin')){receiverDenied();}receiverApplyPlan($settings,$plan);});}
        else{receiverDenied();}
        if(!principal($settings,'receiver_admin')){receiverDenied();}receiverSaveWitness($settings,$plan,'committed');return true;
    });
}
function receiverInspect(array $settings):array
{
    return receiverLocked($settings,static function()use($settings):array{if(!principal($settings,'receiver_admin')){receiverDenied();}$row=receiverCurrent($settings);$value=receiverRootValue($settings,$row);return ['epoch'=>$value['epoch'],'sequence'=>$value['sequence'],'entries'=>$value['entries'],'root_hash'=>receiverRowHash($row)];});
}
function receiverRotateEpoch(array $settings,string $previousEpoch,string $expectedRootHash):bool
{
    if(!preg_match('/\A[a-f0-9]{64}\z/D',$previousEpoch)||$previousEpoch===$settings['epoch']||!preg_match('/\A[a-f0-9]{64}\z/D',$expectedRootHash)){receiverDenied();}
    return receiverLocked($settings,static function()use($settings,$previousEpoch,$expectedRootHash):bool{
        if(!principal($settings,'receiver_admin')){receiverDenied();}$previous=receiverCurrent($settings,$previousEpoch);$value=receiverRootValue($settings,$previous);
        if(!hash_equals($expectedRootHash,receiverRowHash($previous))){receiverDenied();}
        if($value['sequence']>=PHP_INT_MAX-31536002){receiverDenied();}
        $value['epoch']=$settings['epoch'];++$value['sequence'];$value['parent_hash']=receiverRowHash($previous);$value['updated_at']=time();
        $plan=['format'=>1,'state'=>'prepared','kind'=>'epoch','previous'=>$previous,'current'=>receiverSeal($settings,'root',$value),'body'=>'','delivery'=>''];receiverSaveWitness($settings,$plan,'prepared');receiverTransaction($settings['pdo'],static function()use($settings,$plan):void{if(!principal($settings,'receiver_admin')){receiverDenied();}receiverApplyPlan($settings,$plan);});if(!principal($settings,'receiver_admin')){receiverDenied();}receiverSaveWitness($settings,$plan,'committed');return true;
    });
}
