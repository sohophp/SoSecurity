<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
use SoSecurity\Outbox\State;
use SoSecurity\Outbox\Policy;
$mysql=($argv[1] ?? '')==='mysql';
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$e->append($s,$e->message('seed',''));$raw=$e->rows()[0];$namespace=$raw['namespace'];unset($raw['payload_body']);$template=State::record($raw+['body_length'=>0],$e->keys,$e->policy,$namespace,$e->epoch,'tenant','orders',$e->clock->time);unset($template['body_length']);$root=State::root($e->pdo->query('SELECT * FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC),$e->keys,$e->policy,$namespace,$e->epoch,$e->clock->time);$fields=array_merge(State::recordFields(),['payload_body']);
    $e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');
    try{
        $e->pdo->exec('DELETE FROM sosecurity_outbox_records');$q=$e->pdo->prepare('INSERT INTO sosecurity_outbox_records('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')');
        // Authenticated synthetic queue data exercises real history validation; no remote business is claimed.
        for($i=1;$i<=10000;++$i){$row=$template;$id=SoSecurity\Outbox\Message::identifier('indexed-'.$i,$e->clock->time);$row['message_id']=$id;$row['key_hash']=hash('sha256',$id);$row['delivery_id']=State::delivery($namespace,$id);$row['order_no']=$i;$row['aggregate_id']='bulk-'.$i;$row['aggregate_hash']=State::aggregate($row['aggregate_id']);$row['fingerprint']=State::fingerprint('tenant','orders',$id,$row['destination'],$row['topic'],$row['aggregate_id'],0,$row['payload_digest']);$row=State::seal($row,$e->keys,false);foreach($row as $name=>$value){$q->bindValue(':'.$name,$value,is_int($value)?PDO::PARAM_INT:PDO::PARAM_STR);}$q->bindValue(':payload_body','',PDO::PARAM_LOB);$q->execute();$q->closeCursor();}
        $hash=hash_init('sha256');hash_update($hash,State::historyPrefix($namespace));$q=$e->pdo->query('SELECT key_hash,order_no,seal FROM sosecurity_outbox_records ORDER BY sosecurity_outbox_records.key_hash');while($row=$q->fetch(PDO::FETCH_ASSOC)){hash_update($hash,json_encode([$row['key_hash'],(int)$row['order_no'],$row['seal']]));}$q->closeCursor();$root['entries']=10000;$root['last_order']=10000;$root['history_digest']=hash_final($hash);++$root['revision'];$root=State::seal($root,$e->keys,true);$q=$e->pdo->prepare('UPDATE sosecurity_outbox_roots SET '.implode(',',array_map(static function(string $name):string{return $name.'=:'.$name;},State::rootFields())));$q->execute($root);$q->closeCursor();$e->pdo->exec('COMMIT');
    }catch(Throwable $error){$e->pdo->exec('ROLLBACK');throw $error;}
    $history=null;$e->pdo->beforeStatement=static function(string $sql)use(&$history):void{if($history===null&&strpos($sql,' AS body_length FROM ')!==false&&strpos($sql,' WHERE namespace=:namespace ORDER BY ')!==false){$history=$sql;}};
    $page=$s->candidates('tenant','orders','reader',1);$e->pdo->beforeStatement=null;Check::same(1,count($page['records']));Check::same(false,$page['complete']);Check::same(10000,$e->count());Check::same(true,is_string($history));
    $q=$e->pdo->prepare(($e->mysql?'EXPLAIN ':'EXPLAIN QUERY PLAN ').$history);$q->execute(['namespace'=>$namespace]);$plan=$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();$encoded=strtoupper(json_encode($plan));Check::same(false,strpos($encoded,$e->mysql?'FILESORT':'TEMP B-TREE')!==false);
    if(!$e->mysql){$old=preg_replace('/ORDER BY main\.sosecurity_outbox_records\.key_hash/','ORDER BY key_hash',$history);$q=$e->pdo->prepare('EXPLAIN QUERY PLAN '.$old);$q->execute(['namespace'=>$namespace]);Check::same(true,strpos(strtoupper(json_encode($q->fetchAll(PDO::FETCH_ASSOC))),'TEMP B-TREE')!==false);$q->closeCursor();}
    Check::same(true,memory_get_peak_usage(true)<8388608);
},new Policy(['maximum_entries'=>100000,'io_milliseconds'=>30000]));
echo 'PASS SQL Outbox indexed history: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; 10000 authenticated synthetic rows, real candidate/root validation and no temporary history sort under memory_limit=8M\n";
