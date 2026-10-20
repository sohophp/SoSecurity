<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/address-change-support.php';
$socket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));if($socket!==''){if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected an owned disposable test database.');}$GLOBALS['registrationMySQLSocket']=$socket;}
use SoSecurity\Account\AddressChange;
use SoSecurity\Account\Ledger;
use SoSecurity\Account\Notifications;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlSchema;

function familyNamespace():string {$site=hash('sha256',json_encode(['SoSecurity.Account.AddressChange.1','account-test'],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));return hash('sha256',json_encode(['SoSecurity.Account.Ledger.1',$site,'tenant',str_repeat('e',64)],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
function privateSnapshot(ChangeEnvironment $t,string $namespace=''):array {$namespace=$namespace===''?familyNamespace():$namespace;$q=$t->e->pdo->prepare('SELECT * FROM sosecurity_account_roots WHERE namespace=:namespace');$q->execute(['namespace'=>$namespace]);$root=$q->fetch(PDO::FETCH_ASSOC);$q=$t->e->pdo->prepare('SELECT * FROM sosecurity_account_records WHERE namespace=:namespace ORDER BY record_id');$q->execute(['namespace'=>$namespace]);return ['root'=>$root,'rows'=>$q->fetchAll(PDO::FETCH_ASSOC)];}
function restorePrivate(ChangeEnvironment $t,array $snapshot):void
{
    $pdo=$t->e->pdo;$q=$pdo->prepare('DELETE FROM sosecurity_account_records WHERE namespace=:namespace');$q->execute(['namespace'=>$snapshot['root']['namespace']]);
    $types=Ledger::recordTypes();$fields=array_keys($types);
    foreach($snapshot['rows'] as $row){$q=$pdo->prepare('INSERT INTO sosecurity_account_records('.implode(',',$fields).') VALUES(:'.implode(',:',$fields).')');foreach($fields as $field){$value=$types[$field]==='int'?SqlSchema::integer($row[$field]):$row[$field];$q->bindValue(':'.$field,$value,$field==='payload'?PDO::PARAM_LOB:($types[$field]==='int'?PDO::PARAM_INT:PDO::PARAM_STR));}$q->execute();}
    $types=Ledger::rootTypes();$q=$pdo->prepare('UPDATE sosecurity_account_roots SET '.implode(',',array_map(static function(string $field):string{return $field.'=:'.$field;},array_diff(array_keys($types),['namespace']))).' WHERE namespace=:namespace');
    foreach($types as $field=>$type){$q->bindValue(':'.$field,$type==='int'?SqlSchema::integer($snapshot['root'][$field]):$snapshot['root'][$field],$type==='int'?PDO::PARAM_INT:PDO::PARAM_STR);}$q->execute();
}
changeCase(static function(ChangeEnvironment $t):void{
    $t->request();$before=privateSnapshot($t);$t->e->clock->time+=172800;$t->onManager=static function(string $action,string $phase)use($t,$before):bool{if($action==='maintain'&&$phase==='commit'){restorePrivate($t,$before);}return true;};
    Check::throws(StorageException::class,static function()use($t):void{$t->service->maintain(50);});Check::same($before,privateSnapshot($t));Check::same(3,$t->count());
});
function maintenanceService(ChangeEnvironment $t,bool $old=true,?callable $manager=null):AddressChange
{
    $e=$t->e;$keys=$old?['account'=>str_repeat('a',32),'next'=>str_repeat('n',32)]:['next'=>str_repeat('n',32)];$cipher=$old?['mail'=>str_repeat('m',32),'next'=>str_repeat('z',32)]:['next'=>str_repeat('z',32)];$guard=static function():bool{return true;};
    return new AddressChange($e->pdo,'account-test','tenant',str_repeat('e',64),new HmacKeys('next',$keys),new HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$e->accounts,new Notifications('next',$cipher,$e->clock),$t->sessions,$t->grants,$guard,$guard,$e->policy,$e->clock,$manager ?? $guard,$guard);
}
function rotateAll(AddressChange $service,int $limit=1):array
{
    $after='';$counts=['resealed'=>0,'reencrypted'=>0,'recipient_tags'=>0,'root_rotated'=>0];$rounds=0;
    do{$page=$service->rotate($limit,$after);foreach($counts as $name=>$value){$counts[$name]+=(int)$page[$name];}$after=$page['after'];if(++$rounds>30){throw new RuntimeException('Unexpected unbounded maintenance scan.');}}while(!$page['done']);return $counts;
}
function commitChange(ChangeEnvironment $t):string
{
    $d=$t->ready();$selector=$d['verify_address_old']->selector();$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);
    if(!$t->service->complete($t->subject,$selector,$t->credential->token(),$grant,'ip')){throw new RuntimeException('Expected the owned address change to commit.');}return $selector;
}
changeCase(static function(ChangeEnvironment $t):void{
    $q=$t->e->pdo->query("SELECT namespace FROM sosecurity_account_records WHERE kind='register'");$namespace=$q->fetchColumn();$before=privateSnapshot($t,$namespace);$t->e->clock->time+=172801;$t->e->onManagement=static function(string $action,string $phase)use($t,$before):bool{if($action==='maintain'&&$phase==='commit'){restorePrivate($t,$before);}return true;};$registration=$t->e->service();
    Check::throws(StorageException::class,static function()use($registration):void{$registration->maintain(50);});Check::same($before,privateSnapshot($t,$namespace));Check::same(4,count($before['rows']));
});
changeCase(static function(ChangeEnvironment $t):void{
    $namespace=$t->e->pdo->query("SELECT namespace FROM sosecurity_account_records WHERE kind='register'")->fetchColumn();$before=privateSnapshot($t,$namespace);
    $t->e->onManagement=static function(string $action,string $phase)use($t,$before):bool{if($action==='rotate'&&$phase==='commit'){restorePrivate($t,$before);}return true;};
    $r=$t->e->service(null,null,'tenant','',new HmacKeys('next',['account'=>str_repeat('a',32),'next'=>str_repeat('n',32)]),new Notifications('next',['mail'=>str_repeat('m',32),'next'=>str_repeat('z',32)],$t->e->clock));
    Check::throws(StorageException::class,static function()use($r):void{$r->rotate(50);});Check::same($before,privateSnapshot($t,$namespace));Check::same(0,$t->count());
});
changeCase(static function(ChangeEnvironment $t):void{
    $t->request();$before=privateSnapshot($t);$t->e->clock->time+=172800;$t->onManager=static function(string $action,string $phase):bool{return $action!=='maintain'||$phase!=='commit';};
    Check::throws(SecurityException::class,static function()use($t):void{$t->service->maintain(50);});Check::same($before,privateSnapshot($t));$t->onManager=null;Check::same(5,$t->service->maintain(50)['removed']);
});
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->request();$before=$t->e->account();$notices=$t->e->pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC);$t->e->clock->time+=172800;$after='';$removed=0;$rounds=0;
    do{$page=$t->service->maintain(1,$after);Check::same(true,$page['removed']<=2);$removed+=$page['removed'];$after=$page['after'];if(++$rounds>10){throw new RuntimeException('Cleanup did not finish.');}}while(!$page['done']);
    Check::same(5,$removed);Check::same(0,count(privateSnapshot($t)['rows']));Check::same($before,$t->e->account());Check::same($notices,$t->e->pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC));Check::same(null,$t->service->notification($d['verify_address_new']->notice()->id()));Check::same(0,$t->service->maintain()['removed']);
    $t->login();$next=$t->request();Check::same(3,count($next));Check::same(5,count(privateSnapshot($t)['rows']));
});
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->request();$old=$d['verify_address_old']->selector();$retire=privateSnapshot($t)['root']['observed_at'];$q=$t->e->pdo->prepare('SELECT retire_at FROM sosecurity_account_records WHERE record_id=:id');$q->execute(['id'=>$old]);$retire=SqlSchema::integer($q->fetchColumn());
    $t->e->clock->time=$retire-900;$t->login();$next=$t->request('latest@example.com');$selector=$next['verify_address_old']->selector();$t->e->clock->time=$retire;Check::same(4,$t->service->maintain(50)['removed']);Check::same(5,count(privateSnapshot($t)['rows']));Check::same(false,$t->service->confirm($old,'old',$d['verify_address_old']->notice()->token(),'ip'));Check::same('pending',$t->flow($selector)['state']);Check::same(true,$t->service->confirm($selector,'new',$next['verify_address_new']->notice()->token(),'ip'));
});
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->request();$selector=$d['verify_address_old']->selector();$old=$t->flow($selector);$account=$t->e->account();$queue=$t->e->pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC);$rotator=maintenanceService($t);$counts=rotateAll($rotator);
    Check::same(5,$counts['resealed']);Check::same(3,$counts['reencrypted']);Check::same(0,$counts['recipient_tags']);Check::same(1,$counts['root_rotated']);$only=maintenanceService($t,false);
    Check::same($old,$t->flow($selector));Check::same($account,$t->e->account());Check::same($queue,$t->e->pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC));Check::same($d['verify_address_new']->notice()->token(),$only->notification($d['verify_address_new']->notice()->id())->notice()->token());
    Check::throws(StorageException::class,static function()use($t,$d):void{$t->service->notification($d['verify_address_new']->notice()->id());});Check::same(0,rotateAll($only)['resealed']);
    $t->service=$only;foreach(['old','new'] as $side){Check::same(true,$only->confirm($selector,$side,$d['verify_address_'.$side]->notice()->token(),'ip'));}
    $intent=$only->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);Check::same(true,$only->complete($t->subject,$selector,$t->credential->token(),$grant,'ip'));Check::same('new@example.com',$t->e->account()['address']);
});
changeCase(static function(ChangeEnvironment $t):void{
    $selector=commitChange($t);$before=$t->flow($selector);$account=$t->e->account();$queue=$t->e->pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC);$counts=rotateAll(maintenanceService($t));
    Check::same(7,$counts['resealed']);Check::same(5,$counts['reencrypted']);Check::same(2,$counts['recipient_tags']);$only=maintenanceService($t,false);$flow=$t->flow($selector);Check::same('next',$flow['success']['old']['key_id']);Check::same(false,$flow['success']['old']['recipient_tag']===$before['success']['old']['recipient_tag']);
    Check::same('owner@example.com',$only->notification($flow['success']['old']['notice_id'])->notice()->recipient()->value());Check::same('new@example.com',$only->notification($flow['success']['new']['notice_id'])->notice()->recipient()->value());Check::same($account,$t->e->account());Check::same($queue,$t->e->pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC));Check::same(0,rotateAll($only)['resealed']);
});
changeCase(static function(ChangeEnvironment $t):void{
    $selector=commitChange($t);$unit=new SoSecurity\Support\SqlTransaction($t->e->pdo,$t->e->clock,10000);$site=hash('sha256',json_encode(['SoSecurity.Account.AddressChange.1','account-test'],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));$ledger=new Ledger($unit,$site,'tenant',str_repeat('e',64),new HmacKeys('account',['account'=>str_repeat('a',32)]),$t->e->policy);
    $unit->run(static function()use($ledger,$selector):void{$row=$ledger->read($selector);$flow=json_decode($row['payload'],true,6);$flow['success']['old']['recipient_tag']=str_repeat('0',64);$ledger->put($selector,$row['owner'],'change',json_encode($flow,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),$row['retire_at'],$row['revision']);});
    $before=privateSnapshot($t);$id=$t->flow($selector)['success']['old']['notice_id'];Check::throws(StorageException::class,static function()use($t,$id):void{$t->service->notification($id);});$rotator=maintenanceService($t);Check::throws(StorageException::class,static function()use($rotator):void{$rotator->rotate(50);});Check::same($before,privateSnapshot($t));
});
changeCase(static function(ChangeEnvironment $t):void{
    $selector=commitChange($t);$before=$t->flow($selector);$t->e->clock->time+=86401;$counts=rotateAll(maintenanceService($t));Check::same(5,$counts['reencrypted']);Check::same(0,$counts['recipient_tags']);$only=maintenanceService($t,false);
    Check::same($before['success'],$t->flow($selector)['success']);Check::same(null,$only->notification($before['success']['old']['notice_id']));Check::same(5,$only->maintain(50)['removed']);Check::same(2,count(privateSnapshot($t)['rows']));$t->e->clock->time+=1800;Check::same(2,$only->maintain(50)['removed']);Check::same(0,count(privateSnapshot($t)['rows']));
});
foreach(['maintain','rotate'] as $method){changeCase(static function(ChangeEnvironment $t)use($method):void{
    $t->request();$before=privateSnapshot($t);$manager=static function(string $action,string $phase)use($t,$before,$method):bool{if($action===$method&&$phase==='commit'){restorePrivate($t,$before);}return true;};$service=maintenanceService($t,true,$manager);if($method==='maintain'){$t->e->clock->time+=172800;}
    Check::throws(StorageException::class,static function()use($service,$method):void{$service->$method(50);});Check::same($before,privateSnapshot($t));Check::same(3,$t->count());
});}
foreach(['maintain','rotate'] as $method){changeCase(static function(ChangeEnvironment $t)use($method):void{
    $t->request();$before=privateSnapshot($t);$t->onManager=static function(string $action,string $phase)use($t,$method):bool{if($action===$method&&$phase==='commit'){$q=$t->e->pdo->prepare('UPDATE sosecurity_account_records SET payload=:payload WHERE namespace=:namespace');$q->bindValue(':payload',str_repeat('x',strlen(privateSnapshot($t)['rows'][0]['payload'])),PDO::PARAM_LOB);$q->bindValue(':namespace',familyNamespace());$q->execute();}return true;};
    Check::throws(StorageException::class,static function()use($t,$method):void{$t->service->$method(50);});Check::same($before,privateSnapshot($t));
});}
changeCase(static function(ChangeEnvironment $t):void{
    $s=$t->build(false);$queries=$t->e->pdo->queries;Check::throws(SecurityException::class,static function()use($s):void{$s->maintain();});Check::throws(SecurityException::class,static function()use($s):void{$s->rotate();});Check::same($queries,$t->e->pdo->queries);
    foreach([[0,''],[51,''],[1,'bad']] as $args){foreach(['maintain','rotate'] as $method){Check::throws(ConfigurationException::class,static function()use($s,$method,$args):void{$s->$method($args[0],$args[1]);});}}Check::same($queries,$t->e->pdo->queries);
});
changeCase(static function(ChangeEnvironment $t):void{
    $t->request();$account=$t->e->account();$namespace=familyNamespace();$unit=new SoSecurity\Support\SqlTransaction($t->e->pdo,$t->e->clock,10000);$site=hash('sha256',json_encode(['SoSecurity.Account.AddressChange.1','account-test'],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));$ledger=new Ledger($unit,$site,'tenant',str_repeat('e',64),new HmacKeys('account',['account'=>str_repeat('a',32)]),$t->e->policy);
    $unit->run(static function()use($ledger):void{$ledger->put(hash('sha256','unknown-maintenance-record'),str_repeat('a',64),'recover','{}',100900);});$before=privateSnapshot($t);
    Check::throws(StorageException::class,static function()use($t):void{$t->service->maintain(50);});$rotator=maintenanceService($t);Check::throws(StorageException::class,static function()use($rotator):void{$rotator->rotate(50);});Check::same($before,privateSnapshot($t));Check::same($account,$t->e->account());
});
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->request();$account=$t->e->account();$q=$t->e->pdo->prepare('UPDATE sosecurity_account_records SET payload='.($t->e->mysql?'REPEAT(CHAR(0),2097152)':'zeroblob(16777216)').' WHERE record_id=:id');$q->execute(['id'=>$d['verify_address_old']->selector()]);$deletes=0;$t->e->pdo->beforeStatement=static function(string $sql)use(&$deletes):void{if(strpos($sql,'DELETE')===0){++$deletes;}};
    foreach(['maintain','rotate'] as $method){Check::throws(StorageException::class,static function()use($t,$method):void{$t->service->$method(50);});}Check::same(0,$deletes);Check::same($account,$t->e->account());Check::same(3,$t->count());Check::same(true,memory_get_peak_usage(true)<8388608);
});
echo 'PASS address-change maintenance: '.Check::$assertions.' assertions on '.($socket===''?'SQLite':'MySQL').' PHP '.PHP_VERSION."\n";
