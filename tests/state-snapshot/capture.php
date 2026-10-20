<?php
declare(strict_types=1);
require __DIR__.'/support.php';$mysql=($argv[1]??'')==='mysql';
function captureSelect(int $id=1,array $columns=['tag','password','body'],string $scope='tenant'):array{return ['table'=>'snapshot_test','key'=>['scope'=>$scope,'id'=>$id],'columns'=>$columns];}
snapshotCase($mysql,static function(InboxTestConnection $pdo):void{
    $secret="owned-private-capture-49\0secret";snapshotInsert($pdo,'tenant',1,"a\0b",$secret);snapshotInsert($pdo,'other',1,'foreign');
    $s=snapshotSource($pdo,32,1000,['scope'=>'tenant']);$before=$s->digest();$selects=0;
    $pdo->beforeStatement=static function(string $sql)use(&$selects):void{if(strpos($sql,'__sw_valid')!==false){++$selects;}};
    $capture=$s->capture(['actor'=>captureSelect(),'missing'=>captureSelect(2),'foreign'=>captureSelect(1,['tag'],'other')]);$pdo->beforeStatement=null;
    Check::same(1,$selects);Check::same($before,$capture->digest());Check::same(true,$capture->matches($s));Check::same(false,$capture->matches(snapshotSource($pdo,32,1000,['scope'=>'tenant'])));
    Check::same(['tag'=>'owned','password'=>$secret,'body'=>"a\0b"],$capture->row('actor'));Check::same(null,$capture->row('missing'));Check::same(null,$capture->row('foreign'));
    $copy=$capture->row('actor');$copy['tag']='caller-edit';Check::same('owned',$capture->row('actor')['tag']);
    $pdo->exec("UPDATE snapshot_test SET tag='new' WHERE scope='tenant'");Check::same('owned',$capture->row('actor')['tag']);Check::same($before,$capture->digest());Check::same(false,$before===$s->digest());
    foreach([var_export($capture,true),print_r($capture,true),json_encode($capture)] as $dump){Check::same(false,strpos($dump,'owned-private-capture')!==false);}
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($capture):void{serialize($capture);});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($capture):void{$capture->unknown='changed';});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($capture):void{$capture->row('unknown');});
});
snapshotCase($mysql,static function(InboxTestConnection $pdo):void{
    snapshotInsert($pdo,"a\0\xff",1,'',null);$s=snapshotSource($pdo);$scope="a\0\xff";$column='body';$v=captureSelect(1,[$column],$scope);$v['key']['scope']=&$scope;$v['columns'][0]=&$column;
    $c=$s->capture(['binary'=>$v,'null_value'=>captureSelect(1,['password'],$scope)]);$scope='foreign';$column='tag';
    Check::same(['body'=>''],$c->row('binary'));Check::same(['password'=>null],$c->row('null_value'));
    Check::same($s->digest(),$c->digest());
});
snapshotCase($mysql,static function(InboxTestConnection $pdo):void{
    $s=snapshotSource($pdo,1048576);$bad=[[],array_fill_keys(range(0,8),captureSelect())];
    foreach([['key'=>['id'=>1]],['key'=>['scope'=>'tenant','id'=>'1']],['key'=>['scope'=>'tenant','id'=>-1]],['table'=>'missing'],['columns'=>['missing']],['columns'=>['tag','tag']],['columns'=>['body']],['columns'=>[]],['extra'=>true]] as $change){$v=captureSelect();foreach($change as $k=>$value){$v[$k]=$value;}$bad[]=['actor'=>$v];}
    $bad[]=['actor'=>new class{public function __toString():string{throw new RuntimeException('No selector object hooks.');}}];
    foreach($bad as $selectors){$queries=$pdo->queries;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s,$selectors):void{$s->capture($selectors);});Check::same($queries,$pdo->queries);}
    snapshotInsert($pdo,'tenant',1,'');$c=$s->capture(['actor'=>captureSelect(1,['tag'])]);Check::same(['tag'=>'owned'],$c->row('actor'));
    $pdo->exec('BEGIN');try{$pdo->exec("UPDATE snapshot_test SET tag='host-uncommitted'");Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s):void{$s->capture(['actor'=>captureSelect(1,['tag'])]);});Check::same('host-uncommitted',$pdo->query('SELECT tag FROM snapshot_test')->fetchColumn());}finally{$pdo->exec('ROLLBACK');}Check::same('owned',$pdo->query('SELECT tag FROM snapshot_test')->fetchColumn());
});
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer)use($mysql):void{
    for($i=1;$i<=70;++$i){snapshotInsert($pdo,'tenant',$i,"old\0generation");}
    if(!$mysql){$observer->exec('PRAGMA busy_timeout=1');}$s=snapshotSource($pdo);$before=$s->digest();$pages=0;$changed=false;$blocked=false;
    $change=static function()use($observer):void{$observer->beginTransaction();try{$observer->exec("UPDATE snapshot_test SET tag='new-generation' WHERE id IN(1,70)");snapshotInsert($observer,'tenant',71,'next');$observer->commit();}catch(Throwable $e){$observer->rollBack();throw $e;}};
    $pdo->beforeStatement=static function(string $sql)use(&$pages,&$changed,&$blocked,$change,$mysql):void{
        if(strpos($sql,'__sw_valid')===false||++$pages!==2){return;}
        try{$change();$changed=true;}catch(PDOException $e){if($mysql||(int)$e->errorInfo[1]!==5){throw $e;}$blocked=true;}
    };
    $c=$s->capture(['first'=>captureSelect(1,['tag']),'last'=>captureSelect(70,['tag']),'next'=>captureSelect(71,['tag'])]);$pdo->beforeStatement=null;
    Check::same(2,$pages);Check::same($mysql,$changed);Check::same(!$mysql,$blocked);Check::same($before,$c->digest());
    Check::same(['tag'=>'owned'],$c->row('first'));Check::same(['tag'=>'owned'],$c->row('last'));Check::same(null,$c->row('next'));
    if(!$mysql){$change();}Check::same(false,$before===$s->digest());Check::same(['tag'=>'owned'],$c->row('last'));
});
if(!$mysql){snapshotCase(false,static function(InboxTestConnection $pdo):void{
    snapshotInsert($pdo,'tenant',1,'');snapshotInsert($pdo,'tenant',2,'');$s=snapshotSource($pdo);
    $pdo->exec("UPDATE snapshot_test SET tag=CAST('x'||x'00'||zeroblob(16777216) AS TEXT) WHERE id=2");
    snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->capture(['actor'=>captureSelect(1,['tag'])]);});
    Check::same('8M',ini_get('memory_limit'));Check::same(true,memory_get_peak_usage(false)<8388608);
});}
snapshotCase($mysql,static function(InboxTestConnection $pdo):void{
    $body="\0".str_repeat('x',65534)."\0";snapshotInsert($pdo,'tenant',1,$body);$s=snapshotSource($pdo,65536);$selectors=[];
    foreach(['a','b','c','d'] as $alias){$selectors[$alias]=captureSelect(1,['body']);}
    $c=$s->capture($selectors);Check::same($s->digest(),$c->digest());foreach(array_keys($selectors) as $alias){Check::same($body,$c->row($alias)['body']);}
    $selectors['e']=captureSelect(1,['body']);$queries=$pdo->queries;
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s,$selectors):void{$s->capture($selectors);});Check::same($queries,$pdo->queries);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s):void{$s->capture(['actor'=>captureSelect(1,['body','tag'])]);});Check::same($queries,$pdo->queries);
    $selectors=[];foreach(['a','b','c','d','e','f','g','h'] as $alias){$selectors[$alias]=captureSelect(1,['id']);}
    $c=$s->capture($selectors);Check::same(['id'=>1],$c->row('h'));Check::same(true,memory_get_peak_usage(false)<8388608);
});
echo 'PASS same-generation SQL state capture: '.Check::$assertions.' assertions '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; bounded selectors, exact hashed bytes, missing/filtered rows, NULL/empty/NUL, independent concurrent writer and no permission capability\n";
