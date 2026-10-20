<?php
declare(strict_types=1);
require __DIR__.'/support.php';
function boundedSlotPage():array{return ['table'=>'snapshot_test','key'=>['scope'=>'tenant'],'columns'=>['id','body'],'page'=>true,'maximum'=>2,'after'=>null];}
$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer,string $dir):void{
    snapshotInsert($pdo,'tenant',1,"a\0b");$source=snapshotSource($pdo);$bad=[];
    foreach([0,9,'2',1.5] as $limit){$v=boundedSlotPage();$v['maximum']=$limit;$bad[]=$v;}
    foreach([false,1] as $flag){$v=boundedSlotPage();$v['page']=$flag;$bad[]=$v;}
    foreach([[],['scope'=>'other','id'=>1],['scope'=>'tenant'],['scope'=>'tenant','id'=>-1],['scope'=>'tenant','id'=>1,'extra'=>0],'cursor'] as $cursor){$v=boundedSlotPage();$v['after']=$cursor;$bad[]=$v;}
    $v=boundedSlotPage();$v['count']=true;$bad[]=$v;$v=boundedSlotPage();unset($v['after']);$bad[]=$v;$v=boundedSlotPage();$v['key']=[];$bad[]=$v;
    $queries=$pdo->queries;foreach($bad as $v){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($source,$v):void{$source->capture(['slots'=>$v]);});Check::same($queries,$pdo->queries);}
    $large=snapshotSource($pdo,32768);$v=boundedSlotPage();$v['columns']=['body'];$v['maximum']=8;$queries=$pdo->queries;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($large,$v):void{$large->capture(['slots'=>$v]);});Check::same($queries,$pdo->queries);$v['maximum']=7;Check::same(7,$large->capture(['slots'=>$v])->page('slots')['limit']);
    $view=$source->capture(['slots'=>boundedSlotPage()]);$page=$view->page('slots');$variants=[];$v=$page;$v['total']=-1;$variants[]=$v;$v=$page;$v['limit']=9;$variants[]=$v;$v=$page;$v['more']=true;$variants[]=$v;$v=$page;$v['cursor']=null;$variants[]=$v;$v=$page;$v['rows'][0]['bad']=[];$variants[]=$v;$v=$page;$v['cursor']['id']=-1;$variants[]=$v;
    foreach($variants as $v){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($source,$view,$v):void{new SoSecurity\Account\SqlStateCapture($source,$view->digest(),[],['slots'=>$v]);});}
    $restricted=snapshotSource($pdo,32,1000,['scope'=>'tenant','tag'=>'tag']);$queries=$pdo->queries;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($restricted):void{$restricted->capture(['slots'=>boundedSlotPage()]);});Check::same($queries,$pdo->queries);
});
echo 'PASS slot-page selection and byte bounds: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
