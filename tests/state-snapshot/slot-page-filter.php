<?php
declare(strict_types=1);
require __DIR__.'/support.php';
$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer,string $dir):void{
    foreach([[1,'owner-a',null],[2,'owner-b',''],[3,"owner-a\0tail",null],[4,'owner-a',null],[5,'owner-a',null],[6,'owner-b',null]] as $row){snapshotInsert($pdo,'tenant',$row[0],"a\0b",$row[2],$row[1]);}
    $source=snapshotSource($pdo);$digest=$source->digest();$request=['table'=>'snapshot_test','key'=>['scope'=>'tenant'],'columns'=>['id','tag'],'page'=>true,'maximum'=>2,'after'=>null,'filter'=>['tag'=>'owner-a','password'=>null]];
    $view=$source->capture(['owned'=>$request,'all'=>['table'=>'snapshot_test','key'=>['scope'=>'tenant'],'columns'=>[],'count'=>true]]);Check::same($digest,$view->digest());Check::same(['count'=>6],$view->row('all'));$page=$view->page('owned');Check::same(3,$page['total']);Check::same([1,4],array_column($page['rows'],'id'));Check::same(true,$page['more']);Check::same(['scope'=>'tenant','id'=>4],$page['cursor']);
    $request['after']=$page['cursor'];$next=$source->capture(['owned'=>$request])->page('owned');Check::same([5],array_column($next['rows'],'id'));Check::same(false,$next['more']);Check::same(3,$next['total']);
    $request['after']=['scope'=>'tenant','id'=>2];snapshotReason('account.snapshot_cursor',static function()use($source,$request):void{$source->capture(['owned'=>$request]);});
    $request['after']=null;$request['filter']=['tag'=>"owner-a\0tail"];Check::same([3],array_column($source->capture(['owned'=>$request])->page('owned')['rows'],'id'));
    $restricted=snapshotSource($pdo,32,1000,['scope'=>'tenant','tag'=>'owner-a']);$request['filter']=['tag'=>'owner-a'];Check::same(3,$restricted->capture(['owned'=>$request])->page('owned')['total']);
    $queries=$pdo->queries;
    foreach([['id'=>1],['unknown'=>'x'],['tag'=>[]],['password'=>str_repeat('x',4097)],['tag'=>null],['tag'=>'owner-a','body'=>'','password'=>null,'id'=>1,'scope'=>'tenant']] as $filter){$request['filter']=$filter;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($source,$request):void{$source->capture(['owned'=>$request]);});Check::same($queries,$pdo->queries);}
});
echo 'PASS same-snapshot owned-slot filters: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
