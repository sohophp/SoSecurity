<?php
declare(strict_types=1);
require __DIR__.'/support.php';
$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer,string $root)use($mysql):void{
    mkdir($root.'/state',0700);mkdir($root.'/scratch',0700);$pdo->exec('DROP TABLE IF EXISTS snapshot_example');
    $pdo->exec(file_get_contents(dirname(__DIR__,2).'/resources/sql/state-snapshot-example-'.($mysql?'mysql':'sqlite').'.sql'));
    try{
    $pdo->exec("INSERT INTO snapshot_example VALUES('tenant','demo',1)");
    $store=new SoSecurity\Storage\FileStore($root.'/state','example-store');$store->transact('session',static function():SoSecurity\Storage\Change{return new SoSecurity\Storage\Change(['binary'=>"a\0b"],0,true);});
    $build=require dirname(__DIR__,2).'/examples/state-snapshot.php';$queries=$pdo->queries;$snapshot=$build($pdo,$store,$root.'/state',$root.'/scratch');Check::same($queries,$pdo->queries);
    $before=file_get_contents($root.'/state/'.$store->snapshotFile('session'));$capture=$snapshot->capture([
        'accounts'=>['account'=>['table'=>'snapshot_example','key'=>['scope'=>'tenant','subject'=>'demo'],'columns'=>['enabled']]],
        'files'=>['session'=>$store->snapshotFile('session')],
    ]);
    Check::same(['enabled'=>1],$capture->part('accounts')->row('account'));Check::same($before,$capture->part('files')->file('session'));Check::same($snapshot->digest(),$capture->digest());Check::same($before,file_get_contents($root.'/state/'.$store->snapshotFile('session')));
    $other=new SoSecurity\Storage\FileStore($root.'/state','different-namespace');Check::same($store->snapshotBinding(),$other->snapshotBinding());Check::same(false,$store->snapshotReference('session')===$other->snapshotReference('session'));
    }finally{$pdo->exec('DROP TABLE snapshot_example');}
});
echo 'PASS portable read-only snapshot example: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
