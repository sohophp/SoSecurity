<?php
declare(strict_types=1);
require __DIR__.'/support.php';$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer):void{
    snapshotInsert($pdo,'tenant',1,'',null,'approved-generation');$s=snapshotSource($pdo);$approved=$s->digest();$changed=false;
    $pdo->afterCommit=static function()use($observer,&$changed):void{if(!$changed){$changed=true;$observer->exec("UPDATE snapshot_test SET tag='later-generation'");}};
    try{$c=$s->capture(['actor'=>['table'=>'snapshot_test','key'=>['scope'=>'tenant','id'=>1],'columns'=>['tag']]]);}finally{$pdo->afterCommit=null;}
    Check::same(true,$changed);Check::same($approved,$c->digest());Check::same('later-generation',$observer->query('SELECT tag FROM snapshot_test')->fetchColumn());
    if($c->row('actor')!==['tag'=>'approved-generation']){throw new RuntimeException('UNSAFE_SQL_CAPTURE_RETURNED_NEW_ROWS_WITH_OLD_DIGEST');}
    Check::same(['tag'=>'approved-generation'],$c->row('actor'));Check::same(false,$approved===$s->digest());
});
echo 'PASS post-commit capture isolation: '.Check::$assertions.' assertions '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; independent writer advances immediately after snapshot COMMIT, captured permission bytes still match the original full digest\n";
