<?php
declare(strict_types=1);
require __DIR__.'/support.php';
if(getenv('SOSECURITY_SLOT_PAGE_REREAD')){$loader=require dirname(__DIR__,2).'/vendor/autoload.php';$loader->addClassMap(['SoSecurity\Account\SqlStateSnapshot'=>getenv('SOSECURITY_SLOT_PAGE_REREAD')]);}
$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer,string $dir):void{
    snapshotInsert($pdo,'tenant',1,'',null,'denied');$pdo->exec('DROP TABLE IF EXISTS slot_page_business');$pdo->exec('CREATE TABLE slot_page_business(id INTEGER NOT NULL PRIMARY KEY)'.($pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql'?' ENGINE=InnoDB':''));
    try{
        $source=snapshotSource($pdo);$approved=$source->digest();$commits=0;
        $pdo->afterCommit=static function()use($pdo,$observer,&$commits):void{
            ++$commits;$pdo->afterCommit=null;$observer->exec("UPDATE snapshot_test SET tag='allowed' WHERE scope='tenant' AND id=1");
            $pdo->afterCommit=static function()use($pdo,$observer,&$commits):void{++$commits;$pdo->afterCommit=null;$observer->exec("UPDATE snapshot_test SET tag='denied' WHERE scope='tenant' AND id=1");};
        };
        $selector=['table'=>'snapshot_test','key'=>['scope'=>'tenant'],'columns'=>['tag'],'page'=>true,'maximum'=>1,'after'=>null];$view=$source->capture(['slots'=>$selector]);$fresh=$source->digest();$row=$view->page('slots')['rows'][0];
        // Representative pinned-authority decision: a separate re-read can splice
        // allowed data into an old denied digest, even when a final digest matches again.
        if($view->digest()===$approved&&$fresh===$approved&&$row['tag']==='allowed'){$observer->exec('INSERT INTO slot_page_business VALUES(1)');}
        $effects=(int)$observer->query('SELECT COUNT(*) FROM slot_page_business')->fetchColumn();if($effects!==0){throw new RuntimeException('UNSAFE_SLOT_PAGE_REREAD_PERMISSION_WRITE');}
        Check::same(0,$effects);Check::same('denied',$row['tag']);Check::same($approved,$view->digest());Check::same($approved,$source->digest());Check::same(2,$commits);Check::same('denied',$observer->query('SELECT tag FROM snapshot_test')->fetchColumn());
    }finally{$pdo->afterCommit=null;$pdo->exec('DROP TABLE slot_page_business');}
});
echo 'PASS atomic slot-page metadata across committed ABA changes: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
