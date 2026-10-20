<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
// Private SQLite only. SQL constructs oversized values without allocating them in PHP first.
foreach(['zeroblob(16777216)',"CAST(payload||x'00'||zeroblob(16777216) AS TEXT)",'CAST(payload AS TEXT)'] as $expression){inboxCase(false,static function(InboxEnvironment $e)use($expression):void{
    $e->pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-sqlite.sql'));
    $receipt=$e->receive();$e->pdo->exec('UPDATE sosecurity_webhook_inbox SET payload='.$expression);
    $processor=new SoSecurity\Webhook\SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,static function(string $body):SoSecurity\Webhook\Message{
        $data=json_decode($body,true);return new SoSecurity\Webhook\Message($data['id'],$data['type'],$data['resource'],['version'=>$data['version']]);
    },static function():bool{return true;},static function():bool{return true;},null,$e->clock);
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($processor,$receipt):void{$processor->claim($receipt->id(),'worker');});
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($e):void{$e->receive();});
    Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn());
    Check::same(1,$e->count());Check::same(true,memory_get_peak_usage(true)<8388608);
});}
echo 'PASS SQL webhook BLOB bound: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; oversized BLOB/NUL-containing TEXT rejected under memory_limit=8M\n";
