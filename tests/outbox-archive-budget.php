<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-resolution-support.php';
use SoSecurity\Examples\Outbox as Resolution;
if(!function_exists('sodium_crypto_sign_detached')){if(getenv('SOSECURITY_REQUIRE_CRYPTO')==='1'){throw new RuntimeException('Required ext-sodium is missing.');}echo "NOT RUN native audit archive metadata budget: ext-sodium test environment required\n";return;}
nativeResolutionCase(static function(NativeResolutionEnvironment $e):void{
    $baseline=Resolution\resolutionAuditStatus($e->settings())['root_hash'];$e->configure(['resolution_archive'=>true]);Resolution\resolutionArchiveInitialize($e->settings(),$baseline);$before=Resolution\resolutionRead($e->settings());$pdo=$e->pdo();
    // Deliberately unauthenticated synthetic rows exercise metadata projection/capacity only.
    // No root is signed over them and no query may report a valid archived decision.
    $pdo->exec("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000) INSERT INTO outbox_example_resolution_archives SELECT 'o1.1.'||printf('%064x',i),CAST('{}' AS BLOB),'old',printf('%064x',0) FROM n");
    $s=$e->settings();$tracked=new InboxTestConnection('sqlite:'.$e->config['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$tracked->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$tracked]]);$s['pdo']=$tracked;$history=null;$tracked->beforeStatement=static function(string $sql)use(&$history):void{if($history===null&&strpos($sql,' FROM main.outbox_example_resolution_archives')!==false){$history=$sql;}};
    Check::same(100000,Resolution\resolutionHistory($s,true)['entries']);$tracked->beforeStatement=null;$plan=$tracked->query('EXPLAIN QUERY PLAN '.$history)->fetchAll(PDO::FETCH_ASSOC);Check::same(false,strpos(strtoupper(json_encode($plan)),'TEMP B-TREE')!==false);$old=str_replace('ORDER BY outbox_example_resolution_archives.event_id','ORDER BY event_id',$history);Check::same(true,strpos(strtoupper(json_encode($tracked->query('EXPLAIN QUERY PLAN '.$old)->fetchAll(PDO::FETCH_ASSOC))),'TEMP B-TREE')!==false);Check::same(true,memory_get_peak_usage(true)<8388608);nativeResolutionRefused(static function()use($e):void{Resolution\resolutionRoot($e->settings());});
    $pdo->exec("INSERT INTO outbox_example_resolution_archives VALUES('o1.1.'||printf('%064x',100001),CAST('{}' AS BLOB),'old',printf('%064x',0))");
    nativeResolutionRefused(static function()use($e):void{Resolution\resolutionHistory($e->settings(),true);});nativeResolutionRefused(static function()use($e):void{Resolution\resolutionArchive($e->settings());});Check::same($before,Resolution\resolutionRead($e->settings()));Check::same(true,memory_get_peak_usage(true)<8388608);
});
echo 'PASS native Outbox archive metadata budget: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; 100000 synthetic metadata rows scanned under memory_limit=8M, overflow rejected without authenticating or adopting them\n";
