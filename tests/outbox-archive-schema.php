<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-resolution-support.php';
use SoSecurity\Examples\Outbox as Resolution;
if(!function_exists('sodium_crypto_sign_detached')){if(getenv('SOSECURITY_REQUIRE_CRYPTO')==='1'){throw new RuntimeException('Required ext-sodium is missing.');}echo "NOT RUN native audit schema dependencies: ext-sodium test environment required\n";return;}
function archiveSchemaCase(callable $work):void
{
    nativeResolutionCase(static function(NativeResolutionEnvironment $e)use($work):void{$proof=$e->proof();Resolution\resolutionImport($e->settings(),$e->id,$proof);Resolution\outbox($e->settings())->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice');$baseline=Resolution\resolutionAuditStatus($e->settings())['root_hash'];$e->configure(['resolution_archive'=>true]);Resolution\resolutionArchiveInitialize($e->settings(),$baseline);$work($e,$e->settings());});
}
foreach([0,1] as $enabled){foreach(['outbox_example_resolutions'=>'event_id','outbox_example_resolution_root'=>'slot','outbox_example_resolution_archives'=>'event_id'] as $table=>$column){archiveSchemaCase(static function(NativeResolutionEnvironment $e,array $s)use($enabled,$table,$column):void{
    if($table==='outbox_example_resolution_archives'){Resolution\resolutionArchive($s);}$root=Resolution\resolutionRead($s);$s['pdo']->exec('PRAGMA foreign_keys='.$enabled);$s['pdo']->exec('CREATE TABLE archive_local_children(event_id TEXT NOT NULL REFERENCES '.strtoupper($table).'('.$column.') ON DELETE CASCADE, marker TEXT NOT NULL)');$q=$s['pdo']->prepare('INSERT INTO archive_local_children VALUES(?,?)');$q->execute([$column==='slot'?'1':$e->id,'owned-local-test']);$q->closeCursor();
    // A TEMP object cannot redirect main-schema introspection.
    $s['pdo']->exec('CREATE TEMP TABLE pragma_foreign_key_list("table" TEXT)');
    nativeResolutionRefused(static function()use($s):void{Resolution\resolutionArchive($s);});nativeResolutionRefused(static function()use($s,$table):void{Resolution\resolutionRekey($s,$table==='outbox_example_resolution_archives');});nativeResolutionRefused(static function()use($s,$e):void{Resolution\resolutionAuditExport($s,$e->id);});
    Check::same($root,Resolution\resolutionRead($s));Check::same(1,(int)$s['pdo']->query('SELECT COUNT(*) FROM archive_local_children')->fetchColumn());Check::same($enabled,(int)$s['pdo']->query('PRAGMA foreign_keys')->fetchColumn());
});}}
archiveSchemaCase(static function(NativeResolutionEnvironment $e,array $s):void{
    $root=Resolution\resolutionRead($s);$s['pdo']->exec('CREATE TABLE archive_external_parent(id TEXT PRIMARY KEY)');$s['pdo']->exec('ALTER TABLE outbox_example_resolutions ADD COLUMN external_id TEXT REFERENCES archive_external_parent(id)');nativeResolutionRefused(static function()use($s):void{Resolution\resolutionArchive($s);});Check::same($root,Resolution\resolutionRead($s));
});
archiveSchemaCase(static function(NativeResolutionEnvironment $e,array $s):void{
    $root=Resolution\resolutionRead($s);$s['pdo']->exec('CREATE TABLE pragma_foreign_key_list("table" TEXT)');nativeResolutionRefused(static function()use($s):void{Resolution\resolutionAuditStatus($s);});Check::same($root,Resolution\resolutionRead($s));
});
archiveSchemaCase(static function(NativeResolutionEnvironment $e,array $s):void{
    $s['pdo']->exec('PRAGMA foreign_keys=ON');$s['pdo']->exec('CREATE TABLE archive_business_parent(id TEXT PRIMARY KEY);CREATE TABLE archive_business_child(id TEXT REFERENCES archive_business_parent(id) ON DELETE CASCADE)');$s['pdo']->exec("INSERT INTO archive_business_parent VALUES('one');INSERT INTO archive_business_child VALUES('one')");$s['pdo']->exec('CREATE TEMP TABLE pragma_foreign_key_list("table" TEXT)');Check::same(1,Resolution\resolutionArchive($s)['archived']);Check::same(1,(int)$s['pdo']->query('SELECT COUNT(*) FROM archive_business_child')->fetchColumn());Check::same(1,Resolution\resolutionAuditStatus($s)['archived_entries']);
});
echo 'PASS native Outbox audit schema dependencies: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; incoming/outgoing audit foreign keys refused, main introspection preserved, unrelated business rows retained\n";
