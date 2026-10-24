<?php
declare(strict_types=1);
require __DIR__.'/support.php';
snapshotCase(true,static function(InboxTestConnection $pdo):void{
 $source=snapshotSource($pdo);$metadata=0;
 $pdo->beforeStatement=static function(string $sql)use(&$metadata):void{if(strpos($sql,'information_schema.COLUMNS')!==false||strpos($sql,'information_schema.STATISTICS')!==false){++$metadata;}};
 $empty=$source->digest();Check::same(2,$metadata); // One complete schema query before and after rows.
 snapshotInsert($pdo,'tenant',1,'owned');$metadata=0;$filled=$source->digest();Check::same(2,$metadata);Check::same(false,$empty===$filled);
 $pdo->beforeStatement=null;
 // A primary prefix and an unexpected column remain rejected after combining result shapes.
 $pdo->exec('ALTER TABLE snapshot_test DROP PRIMARY KEY,ADD PRIMARY KEY(scope(32),id)');
 snapshotReason('account.snapshot_corrupt',static function()use($source):void{$source->digest();});
 $pdo->exec('ALTER TABLE snapshot_test DROP PRIMARY KEY,ADD PRIMARY KEY(scope,id)');
 Check::same($filled,$source->digest());
 $pdo->exec('ALTER TABLE snapshot_test ADD COLUMN unexpected BIGINT UNSIGNED NOT NULL DEFAULT 0');
 snapshotReason('account.snapshot_corrupt',static function()use($source):void{$source->digest();});
});
echo 'PASS unified snapshot metadata: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
