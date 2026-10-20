<?php
declare(strict_types=1);
require __DIR__.'/restoration-support.php';
require dirname(__DIR__).'/fixtures/account-factor/registry-format6.php';
managedCase(static function(ManagedEnvironment $e):void{
    $f=restorationSetup($e,'retired');$r=restorationService($e,$f);list($v,$secret)=restorationProven($e,$r);$review=$r->operationReview($v['operation'],'owned-previous-reader-review');$r->activate($review,'owned-restoration-before-previous-reader',normalProof());$next=restorationRotate($e,$f);lifecycleRebind($e,$next,lifecycleRaw($e));$old=new SoSecurity\Account\PreviousRestorationRegistry($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->accounts,$e->factors,static function():bool{return true;},static function():bool{return true;},null,$e->clock,$next);$before=restorationState($e);
    foreach(['current','initialize','adopt','inspect'] as $method){migrationReason('account.factor_corrupt',static function()use($old,$method):void{$old->$method('user');});Check::same($before,restorationState($e));}Check::same(false,$e->registry->inspect('user')->retired());
});
echo 'PASS previous restoration reader: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; actual previous source rejects format-7 restored directory before read/initialize/adopt/inspect writes\n";
