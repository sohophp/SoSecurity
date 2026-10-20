<?php
declare(strict_types=1);
require __DIR__.'/intent-history-support.php';
managedCase(static function(ManagedEnvironment $e):void{
    $raw=$e->factors;$f=purgeFence($e);$config=['site'=>'managed-test','account_factors'=>['connection'=>'db','scope'=>'tenant','epoch'=>str_repeat('e',64),'repository'=>'accounts','integrity_keys'=>'keys','totp'=>'raw','fence'=>'fence','worker_guard'=>'worker','read_guard'=>'read','management_guard'=>'manage']];$services=['db'=>$e->pdo,'accounts'=>$e->accounts,'keys'=>$e->keys,'raw'=>$raw,'fence'=>$f,'worker'=>static function():bool{return true;},'read'=>static function():bool{return true;},'manage'=>static function():bool{return true;}];
    $e->registry=SoSecurity\Security::fromArray($config,$services,$e->clock)->accountFactors();
    Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM sosecurity_account_roots')->fetchColumn());
    $core=migrationService($e,$raw,$f);$core->initialize('owned-explicit-first-registration');
    Check::same(1,(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_roots WHERE namespace LIKE '%'")->fetchColumn());
    $review=$core->review('user','owned-first-review',migrationStop());Check::same(true,$core->execute($review,'owned-first-migration',migrationProof())['completed']);Check::same(true,$e->registry->current('user')->enabled());
});
echo 'PASS SDK public first registration: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; no internal Ledger provisioning, explicit migration initialize then real account migration\n";
