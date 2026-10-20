<?php
declare(strict_types=1);
require __DIR__.'/migration-maintenance-support.php';
managedCase(static function(ManagedEnvironment $e):void{
    list($f,$m)=registeredSetup($e);$before=modeSnapshot($e);migrationReason('factor.fence_closed_context',static function()use($f,$m):void{$m->migrationSnapshotClosed($f,'tenant','user');});$other=purgeFence($e,'wrong-authority');Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($other,$m):void{$m->migrationSnapshotClosed($other,'tenant','user');});
    $info=$f->drain(static function()use($f,$m):array{return $m->migrationSnapshotClosed($f,'tenant','user');},static function():bool{return true;});Check::same($before['payload']['enabled']['id'],$info['factor_id']);Check::same(true,$info['managed']);Check::same(null,$info['migration']);Check::same(false,strpos(json_encode($info),$e->secret)!==false);Check::same($before,modeSnapshot($e));migrationReason('factor.fence_closed',static function()use($m):void{$m->status('tenant','user');});
});
// The closed read capability must remain read-only even when the caller uses the lower store API.
managedCase(static function(ManagedEnvironment $e):void{
    list($f,$m)=registeredSetup($e);$before=modeSnapshot($e);$authority=new SoSecurity\Mfa\FactorAuthority($f,registeredProvider($e,$f),$e->clock,10000);$context=hash('sha256',json_encode(['SoSecurity.Mfa.ManagedContext.1','managed-test','tenant',str_repeat('e',64)],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));$store=new SoSecurity\Mfa\ManagedFactorStore(modeStore($e),$context,$e->keys,$authority);$key=SoSecurity\Support\Guard::key('mfa-totp','tenant','user');$denied=false;
    $f->drain(static function()use($authority,$f,$store,$key,&$denied):void{try{$authority->inspectClosed($f,'tenant','user',static function()use($store,$key):void{$store->transact($key,static function():SoSecurity\Storage\Change{return new SoSecurity\Storage\Change(null,0,true);});});}catch(SoSecurity\Exception\ConfigurationException $error){Check::same('mfa.closed_read_only',$error->reason());$denied=true;}},static function():bool{return true;});
    if(modeSnapshot($e)!==$before){throw new RuntimeException('CLOSED_INSPECTION_DELETED_FACTOR');}Check::same(true,$denied);Check::same($before,modeSnapshot($e));
});
echo 'PASS closed migration inspection: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; exact active closed EX capability, metadata only, wrong authority and direct write refusal\n";
