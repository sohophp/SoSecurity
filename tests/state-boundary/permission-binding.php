<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $e=$x->e;$fields=['scope','subject','credential_version','status','verified','mfa_required','roles','password'];$columns=array_combine($fields,$fields);$queries=$e->pdo->queries;
    $make=static function($store,$registry,$adapter,$factors,$keys)use($x,$e,$columns){return new SoSecurity\Account\StateAccountPolicy($x->witness,$x->source,$x->sources['sql'],$x->sources['files'],'complete-sql','sessions-and-factors','account_example',$columns,$store,$registry,$adapter,$factors,'managed-test','tenant',str_repeat('e',64),$keys);};
    $duplicate=new SoSecurity\Storage\FileStore($e->directory.'/factors','entry-sessions',$e->clock);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($make,$duplicate,$x,$e):void{$make($duplicate,$x->sessions,$x->factorAdapter,$e->factors,$e->keys);});
    $otherAdapter=$e->registry->secondFactor();Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($make,$otherAdapter,$x,$e):void{$make($x->store,$x->sessions,$otherAdapter,$e->factors,$e->keys);});
    $otherClock=new TestClock();$otherClock->time=$e->clock->time;$otherRegistry=new SoSecurity\Auth\SessionRegistry($x->store,$x->provider,$x->factorAdapter,$otherClock,1800,28800,16,$x->boundary);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($make,$otherRegistry,$x,$e):void{$make($x->store,$otherRegistry,$x->factorAdapter,$e->factors,$e->keys);});
    $differentKeys=new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('o',32)]);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($make,$differentKeys,$x,$e):void{$make($x->store,$x->sessions,$x->factorAdapter,$e->factors,$differentKeys);});
    Check::same($queries,$e->pdo->queries);Check::same(true,permissionPolicy($x)->boundTo($x->witness));Check::same($queries,$e->pdo->queries);
});
echo 'PASS exact runtime permission bindings: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; real raw store object, session adapter, factor service, shared clock/keyring and pure constructor rejection\n";
