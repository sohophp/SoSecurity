<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $before=entryFiles($x);$root=$x->inspect();$calls=0;
    $same=new SoSecurity\Storage\FileStore($x->e->directory.'/factors','entry-sessions',$x->e->clock);
    $anotherNamespace=new SoSecurity\Storage\FileStore($x->e->directory.'/factors','another-namespace',$x->e->clock);
    foreach([$x->store,clone $x->store,$same,$anotherNamespace,new SoSecurity\Storage\NamespacedStore($same,'extra')] as $raw){
        witnessReason('account.state_required',static function()use($raw,&$calls):void{$raw->transact('forbidden',static function()use(&$calls){++$calls;return new SoSecurity\Storage\Change(['unexpected'=>true],0,true);});});
    }
    witnessReason('account.state_required',static function()use($x):void{$x->store->prune();});
    witnessReason('account.state_required',static function()use($x):void{$x->store->pruneBatch();});
    Check::same(0,$calls);Check::same($before,entryFiles($x));Check::same($root,$x->inspect());
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($same,$x):void{new SoSecurity\Auth\SessionRegistry($same,$x->provider);});
    $value=$x->boundary->run('owned.bound.raw',static function()use($x):string{return $x->store->transact('within',static function(){return new SoSecurity\Storage\Change(['owned'=>true],0,'completed');});});
    Check::same('completed',$value);Check::same('current',$x->inspect()['status']);$login=$x->login();Check::same('authenticated',$login->status());
    $other=new SoSecurity\Account\StateBoundary($x->witness,static function():bool{return true;});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x,$other):void{$other->protect($x->store);});
    Check::same(false,$x->boundary->active());
});
echo 'PASS original store boundary: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; original instance, clone and namespace wrapper cannot transact or prune outside their exact authority',PHP_EOL;
