<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $x->publicAllowed=false;$before=$x->lookups;
    witnessReason('account.completion_unknown',static function()use($x):void{$x->boundary->run('nested-request',static function()use($x):void{$x->auth->password('tenant','browser','owned@example.test',$x->e->password);});});
    Check::same($before,$x->lookups);Check::same([['public',true,'password','tenant']],$x->guards);Check::same(false,$x->boundary->active());
});
entryCase(static function(EntryEnvironment $x):void{
    $x->currentAllowed=false;$before=$x->lookups;$root=$x->inspect();$files=entryFiles($x);$persists=0;
    $x->persistHook=static function()use(&$persists):bool{++$persists;return true;};
    witnessReason('auth.request_denied',static function()use($x):void{$x->auth->password('tenant','browser','owned@example.test',$x->e->password);});
    Check::same($before,$x->lookups);Check::same($root,$x->inspect());Check::same($files,entryFiles($x));Check::same(0,$persists);Check::same(false,$x->boundary->active());
    $x->persistHook=null;$x->currentAllowed=true;Check::same('authenticated',$x->login()->status());
});
entryCase(static function(EntryEnvironment $x):void{
    $x->finalAllowed=false;$result=null;
    witnessReason('account.completion_unknown',static function()use($x,&$result):void{$result=$x->auth->password('tenant','browser','owned@example.test',$x->e->password);});
    Check::same(null,$result);Check::same('pending',$x->inspect()['status']);Check::same(false,$x->boundary->active());Check::same(true,$x->lookups>0);
});
entryCase(static function(EntryEnvironment $x):void{
    $calls=0;$x->persistHook=static function()use(&$calls):bool{++$calls;return false;};$before=$x->lookups;
    witnessReason('account.completion_unknown',static function()use($x):void{$x->auth->password('tenant','browser','owned@example.test',$x->e->password);});
    Check::same(1,$calls);Check::same($before,$x->lookups);Check::same('pending',$x->inspect()['status']);Check::same(false,$x->boundary->active());
});
entryCase(static function(EntryEnvironment $x):void{
    $calls=0;$x->persistHook=static function()use(&$calls):bool{return ++$calls===1;};$result=null;
    witnessReason('account.completion_unknown',static function()use($x,&$result):void{$result=$x->auth->password('tenant','browser','owned@example.test',$x->e->password);});
    Check::same(null,$result);Check::same(2,$calls);Check::same('current',$x->inspect()['status']);Check::same(false,$x->boundary->active());
});
echo 'PASS entry outcome boundaries: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; current authority recheck and final budget, durable pending before provider, unknown receipts retained, no result or leaked active scope\n";
