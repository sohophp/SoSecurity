<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $before=$x->inspect();$files=entryFiles($x);$queries=$x->e->pdo->queries;$lookups=$x->lookups;
    foreach([['', 'secret'],['owned@example.test',''],[str_repeat('x',257),'secret'],['owned@example.test',str_repeat('x',4097)],['owned@example.test',"valid\0hidden"],["owned\0hidden",'secret']] as $bad){Check::same('denied',$x->auth->password('tenant','browser',$bad[0],$bad[1])->status());}
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x):void{$x->auth->password('tenant','browser','owned@example.test',$x->e->password,str_repeat('x',129));});
    Check::same('denied',$x->auth->password('tenant','browser','owned@example.test',$x->e->password,'','bad-token')->status());
    foreach(['',str_repeat('a',65),new stdClass()] as $bad){Check::same('denied',$x->auth->secondFactor('tenant','browser',$bad,[])->status());}
    foreach(['',str_repeat('a',103),new stdClass()] as $bad){Check::same(null,$x->sessions->verify('tenant','user',$bad));Check::same(null,$x->remember->issue('tenant','user',$bad));}
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x):void{$x->sessions->verify('tenant','user','bad',3);});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x):void{$x->sessions->register('tenant','user','bad','bad');});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x):void{$x->sessions->replace('tenant','user',str_repeat('a',64),str_repeat('b',64),'password','bad','bad');});
    Check::same(false,$x->sessions->revoke('tenant','user','bad'));Check::same(false,$x->remember->revoke('tenant','user','bad'));
    Check::same('invalid',$x->remember->resume('tenant','bad-token')->status());Check::same(false,$x->remember->forget('tenant','bad-token'));
    Check::same($queries,$x->e->pdo->queries);Check::same($lookups,$x->lookups);Check::same([], $x->budgets);Check::same($files,entryFiles($x));Check::same($before,$x->inspect());
    $x->publicAllowed=false;$queries=$x->e->pdo->queries;
    witnessReason('auth.request_denied',static function()use($x):void{$x->auth->password('tenant','browser','owned@example.test',$x->e->password);});
    witnessReason('auth.request_denied',static function()use($x):void{$x->auth->secondFactor('tenant','browser',str_repeat('a',64),[]);});
    witnessReason('auth.request_denied',static function()use($x):void{$x->auth->cancel('tenant','browser');});
    witnessReason('auth.request_denied',static function()use($x):void{$x->remember->all('tenant','user');});
    Check::same($queries,$x->e->pdo->queries);Check::same([], $x->budgets);Check::same($before,$x->inspect());
    $x->publicAllowed=true;$x->budgetAllowed=false;$queries=$x->e->pdo->queries;
    witnessReason('account.witness_budget',static function()use($x):void{$x->auth->password('tenant','browser','owned@example.test',$x->e->password);});
    Check::same($queries,$x->e->pdo->queries);Check::same($lookups,$x->lookups);Check::same($before,$x->inspect());Check::same(false,$x->boundary->active());
    $x->budgetAllowed=true;$login=$x->login();Check::same('authenticated',$login->status());Check::same('current',$x->inspect()['status']);
});
echo 'PASS entry input boundaries: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; invalid inputs and public/request budget refusal before source/provider/store access, no pending poisoning and subsequent real MFA login succeeds\n";
