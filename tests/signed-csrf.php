<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\HmacKeys;
use SoSecurity\Csrf\SignedTokens;
use SoSecurity\Csrf\RequestPolicy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
$clock=new TestClock(); $keys=new HmacKeys('k1',['k1'=>str_repeat('k',32)]);
$csrf=new SignedTokens($keys,'site-a',30,$clock); $token=$csrf->issue('orders:update','current-login-binding');
Check::same(true,$csrf->verify('orders:update','current-login-binding',$token));
Check::same(true,$csrf->verify('orders:update','current-login-binding',$token)); // Deliberately reusable, no single-use claim.
Check::same(false,$csrf->verify('other','current-login-binding',$token));
Check::same(false,$csrf->verify('orders:update','another-login-binding',$token));
Check::same(false,(new SignedTokens($keys,'site-b',30,$clock))->verify('orders:update','current-login-binding',$token));
Check::same(false,strpos($token,'current-login-binding')); Check::same(false,strpos($token,'orders:update'));
Check::same(false,$token===$csrf->issue('orders:update','current-login-binding'));
Check::same($token,$csrf->reuseOrIssue('orders:update','current-login-binding',$token));
Check::same(true,$csrf->verifyDoubleSubmit('orders:update','current-login-binding',$token,$token));
foreach ([null,[],1,'',str_repeat('a',10000),$token.'x',strtoupper($token),str_replace('socs1','socs2',$token),$token."\n"] as $bad) {
    Check::same(false,$csrf->verify('orders:update','current-login-binding',$bad));
    Check::same(false,$csrf->verifyDoubleSubmit('orders:update','current-login-binding',$bad,$token));
    Check::same(false,$csrf->verifyDoubleSubmit('orders:update','current-login-binding',$token,$bad));
}
$parts=explode('.',$token);
foreach ([1=>'k2',2=>'100001',3=>'100031',4=>str_repeat('a',64),5=>str_repeat('a',64)] as $index=>$changed) {
    $tampered=$parts; $tampered[$index]=$changed; Check::same(false,$csrf->verify('orders:update','current-login-binding',implode('.',$tampered)));
}
$attacker=$csrf->issue('orders:update','attacker-login-binding');
Check::same(false,$csrf->verifyDoubleSubmit('orders:update','current-login-binding',$attacker,$attacker));
Check::same(false,$csrf->verifyDoubleSubmit('orders:update','current-login-binding',$attacker,$token));
$clock->time=100029; Check::same(true,$csrf->verify('orders:update','current-login-binding',$token));
$clock->time=100030; Check::same(false,$csrf->verify('orders:update','current-login-binding',$token));
$new=$csrf->reuseOrIssue('orders:update','current-login-binding',$token); Check::same(false,$new===$token); Check::same(true,$csrf->verify('orders:update','current-login-binding',$new));
$clock->time=99999; Check::same(false,$csrf->verify('orders:update','current-login-binding',$token)); $clock->time=100000;
$rotating=new HmacKeys('k2',['k1'=>str_repeat('k',32),'k2'=>str_repeat('r',32)]);
Check::same(true,(new SignedTokens($rotating,'site-a',30,$clock))->verify('orders:update','current-login-binding',$token));
Check::same(false,(new SignedTokens(new HmacKeys('k2',['k2'=>str_repeat('r',32)]),'site-a',30,$clock))->verify('orders:update','current-login-binding',$token));
$next=(new SignedTokens($rotating,'site-a',30,$clock))->issue('orders:update','current-login-binding');
Check::same('k2',explode('.',$next)[1]); Check::same(false,$csrf->verify('orders:update','current-login-binding',$next));
Check::same(false,(new SignedTokens($keys,'site-a',29,$clock))->verify('orders:update','current-login-binding',$token));
$secret=str_repeat('x',32); $frozen=new HmacKeys('ref',['ref'=>&$secret]); $expected=$frozen->sign('message'); $secret=str_repeat('y',32); Check::same($expected,$frozen->sign('message'));
ob_start(); var_dump($keys); $debug=ob_get_clean(); Check::same(false,strpos($debug,str_repeat('k',32))); Check::same('{}',json_encode($keys));
Check::throws(ConfigurationException::class,function () use ($keys) { serialize($keys); });
Check::throws(ConfigurationException::class,function () use ($keys) { $keys->current='evil'; });
foreach ([['k1'=>str_repeat('k',31)],['k1'=>str_repeat('k',129)],['bad.id'=>str_repeat('k',32)],['k1'=>[]],[],array_fill_keys(['a','b','c','d','e','f','g','h','i'],str_repeat('k',32))] as $bad) {
    Check::throws(ConfigurationException::class,function () use ($bad) { new HmacKeys('k1',$bad); });
}
Check::throws(ConfigurationException::class,function () { new HmacKeys('missing',['k1'=>str_repeat('k',32)]); });
Check::throws(ConfigurationException::class,function () use ($keys) { $keys->sign(str_repeat('a',16385)); });
foreach ([0,86401] as $ttl) { Check::throws(ConfigurationException::class,function () use ($keys,$ttl) { new SignedTokens($keys,'site',$ttl); }); }
Check::throws(ConfigurationException::class,function () use ($csrf) { $csrf->issue('scope',''); });
Check::throws(ConfigurationException::class,function () use ($csrf) { $csrf->verify('',str_repeat('x',1025),'bad'); });
Check::throws(ConfigurationException::class,function () use ($csrf) { $csrf->verifyDoubleSubmit('','binding',null,null); });
$clock->time=PHP_INT_MAX; Check::throws(ConfigurationException::class,function () use ($csrf) { $csrf->issue('scope','binding'); }); $clock->time=100000;
$movingClock=new class implements SoSecurity\Support\Clock { private $calls=0; public function now(): int { return ++$this->calls===1 ? 100000 : 100030; } };
Check::same(false,(new SignedTokens($keys,'site-a',30,$movingClock))->verify('orders:update','current-login-binding',$token));
$policy=new RequestPolicy([['method'=>'POST','path'=>'/hooks/provider']]);
foreach (['GET','HEAD','OPTIONS'] as $method) { Check::same(false,$policy->requiresToken($method,'/account')); }
foreach (['POST','PUT','PATCH','DELETE','CUSTOM','TRACE'] as $method) { Check::same(true,$policy->requiresToken($method,'/account')); }
Check::same(false,$policy->requiresToken('POST','/hooks/provider'));
foreach (['/hooks/provider/','/hooks/providerX','/hooks/provider/delete','/hooks/%70rovider','/hooks//provider','/HOOKS/provider','/account'] as $path) { Check::same(true,$policy->requiresToken('POST',$path)); }
Check::same(true,$policy->requiresToken('DELETE','/hooks/provider'));
foreach (['/hooks/../provider','//evil.invalid','https://site.invalid/x','/hooks/provider?x=1','/hooks/*',"/hooks/\r\nX",''] as $path) { Check::throws(ValidationException::class,function () use ($policy,$path) { $policy->requiresToken('POST',$path); }); }
Check::throws(ValidationException::class,function () use ($policy) { $policy->requiresToken('post','/account'); });
foreach ([[['method'=>'POST','path'=>'/*']],[['method'=>'POST','path'=>'/hooks/%70rovider']],[['method'=>'POST','path'=>'/hooks//provider']],[['method'=>'post','path'=>'/hooks/provider']],[['method'=>'POST','path'=>'/hooks/provider','other'=>true]],[['method'=>null,'path'=>'/hooks/provider']],array_fill(0,33,['method'=>'POST','path'=>'/hook'])] as $rules) { Check::throws(ConfigurationException::class,function () use ($rules) { new RequestPolicy($rules); }); }
$factory=SoSecurity\Security::fromArray(['site'=>'site-a','stateless_csrf'=>['keys'=>'private_keys','ttl'=>30],'csrf'=>['exemptions'=>[['method'=>'POST','path'=>'/hooks/provider']]]],['private_keys'=>$keys],$clock);
Check::same(true,$factory->signedCsrf()->verify('orders:update','current-login-binding',$token));
Check::same(false,$factory->csrfPolicy()->requiresToken('POST','/hooks/provider')); Check::same(true,$factory->csrfPolicy()->requiresToken('POST','/account'));
Check::same('manual',array_column($factory->diagnose(),null,'check')['csrf.signed.binding']['status']);
$path='/hooks/frozen'; $frozenPolicy=SoSecurity\Security::fromArray(['site'=>'frozen','csrf'=>['exemptions'=>[['method'=>'POST','path'=>&$path]]]]);
$path='/account/delete'; Check::same(true,$frozenPolicy->csrfPolicy()->requiresToken('POST','/account/delete')); Check::same(false,$frozenPolicy->csrfPolicy()->requiresToken('POST','/hooks/frozen'));
foreach ([['site'=>'a','stateless_csrf'=>['keys'=>'missing']],['site'=>'a'],['site'=>'a','stateless_csrf'=>['keys'=>'x','ttl'=>null]],['site'=>'a','stateless_csrf'=>['keys'=>'x','unknown'=>true]],['site'=>'a','csrf'=>['exemptions'=>null]]] as $bad) {
    Check::throws(ConfigurationException::class,function () use ($bad) { SoSecurity\Security::fromArray($bad)->signedCsrf(); });
}
echo 'PHP '.PHP_VERSION.': '.Check::$assertions." signed CSRF/key/route assertions passed\n";
