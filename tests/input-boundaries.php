<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Http\Uri;
use SoSecurity\Http\Cookie;
use SoSecurity\Http\IpRules;
use SoSecurity\Validation\Validator;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

$host=str_repeat('a',63).'.'.str_repeat('b',63).'.'.str_repeat('c',63).'.'.str_repeat('d',61);
Check::same(253,strlen($host));Check::same($host,Uri::host(strtoupper($host)));
Check::throws(ValidationException::class,static function()use($host):void{Uri::host($host.'a');});
Check::same(true,strpos(Cookie::header('id','x','/',true,true,'Lax',null,'.'.strtoupper($host)),'Domain='.$host)!==false);
Check::throws(ConfigurationException::class,static function()use($host):void{Cookie::header('id','x','/',true,true,'Lax',null,'.'.$host.'a');});
$path='/'.str_repeat('a',4095);Check::same(true,strpos(Cookie::header('id','x',$path),'Path='.$path.';')!==false);
Check::throws(ConfigurationException::class,static function()use($path):void{Cookie::header('id','x',$path.'a');});
$long='ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128';
Check::same(49,strlen($long));Check::same(true,(new IpRules([$long]))->contains('ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255'));
$rules=array_fill(0,1024,'192.0.2.0/24');Check::same(true,(new IpRules($rules))->contains('192.0.2.1'));
$rules[]='::1';Check::throws(ConfigurationException::class,static function()use($rules):void{new IpRules($rules);});
Check::same(false,(new IpRules(['::/0']))->contains(str_repeat('a',46)));
$invalid=(new Validator(['age'=>['type'=>'integer']]))->validate(['age'=>'private-invalid']);
Check::same(false,$invalid->valid());Check::same(true,count($invalid->errors())>0);
Check::throws(ValidationException::class,static function()use($invalid):void{$invalid->data();});
foreach(['https://example.com/dir/file?old=1#fragment','https://example.com/'] as $url){
 $uri=Uri::parse($url,true);Check::same($url,$uri->url());Check::same($url,(clone $uri)->url());
 Check::same('https://example.com/?new=1',$uri->resolve('/?new=1')->url());
 Check::same($uri->origin().$uri->path().'?new=1',$uri->resolve('?new=1')->url());
 Check::same($uri->origin().$uri->target().'#new',$uri->resolve('#new')->url());
}
Check::same('https://example.com/dir/next',Uri::parse('https://example.com/dir/file')->resolve('next')->url());
Check::same('https://example.com',Uri::originValue('https://EXAMPLE.COM/'));
Check::throws(ValidationException::class,static function():void{Uri::originValue('https://example.com/?');});
echo 'PASS input boundaries: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
