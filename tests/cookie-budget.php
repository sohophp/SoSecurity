<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Http\Cookie;

$name='token';
$exact=Cookie::header($name,str_repeat('a',4090));
Check::same(4096,strlen(explode(';',$exact,2)[0]));
Check::same(true,strpos($exact,'; Secure; HttpOnly')!==false);
Check::throws(ConfigurationException::class,static function()use($name):void{Cookie::header($name,str_repeat('a',4091));});
Check::same(4095,strlen(explode(';',Cookie::header($name,str_repeat('%',1363)),2)[0]));
Check::throws(ConfigurationException::class,static function()use($name):void{Cookie::header($name,str_repeat('%',1364));});
Check::same(true,strpos(Cookie::header($name,"a\0b"),'a%00b')!==false);
$oversized=str_repeat('x',4*1024*1024);
Check::throws(ConfigurationException::class,static function()use($name,$oversized):void{Cookie::header($name,$oversized);});
Check::same(true,memory_get_peak_usage(false)<8388608);
echo 'PASS cookie encoded-byte budget: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
