<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Http\Cookie;
use SoSecurity\Http\IpRules;
use SoSecurity\Http\Uri;

$mode=$argv[1] ?? '';
$input=str_repeat($mode==='ip_rule' ? '/' : 'A',4194304);
if($mode==='uri_host'){
    Check::throws(ValidationException::class,static function()use($input):void{Uri::host($input);});
    Check::same('example.com',Uri::host('EXAMPLE.COM'));
}elseif($mode==='cookie_domain'){
    Check::throws(ConfigurationException::class,static function()use($input):void{Cookie::header('id','x','/',true,true,'Lax',null,$input);});
    Check::same(true,strpos(Cookie::header('id','x','/',true,true,'Lax',null,'.EXAMPLE.COM'),'; Domain=example.com')!==false);
}elseif($mode==='cookie_path'){
    $input[0]='/';
    Check::throws(ConfigurationException::class,static function()use($input):void{Cookie::header('id','x',$input);});
    Check::same(true,strpos(Cookie::header('id','x','/valid_path'),'; Path=/valid_path')!==false);
}elseif($mode==='ip_rule'){
    Check::throws(ConfigurationException::class,static function()use($input):void{new IpRules([$input]);});
    Check::same(true,(new IpRules(['2001:db8::/32','192.0.2.0/24']))->contains('2001:db8::1'));
}else{throw new RuntimeException('Unknown normalization budget case.');}
Check::same(true,memory_get_peak_usage(false)<8388608);
echo 'PASS normalization budget '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."; 4MiB rejected before expanding/copying input\n";
