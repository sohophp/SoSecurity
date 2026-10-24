<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\StatePermission;
use SoSecurity\Exception\ConfigurationException;
$token='soss_'.str_repeat('1',32).'.'.str_repeat('2',64);
$make=static function(array $methods)use($token):StatePermission{return new StatePermission('account.review','tenant','user','user',$token,[],2,300,true,true,$methods);};
$make([]);$methods=array_fill(0,200000,'totp');unset($methods[0]);
if(ini_set('memory_limit',(string)(memory_get_usage(true)+1048576))===false){throw new RuntimeException('Cannot set diagnostic memory limit');}
try{$make($methods);throw new RuntimeException('Oversized permission methods accepted');}catch(ConfigurationException $error){Check::same('configuration.state_permission',$error->reason());}
unset($methods);
Check::same([],$make([])->definition()['methods']);
Check::same(['password','recovery','totp','webauthn'],$make(['webauthn','totp','recovery','password'])->definition()['methods']);
Check::same($make(['totp','password'])->binding(),$make(['password','totp'])->binding());
foreach([[1=>'totp'],['totp','totp'],['unknown'],[null],['password','totp','recovery','webauthn','totp']] as $invalid){Check::throws(ConfigurationException::class,static function()use($make,$invalid):void{$make($invalid);});}
$methods=['totp'];$permission=$make($methods);$methods[0]='password';Check::same(['totp'],$permission->definition()['methods']);
Check::same(false,strpos(var_export($permission,true),$token)!==false);
echo 'PASS state permission list budget '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
