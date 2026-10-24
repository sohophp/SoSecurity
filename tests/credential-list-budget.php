<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Api\CredentialEncoding;
use SoSecurity\Api\CredentialPolicy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
$mode=$argv[1]??'scopes';
// Load dependencies before setting the diagnostic headroom; the submitted input already exists.
class_exists(CredentialEncoding::class);class_exists(CredentialPolicy::class);
new CredentialPolicy();
$values=array_fill(0,200000,'read');unset($values[0]);
$limit=memory_get_usage(true)+1048576;
if(ini_set('memory_limit',(string)$limit)===false){throw new RuntimeException('Cannot set diagnostic memory limit');}
try{
 if($mode==='scopes'){CredentialEncoding::scopes($values);}
 elseif($mode==='allowlist'){new CredentialPolicy(['allowed_scopes'=>$values]);}
 elseif($mode==='methods'){new CredentialPolicy(['methods'=>$values]);}
 else{throw new RuntimeException('Unknown test mode');}
 throw new RuntimeException('Oversized list accepted');
}catch(ConfigurationException|ValidationException $error){Check::same($mode==='scopes'?'api_credentials.scopes':'configuration.api_credentials',$error->reason());}
unset($values);
Check::same(['read','write'],CredentialEncoding::scopes(['write','read']));
Check::same(['password','totp'],(new CredentialPolicy(['methods'=>['totp','password']]))->methods());
foreach([['read','read'],[1=>'read'],[]] as $invalid){Check::throws(ValidationException::class,static function()use($invalid):void{CredentialEncoding::scopes($invalid);});}
foreach([['password','password'],[1=>'password'],[],['password','totp','webauthn','recovery','password']] as $invalid){Check::throws(ConfigurationException::class,static function()use($invalid):void{new CredentialPolicy(['methods'=>$invalid]);});}
Check::same([],CredentialEncoding::scopes([],true));
$maximum=[];for($i=0;$i<32;++$i){$maximum[]='scope:'.str_pad((string)$i,2,'0',STR_PAD_LEFT);}Check::same($maximum,CredentialEncoding::scopes($maximum));
Check::same(4,count((new CredentialPolicy(['methods'=>['password','totp','webauthn','recovery']]))->methods()));
echo 'PASS credential list budget '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
