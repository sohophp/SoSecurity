<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__).'/vendor/autoload.php';
use SoSecurity\WebAuthn\Ceremonies;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;
$service=new Ceremonies('Test','example.test','https://example.test');
$user=PublicKeyCredentialUserEntity::create('alice','alice-id','Alice');
$record=CredentialRecord::create('credential-id','public-key',[],'none',EmptyTrustPath::create(),Uuid::v4(),'not-a-real-key','alice-id',0);
$checks=0;
$reject=static function(callable $run)use(&$checks):void{try{$run();}catch(InvalidArgumentException $error){++$checks;return;}throw new RuntimeException('Expected bounded credential rejection');};
$mode=$argv[2]??'normal';
if($mode==='register-large'||$mode==='authenticate-large'){
    $large=array_fill(0,60000,$record);
    $reject(static function()use($mode,$service,$user,$large):void{if($mode==='register-large'){$service->beginRegistration($user,$large);}else{$service->beginAuthentication($user->id,$large);}});
}else{
    $rows=[];for($n=0;$n<32;++$n){$row=clone $record;$row->publicKeyCredentialId='credential-'.$n;$rows[]=$row;}
    if(count($service->beginRegistration($user,[])->excludeCredentials)!==0||count($service->beginRegistration($user,$rows)->excludeCredentials)!==32||count($service->beginAuthentication($user->id,$rows)->allowCredentials)!==32){throw new RuntimeException('Valid credential list changed');}$checks+=3;
    $rows[]=$record;
    $reject(static function()use($service,$user,$rows):void{$service->beginRegistration($user,$rows);});
    $reject(static function()use($service,$user,$rows):void{$service->beginAuthentication($user->id,$rows);});
    $reject(static function()use($service,$user):void{$service->beginAuthentication($user->id,[]);});
    $reject(static function()use($service,$record):void{$service->beginAuthentication('another-user',[$record]);});
    $reject(static function()use($service,$user):void{$service->beginRegistration($user,[null]);});
}
echo 'PASS WebAuthn credential list budgets: '.$checks.' assertions PHP '.PHP_VERSION.PHP_EOL;
