<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/credential-support.php';
$entry=$argv[1]??'authenticate';if(!in_array($entry,['authenticate','fromAuthorization'],true)){throw new RuntimeException('Known entry required');}
credentialCase(static function(CredentialEnvironment $e)use($entry):void{
 $issued=$e->issue();$object=new class implements JsonSerializable{public function jsonSerialize():array{throw new RuntimeException('PRIVATE-UNDECLARED-ARGUMENT');}};
 foreach(['undeclared',null,$object] as $extra){$input=$entry==='authenticate'?$issued->token():'Bearer '.$issued->token();$proof=$e->registry->$entry('tenant',$input,'documents:read',$extra);Check::same(true,$proof instanceof SoSecurity\Api\VerifiedCredential);Check::same(['documents:read'],$proof->scopes());}
});
echo 'PASS credential public argument boundary '.$entry.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
