<?php
declare(strict_types=1);
// CLI-only isolated test data. Enroll in a prior time step; the HTTP adapter always uses real time.
require __DIR__.'/bootstrap.php';
$input=json_decode(stream_get_contents(STDIN),true);
$clock=new TestClock();$clock->time=time()-90;
$store=new SoSecurity\Storage\FileStore($input['directory'],'operation-example');
$cipher=new SoSecurity\Crypto\Cipher('current',['current'=>base64_decode($input['key'],true)],'operation-example:mfa');
$factors=new SoSecurity\Mfa\TotpFactors($store,$cipher,'Operation example',$clock);
$pending=$factors->begin('operation-example','alice','operation@example.test');
parse_str(parse_url($pending->provisioningUri(),PHP_URL_QUERY),$parts);
$codes=$factors->confirm('operation-example','alice',$pending->id(),(new SoSecurity\Mfa\Totp())->codeAt($parts['secret'],$clock->time));
echo json_encode(['uri'=>$pending->provisioningUri(),'recovery'=>$codes]);
