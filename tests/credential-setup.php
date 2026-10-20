<?php
declare(strict_types=1);
// Isolated HTTP fixture provisioning only; the shipped example never creates accounts, keys or MFA factors.
require __DIR__.'/bootstrap.php';
$input=json_decode(stream_get_contents(STDIN),true);
$clock=new TestClock();$clock->time=time()-90;
$store=new SoSecurity\Storage\FileStore($input['directory'],'credential-example');
$factor=new SoSecurity\Mfa\TotpFactors($store,new SoSecurity\Crypto\Cipher('test',['test'=>base64_decode($input['key'],true)],'credential-example:mfa'),'Credential example',$clock);
$enrollment=$factor->begin('credential-example','admin','Admin fixture');
parse_str(parse_url($enrollment->provisioningUri(),PHP_URL_QUERY),$query);
$codes=$factor->confirm('credential-example','admin',$enrollment->id(),(new SoSecurity\Mfa\Totp())->codeAt($query['secret'],$clock->time));
if($codes===null){throw new RuntimeException('Cannot prepare isolated TOTP factor.');}
echo json_encode(['uri'=>$enrollment->provisioningUri()])."\n";
