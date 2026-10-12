<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$cases=json_decode(stream_get_contents(STDIN),true,16);
if (!is_array($cases)) { throw new RuntimeException('Expected independent test vectors.'); }
$out=[];
foreach ($cases as $case) {
    $clock=new TestClock(); $clock->time=$case['created'];
    $key=new SoSecurity\Api\SigningKey($case['id'],hex2bin($case['secret_hex']),'python-client',['read']);
    $policy=new SoSecurity\Api\SignaturePolicy(['origin'=>$case['origin']]);
    $signer=new SoSecurity\Api\HmacSigner($policy,$key,$clock); $body=base64_decode($case['body_base64'],true);
    $php=$signer->sign($case['method'],$case['url'],$body,$case['type'],$case['lifetime'],$case['nonce']);
    Check::same($case['headers'],$php);
    $verifier=new SoSecurity\Api\HmacVerifier($policy,new SoSecurity\Api\KeyRing([$key]),new SoSecurity\Api\NonceStore(new SoSecurity\Storage\MemoryStore($clock),$clock),$clock);
    Check::same('python-client',$verifier->verify($case['method'],$case['url'],$body,$case['headers'],'read')->subject());
    Check::same(null,$verifier->verify($case['method'],$case['url'],$body,$case['headers'],'read'));
    $out[]=$php;
}
echo json_encode($out,JSON_UNESCAPED_SLASHES);
