<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$cases=json_decode(stream_get_contents(STDIN),true,16); if (!is_array($cases)) { throw new RuntimeException('Expected independent vectors.'); }
$out=[];
foreach ($cases as $case) {
    $clock=new TestClock(); $clock->time=$case['created']; $binding=base64_decode($case['binding_b64'],true);
    $csrf=new SoSecurity\Csrf\SignedTokens(new SoSecurity\Support\HmacKeys($case['id'],[$case['id']=>hex2bin($case['secret_hex'])]),$case['audience'],$case['ttl'],$clock);
    Check::same(true,$csrf->verify($case['scope'],$binding,$case['token']));
    Check::same(false,$csrf->verify($case['scope'],$binding.'x',$case['token']));
    $out[]=$csrf->issue($case['scope'],$binding);
}
echo json_encode($out);
