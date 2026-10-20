<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
Check::same(false,extension_loaded('sodium'));
$key=str_repeat('K',32);$service=new SoSecurity\Support\HmacKeys('one',['one'=>$key]);$mac=$service->sign("binary\0message");
Check::same(hash_hmac('sha256',"binary\0message",$key,true),$mac);Check::same(true,$service->verify('one',"binary\0message",$mac));Check::same(false,strpos(var_export($service,true),$key)!==false);
echo 'PASS HMAC export without sodium: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."\n";
