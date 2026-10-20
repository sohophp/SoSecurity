<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

$clock=new TestClock();
$factors=new SoSecurity\Mfa\TotpFactors(
    new SoSecurity\Storage\MemoryStore($clock),
    new SoSecurity\Crypto\Cipher('test',['test'=>str_repeat('t',32)],'owned-enrollment'),
    'Owned',$clock
);
$enrollment=$factors->begin('tenant','subject','owned@example.test');
$uri=$enrollment->provisioningUri();
parse_str(parse_url($uri,PHP_URL_QUERY),$parts);
foreach([var_export($enrollment,true),print_r($enrollment,true),json_encode($enrollment)] as $dump){
    Check::same(false,strpos($dump,$parts['secret'])!==false);
    Check::same(false,strpos($dump,$uri)!==false);
}
Check::same($uri,$enrollment->provisioningUri());
Check::same(32,strlen($enrollment->id()));
Check::same(100300,$enrollment->expiresAt());
$code=(new SoSecurity\Mfa\Totp())->codeAt($parts['secret'],$clock->time);
Check::same(true,$factors->confirm('tenant','subject',$enrollment->id(),$code)!==null);
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($enrollment):void{serialize($enrollment);});
$class=SoSecurity\Mfa\Enrollment::class;
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($class):void{
    unserialize('O:'.strlen($class).':"'.$class.'":0:{}');
});
echo 'PASS private TOTP enrollment export: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; explicit provisioning/confirmation preserved, automatic exports and wakeup refuse secrets\n";
