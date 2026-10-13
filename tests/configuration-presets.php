<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Security;
use SoSecurity\Exception\ConfigurationException;
$loginPolicies='host-owned-value';
$presets=require dirname(__DIR__).'/examples/configuration-presets.php';
Check::same('host-owned-value',$loginPolicies);
Check::same(7,count($presets));
foreach ($presets as $name=>$configuration) {
    $security=Security::fromArray($configuration);
    Check::same('example-site',$security->config()->site());
    Check::same(PHP_SESSION_NONE,session_status());
    Check::same(false,headers_sent());
}
$form=Security::fromArray($presets['form_session']);
Check::same('session',$form->config()->tokenStorage()['driver']);
Check::throws(ConfigurationException::class,static function () use ($form): void { $form->rateLimiter(); });
$directory=privateDirectory();
try {
    $config=$presets['login_file'];$config['storage']['directory']=$directory;
    $login=Security::fromArray($config);
    Check::same(100,$login->config()->policy('ip')->limit());
    $limiter=$login->rateLimiter('login');
    for ($attempt=0;$attempt<5;$attempt++) { Check::same(true,$limiter->consume('login-pair','trusted-ip-account')->allowed); }
    $blocked=$limiter->consume('login-pair','trusted-ip-account');
    Check::same(false,$blocked->allowed);Check::same(true,$blocked->retryAfter>0);
    Check::same(true,$limiter->consume('login-pair','other-ip-account')->allowed);
    Check::same(false,$limiter->inspect('login-pair','trusted-ip-account')->allowed);
    $limiter->reset('login-pair','trusted-ip-account');Check::same(true,$limiter->consume('login-pair','trusted-ip-account')->allowed);
} finally { cleanDirectory($directory); }
$signing=Security::fromArray($presets['api_signing']);
$headers=$signing->hmacSigner(SoSecurity\Api\SigningKey::generate('test-client',['read']))->sign('GET','https://api.example.com/items');
Check::same(true,isset($headers['Signature'],$headers['Signature-Input']));
Check::throws(ConfigurationException::class,static function () use ($signing): void { $signing->hmacVerifier(); });
Check::throws(ConfigurationException::class,static function () use ($presets): void { Security::fromArray($presets['signed_form'])->signedCsrf(); });
$keys=new SoSecurity\Support\HmacKeys('test',['test'=>random_bytes(32)]);
$signed=Security::fromArray($presets['signed_form'],['csrf_keys'=>$keys])->signedCsrf();
$token=$signed->issue('form','server-login-binding');
Check::same(true,$signed->verifyDoubleSubmit('form','server-login-binding',$token,$token));
Check::same(false,$signed->verify('form','other-login-binding',$token));
Check::same(65536,Security::fromArray($presets['rich_text'])->config()->html()['maximum_input']);
Check::same('security_redis',Security::fromArray($presets['login_redis'])->config()->storage()['connection']);
Check::same('security_db',Security::fromArray($presets['login_mysql'])->config()->storage()['connection']);
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
echo 'PHP '.PHP_VERSION.': '.Check::$assertions." configuration preset workflow assertions passed\n";
