<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Validation\Validator;

// Input construction fits the 8 MiB process budget; copying unknown option keys must not exhaust it.
$options=['type'=>'string'];
for($i=0;$i<60000;++$i){$options[$i]=null;}
if(($argv[1] ?? '')==='role'){
    $options['type']='document';$options['roles']=['reader'];$options['fields']=['title'];
    Check::throws(ConfigurationException::class,static function()use($options):void{new RolePolicy(['read'=>$options]);});
}elseif(($argv[1] ?? '')==='validation'){
    Check::throws(ConfigurationException::class,static function()use($options):void{new Validator(['title'=>$options]);});
}else{
    $mode=$argv[1] ?? '';
    if($mode==='processing_backoff'){$options=['backoff'=>$options];}
    Check::throws(ConfigurationException::class,static function()use($options,$mode):void{
        if($mode==='session'){\SoSecurity\Session\SessionSecurity::configure(true,'Lax',$options);return;}
        if($mode==='quarantine'){\SoSecurity\Upload\QuarantineState::options($options);return;}
        if($mode==='bcrypt'||$mode==='argon2id'){new \SoSecurity\Password\PasswordHasher($mode,$options);return;}
        if($mode==='webhook'){new \SoSecurity\Webhook\Endpoint('hook','tenant','account','https://example.test/hook','standard-hmac',$options);return;}
        if($mode==='processing_backoff'){new \SoSecurity\Webhook\ProcessingPolicy($options);return;}
        $classes=[
            'config'=>\SoSecurity\Configuration\Config::class,'outbound'=>\SoSecurity\Http\Outbound\Policy::class,
            'upload'=>\SoSecurity\Upload\Policy::class,'credential'=>\SoSecurity\Api\CredentialPolicy::class,
            'signature'=>\SoSecurity\Api\SignaturePolicy::class,'account'=>\SoSecurity\Account\Policy::class,
            'idempotency'=>\SoSecurity\Idempotency\Policy::class,'outbox'=>\SoSecurity\Outbox\Policy::class,
            'download'=>\SoSecurity\Download\Policy::class,'processing'=>\SoSecurity\Webhook\ProcessingPolicy::class,
            'html'=>\SoSecurity\Output\HtmlPolicy::class,
        ];
        if(!isset($classes[$mode])){throw new LogicException('Unknown test mode');}
        $class=$classes[$mode];new $class($options);
    });
}
echo 'PASS schema option budget: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
