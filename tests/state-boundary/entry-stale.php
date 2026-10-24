<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $login=$x->login();$old=entryFiles($x);$token=$login->credential()->token();Check::same(true,$x->sessions->revoke('tenant','user',$login->credential()->id()));Check::same(null,$x->sessions->verify('tenant','user',$token,2));entryRestore($x,$old);$authenticated=false;$error=null;
    try{$authenticated=$x->sessions->verify('tenant','user',$token,2)!==null;}catch(Throwable $caught){$error=$caught;}
    if($authenticated){throw new RuntimeException('UNSAFE_AUTOMATIC_ENTRY_REAUTHENTICATED_REVOKED_SESSION');}
    Check::same(true,$error instanceof SoSecurity\Storage\StorageException);Check::same('account.witness_stale',$error->reason());
});
echo 'PASS automatic revoked-session backup guard: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
