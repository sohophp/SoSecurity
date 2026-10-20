<?php
declare(strict_types=1);
require __DIR__.'/enroll-support.php';
function modeStore(ManagedEnvironment $e):SoSecurity\Storage\AtomicStore
{
    if(($GLOBALS['argv'][2]??'')!=='mysql-store'){return new SoSecurity\Storage\FileStore($e->directory.'/factors','managed-factor-test',$e->clock);}
    $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned MySQL required.');}
    $pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);return new SoSecurity\Storage\MySqlStore($pdo,'managed-'.basename($e->directory),$e->clock);
}
function modeSnapshot(ManagedEnvironment $e,string $subject='user'):?array
{
    return modeStore($e)->transact(SoSecurity\Support\Guard::key('mfa-totp','tenant',$subject),static function($value):SoSecurity\Storage\Change{return new SoSecurity\Storage\Change($value,0,$value);});
}
function modeReplace(ManagedEnvironment $e,?array $value,string $subject='user'):void
{
    modeStore($e)->transact(SoSecurity\Support\Guard::key('mfa-totp','tenant',$subject),static function()use($value):SoSecurity\Storage\Change{return new SoSecurity\Storage\Change($value,0,null);});
}
function managedFactors(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,?callable $guard=null,?SoSecurity\Support\HmacKeys $keys=null):SoSecurity\Mfa\TotpFactors
{
    return $e->factors->managed('managed-test','tenant',str_repeat('e',64),$keys??$e->keys,$f,$guard??static function():bool{return true;});
}
function modeCalls(SoSecurity\Mfa\TotpFactors $m,string $id,string $code,string $recovery):array
{
    return [
        'begin'=>static function()use($m){return $m->begin('tenant','user','owned@example.test');},
        'confirm'=>static function()use($m,$id,$code){return $m->confirm('tenant','user',$id,$code);},
        'verify'=>static function()use($m,$code){return $m->verify('tenant','user',$code);},
        'verifyRecovery'=>static function()use($m,$recovery){return $m->verifyRecovery('tenant','user',$recovery);},
        'verifyBound'=>static function()use($m,$id,$code){return $m->verifyBound('tenant','user',$id,$code);},
        'regenerateRecoveryCodes'=>static function()use($m,$code){return $m->regenerateRecoveryCodes('tenant','user',$code);},
        'regenerateRecoveryCodesBound'=>static function()use($m,$id,$code){return $m->regenerateRecoveryCodesBound('tenant','user',$id,$code);},
        'disable'=>static function()use($m,$code){return $m->disable('tenant','user',$code);},
        'disableBound'=>static function()use($m,$id,$code){return $m->disableBound('tenant','user',$id,$code);},
        'prepare'=>static function()use($m,$id){return $m->prepare('tenant','user',$id,'owned@example.test');},
        'revokeGeneration'=>static function()use($m,$id){return $m->revokeGeneration('tenant','user',$id);},
        'revoke'=>static function()use($m):void{$m->revoke('tenant','user');},
        'status'=>static function()use($m){return $m->status('tenant','user');},
        'reencrypt'=>static function()use($m){return $m->reencrypt('tenant','user');},
        'reencryptBound'=>static function()use($m,$id){return $m->reencryptBound('tenant','user',$id);},
    ];
}
