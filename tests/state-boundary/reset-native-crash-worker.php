<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require_once __DIR__.'/crash-load.php';
require_once __DIR__.'/reset-native-support.php';
$backend=$argv[1]??'';$action=$argv[2]??'';$mode=$argv[3]??'';$transport=$argv[4]??'';
if(!in_array($backend,['sqlite','mysql'],true)||!in_array($action,['produce','resume','contend'],true)||!in_array($mode,['after-pending','after-sql-before-commit','after-commit-before-current'],true)||!is_dir(dirname($transport))||(fileperms(dirname($transport))&0077)!==0){throw new RuntimeException('Use the owned private native-reset crash controller.');}
if($backend==='mysql'){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL only.');}}
if($action==='produce'){
    managedCase(static function(ManagedEnvironment $e)use($backend,$mode,$transport):void{
        $x=new EntryEnvironment($e,false,3,null,30000,null,str_repeat('d',64));$r=resetNative($x);$token=$r->issueFor('tenant','user');$before=$x->inspect();$expected=resetExpected($x,'execute',$token,$before['digest'],resetTables());$calls=$e->directory.'/reset-invocations.log';file_put_contents($calls,'');chmod($calls,0600);$hash=(new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]))->hash('Owned native crash password 49!');
        file_put_contents($transport,json_encode(['producer_pid'=>getmypid(),'target'=>crashMeta($x,$backend)+['format'=>3,'generation'=>str_repeat('d',64)],'before'=>$before,'expected'=>$expected,'token'=>$token,'old_hash'=>hash('sha256',$e->row()['password']),'new_hash'=>hash('sha256',$hash),'calls'=>$calls]));chmod($transport,0600);
        $x->persistHook=static function()use($mode):bool{if($mode==='after-pending'){crashStop();}return true;};
        $r->withConsumption('tenant','user',$e->pdo,resetTables(),$token,static function(PDO $pdo,SoSecurity\Account\AccountRecord $record)use($x,$e,$mode,$calls,$hash):string{
            file_put_contents($calls,"called\n",FILE_APPEND|LOCK_EX);Check::same(true,$e->accounts->replacePassword($record,$hash) instanceof SoSecurity\Account\AccountRecord);if($mode==='after-sql-before-commit'){crashStop();}if($mode==='after-commit-before-current'){$e->pdo->afterCommit=static function():void{crashStop();};}return 'changed';
        });throw new RuntimeException('Writer must be killed at its fixed durable point.');
    });exit(2);
}
$m=json_decode(file_get_contents($transport),true);Check::same(false,$m['producer_pid']===getmypid());$x=crashLoad($m['target'],false);$guard=0;$work=0;$r=resetNative($x,static function()use(&$guard):bool{++$guard;return true;});
if($action==='contend'){echo "CONTENDER_READY\n";fflush(STDOUT);}
$files=entryFiles($x);witnessReason('account.witness_pending',static function()use($x,$r,$m,&$work):void{$r->withConsumption('tenant','user',$x->e->pdo,resetTables(),$m['token'],static function()use(&$work):void{++$work;});});Check::same(0,$guard);Check::same(0,$work);Check::same($files,entryFiles($x));
$pending=$x->inspect();Check::same(3,$pending['format']);Check::same(str_repeat('d',64),$pending['generation']);Check::same('pending',$pending['status']);Check::same($m['before']['digest'],$pending['digest']);Check::same($m['before']['revision']+1,$pending['revision']);apiIntentCheck($m['expected'],$pending);$row=$x->e->row();Check::same($mode==='after-commit-before-current'?$m['new_hash']:$m['old_hash'],hash('sha256',$row['password']));Check::same(1,(int)$row['mfa_required']);Check::same($mode==='after-pending'?'':"called\n",file_get_contents($m['calls']));Check::same($pending,$x->inspect());Check::same([],glob($x->e->directory.'/factors/stage-*'));
echo 'PASS native reset '.$action.' '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."; format 3, fresh PDOs, exact pending receipt, actual password SQL commit/rollback, no guard/work replay or MFA removal\n";
