<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require_once __DIR__.'/crash-load.php';
require_once __DIR__.'/api-business-support.php';
use SoSecurity\Account\Example\StateDocuments;
$backend=$argv[1]??'';$action=$argv[2]??'';$mode=$argv[3]??'';$transport=$argv[4]??'';
if(!in_array($backend,['sqlite','mysql'],true)||!in_array($action,['produce','resume','contend'],true)||!in_array($mode,['after-pending','after-sql-before-commit','after-commit-before-current'],true)||!is_dir(dirname($transport))||(fileperms(dirname($transport))&0077)!==0){throw new RuntimeException('Use the owned private business crash controller.');}
if($backend==='mysql'){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL only.');}}
if($action==='produce'){
    businessCase(static function(EntryEnvironment $x,SoSecurity\Api\CredentialRegistry $api,string $header)use($backend,$mode,$transport):void{
        $proof=$api->fromAuthorization('tenant',$header,'records:write');$before=$x->inspect();$identity=apiIntentIdentity($x,'user',null);$intent=businessIntent($x->e->pdo,$proof);
        $expected=apiIntentExpected($x,$api,'execute','user','user',$identity['fingerprint'],$identity['fingerprint'],['digest'=>hash('sha256',substr($header,7))],['required_scope'=>'records:write','intent'=>$intent->fingerprint(),'business_policy'=>StateDocuments::policy()->fingerprint(),'tables'=>['state_example_documents']],['records:read','records:write'],$before['digest']);$calls=$x->e->directory.'/business-invocations.log';file_put_contents($calls,'');chmod($calls,0600);
        file_put_contents($transport,json_encode(['producer_pid'=>getmypid(),'target'=>crashMeta($x,$backend)+['business'=>true,'format'=>3,'generation'=>str_repeat('b',64)],'before'=>$before,'expected'=>$expected,'header'=>$header,'calls'=>$calls]));chmod($transport,0600);
        $x->persistHook=static function()use($mode):bool{if($mode==='after-pending'){crashStop();}return true;};
        businessRun($x,$api,$header,static function(PDO $pdo,SoSecurity\Api\VerifiedCredential $proof,SoSecurity\Operation\Intent $intent)use($x,$mode,$calls):int{
            file_put_contents($calls,"called\n",FILE_APPEND|LOCK_EX);$version=businessWrite($pdo,$proof,$intent);if($mode==='after-sql-before-commit'){crashStop();}if($mode==='after-commit-before-current'){$x->e->pdo->afterCommit=static function():void{crashStop();};}return $version;
        });throw new RuntimeException('Writer must be killed at its fixed durable point.');
    },3);exit(2);
}
$m=json_decode(file_get_contents($transport),true);Check::same(false,$m['producer_pid']===getmypid());$x=crashLoad($m['target'],false);$guard=0;$work=0;$api=nativeApi($x,static function()use(&$guard):bool{++$guard;return true;});
if($action==='contend'){echo "CONTENDER_READY\n";fflush(STDOUT);}
$files=entryFiles($x);witnessReason('account.witness_pending',static function()use($x,$api,$m,&$work):void{businessRun($x,$api,$m['header'],static function()use(&$work):void{++$work;});});Check::same(0,$guard);Check::same(0,$work);Check::same($files,entryFiles($x));
$pending=$x->inspect();Check::same(3,$pending['format']);Check::same(str_repeat('b',64),$pending['generation']);Check::same('pending',$pending['status']);Check::same($m['before']['digest'],$pending['digest']);Check::same($m['before']['revision']+1,$pending['revision']);apiIntentCheck($m['expected'],$pending);
$rows=businessRows($x);$row=null;foreach($rows as $r){if($r['scope']==='tenant'&&$r['id']==='owned'){$row=$r;}}$committed=$mode==='after-commit-before-current';Check::same($committed?'2':'1',(string)$row['version']);Check::same($committed?'Changed':'Original',$row['title']);Check::same($mode==='after-pending'?'':"called\n",file_get_contents($m['calls']));Check::same($pending,$x->inspect());Check::same([],glob($x->e->directory.'/factors/stage-*'));
echo 'PASS business '.$action.' '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."; format 3, fresh PDOs, exact pending intent, observed SQL commit/rollback and zero replay\n";
