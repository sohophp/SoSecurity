<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require_once __DIR__.'/crash-load.php';
require_once __DIR__.'/links-native-support.php';
use SoSecurity\Account\Example\StateDocuments;
use SoSecurity\Account\Example\StateDocumentLinks;
$backend=$argv[1]??'';$action=$argv[2]??'';$mode=$argv[3]??'';$transport=$argv[4]??'';
if(!in_array($backend,['sqlite','mysql'],true)||!in_array($action,['produce','resume','contend'],true)||!in_array($mode,['after-pending','after-sql-before-commit','after-commit-before-current'],true)||!is_dir(dirname($transport))||(fileperms(dirname($transport))&0077)!==0){throw new RuntimeException('Use the owned private native-link crash controller.');}
if($backend==='mysql'){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL only.');}}
if($action==='produce'){
    grantCase(static function(EntryEnvironment $x,string $token)use($backend,$mode,$transport):void{
        $links=nativeLinks($x);$issued=linkIssue($x,$links,$token);$before=$x->inspect();$target=StateDocumentLinks::target($x->e->pdo,'tenant','owned');$expected=linkExpected($x,$links,'execute',null,null,$target,['url'=>$issued->url(),'method'=>'POST','binding'=>''],$before['digest']);$calls=$x->e->directory.'/link-invocations.log';file_put_contents($calls,'');chmod($calls,0600);
        file_put_contents($transport,json_encode(['producer_pid'=>getmypid(),'target'=>crashMeta($x,$backend)+['business'=>true,'format'=>3,'generation'=>str_repeat('c',64)],'before'=>$before,'expected'=>$expected,'url'=>$issued->url(),'calls'=>$calls]));chmod($transport,0600);
        $x->persistHook=static function()use($mode):bool{if($mode==='after-pending'){crashStop();}return true;};
        $links->withVerification('tenant',$x->e->pdo,StateDocuments::definition(),linkPrepare(),$issued->url(),static function(PDO $pdo,SoSecurity\Link\VerifiedLink $proof)use($x,$mode,$calls):int{
            file_put_contents($calls,"called\n",FILE_APPEND|LOCK_EX);$r=$proof->target()->resource();$q=$pdo->prepare('UPDATE state_example_documents SET title=?,version=version+1 WHERE scope=? AND id=? AND version=? AND owner=?');$q->execute(['Changed',$r->scope(),$r->id(),$r->version(),$r->attributes()['owner']]);Check::same(1,$q->rowCount());$q->closeCursor();if($mode==='after-sql-before-commit'){crashStop();}if($mode==='after-commit-before-current'){$x->e->pdo->afterCommit=static function():void{crashStop();};}return 2;
        },'POST');throw new RuntimeException('Writer must be killed at its fixed durable point.');
    });exit(2);
}
$m=json_decode(file_get_contents($transport),true);Check::same(false,$m['producer_pid']===getmypid());$x=crashLoad($m['target'],false);$guard=0;$prepare=0;$work=0;$links=nativeLinks($x,static function()use(&$guard):bool{++$guard;return true;});
if($action==='contend'){echo "CONTENDER_READY\n";fflush(STDOUT);}
$files=entryFiles($x);witnessReason('account.witness_pending',static function()use($x,$links,$m,&$prepare,&$work):void{$links->withVerification('tenant',$x->e->pdo,StateDocuments::definition(),static function(PDO $pdo)use(&$prepare):SoSecurity\Link\Target{++$prepare;return StateDocumentLinks::target($pdo,'tenant','owned');},$m['url'],static function()use(&$work):void{++$work;},'POST');});Check::same(0,$guard);Check::same(0,$prepare);Check::same(0,$work);Check::same($files,entryFiles($x));
$pending=$x->inspect();Check::same(3,$pending['format']);Check::same(str_repeat('c',64),$pending['generation']);Check::same('pending',$pending['status']);Check::same($m['before']['digest'],$pending['digest']);Check::same($m['before']['revision']+1,$pending['revision']);Check::same($m['expected'],$pending['intent']);Check::same(SoSecurity\Account\StateOperation::digestOf($m['expected']),$pending['intent_digest']);
$rows=businessRows($x);$row=null;foreach($rows as $r){if($r['scope']==='tenant'&&$r['id']==='owned'){$row=$r;}}$committed=$mode==='after-commit-before-current';Check::same($committed?'2':'1',(string)$row['version']);Check::same($committed?'Changed':'Original',$row['title']);Check::same($mode==='after-pending'?'':"called\n",file_get_contents($m['calls']));Check::same($pending,$x->inspect());Check::same([],glob($x->e->directory.'/factors/stage-*'));
echo 'PASS native link '.$action.' '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."; format 3, fresh PDOs, exact pending intent, observed SQL commit/rollback and zero loader/guard/work replay\n";
