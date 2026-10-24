<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require_once __DIR__.'/crash-load.php';
require_once __DIR__.'/admission-capacity-support.php';
$backend=$argv[1]??'';$action=$argv[2]??'';$pair=$argv[3]??'';$transport=$argv[4]??'';
if(!in_array($backend,['sqlite','mysql'],true)||!in_array($action,['produce','contend'],true)||!in_array($pair,['links-reset','api-grants'],true)||!is_dir(dirname($transport))||(fileperms(dirname($transport))&0077)!==0){throw new RuntimeException('Use the owned last-slot concurrency controller.');}
if($action==='produce'){
    capacityCase(static function(EntryEnvironment $x,string $session)use($backend,$pair,$transport):void{
        capacityFill($x,7);$before=$x->inspect();$first=$pair==='links-reset'?'links':'api';$second=$pair==='links-reset'?'reset':'grants';$expected=$pair==='links-reset'?'links.issue':'api.credentials.issue';$issue=capacityIssuer($x,$session,$first);
        file_put_contents($transport,json_encode(['target'=>crashMeta($x,$backend)+['business'=>true,'format'=>3,'generation'=>str_repeat('f',64),'files_cap'=>8,'hmac_keys'=>[['id'=>'service-key','secret'=>str_repeat('n',32),'subject'=>'user','scopes'=>['documents:write']]]],'before'=>$before,'session'=>$session,'second'=>$second,'expected'=>$expected]));chmod($transport,0600);$stopped=false;
        $x->persistHook=static function()use(&$stopped):bool{if(!$stopped){$stopped=true;echo "CAPACITY_READY\n";fflush(STDOUT);posix_kill(getmypid(),SIGSTOP);}return true;};Check::same(false,$issue()===null);$x->persistHook=null;Check::same('current',$x->inspect()['status']);Check::same($expected,$x->inspect()['intent']['action']);Check::same($before['revision']+1,$x->inspect()['revision']);Check::same(8,count(glob($x->e->directory.'/factors/*.json')));echo "WRITER_DONE\n";fflush(STDOUT);if(trim((string)fgets(STDIN))!=='CLEANUP'){throw new RuntimeException('Owned controller must finish the contender before cleanup.');}
    });echo 'PASS last-slot producer '.$pair.' PHP '.PHP_VERSION."; one slot consumed, final current durable, fixture cleanup after contender\n";exit;
}
$m=json_decode(file_get_contents($transport),true);$x=crashLoad($m['target'],false);$issue=capacityIssuer($x,$m['session'],$m['second']);echo "CONTENDER_READY\n";fflush(STDOUT);witnessReason($m['second']==='reset'?'reset.capacity':'operation.capacity',$issue);$state=$x->inspect();Check::same('current',$state['status']);Check::same($m['expected'],$state['intent']['action']);Check::same($m['before']['revision']+1,$state['revision']);Check::same(8,count(glob($x->e->directory.'/factors/*.json')));Check::same($x->source->digest(),$state['digest']);echo 'PASS last-slot contender '.$pair.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."; waited, reevaluated full physical source, denied before pending; first successful receipt retained\n";
