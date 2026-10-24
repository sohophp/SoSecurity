<?php
declare(strict_types=1);
$case=substr($argv[4],strlen('captured-'));
$boundary->run('owned.address.captured.seed',static function()use($pdo,$case):void{$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['["member"]','fresh-user']);$pdo->prepare('INSERT INTO owned_address_permissions VALUES(?,?,?)')->execute(['tenant','fresh-user',$case==='deny'?0:1]);});
++$clock->time;$login=$auth->password('tenant','owned-captured-address','fresh@example.test',$password);Check::same('authenticated',$login->status());$token=$login->credential()->token();
echo 'ADDRESS_CAPTURED_FACTORY '.$case.PHP_EOL;
$address=$sdk->addressChange($policy);$grants=$sdk->operations($policy);Check::same(0,$capturedAddressEvaluator->calls);Check::same(0,$capturedAddressEvaluator->selections);
$boundary->run('owned.address.captured.initialize',static function()use($address):void{$address->initialize();});
$before=$witness->inspect(static function():bool{return true;});
$adapter=$sdk->operations()->forAddress($policy);
Check::throws(SoSecurity\Storage\StorageException::class,static function()use($policy,$boundary):void{$policy->activePolicyDigest($boundary);});
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($adapter,$policy):void{$adapter->forAddress($policy);});
$probeIntent=new SoSecurity\Operation\Intent('account.address.request',new SoSecurity\Authorization\Resource('tenant','account','fresh-user','probe'),['target'=>'probe'],['address']);
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($adapter,$token,$probeIntent):void{$adapter->begin('tenant','fresh-user',$token,$probeIntent);});
Check::same(0,$capturedAddressEvaluator->calls);Check::same(0,$capturedAddressEvaluator->selections);
if($case!=='role'){$legacy=$sdk->addressChange();Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($legacy,$policy,$token):void{$legacy->proposalFor($policy,'fresh-user','new@owned.example',$token,'owned-captured-address');});}
$unsupportedCalls=0;$audit=new SoSecurity\Audit\AuditLogger(static function()use(&$unsupportedCalls):void{++$unsupportedCalls;},str_repeat('a',32));
$plain=new class implements SoSecurity\Authorization\PolicyProvider {public function decide(SoSecurity\Auth\Account $actor,string $action,SoSecurity\Authorization\Resource $resource,array $fields=[]):?SoSecurity\Authorization\Decision{throw new RuntimeException('PRIVATE-ADDRESS-PLAIN');}};
foreach([new SoSecurity\Authorization\Authorizer(clone $provider,$capturedAddressPolicy),new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\SnapshotPolicy($capturedAddressEvaluator,clone $sql,hash('sha256','wrong-source'))),new SoSecurity\Authorization\Authorizer($provider,$plain),new SoSecurity\Authorization\Authorizer($provider,$capturedAddressPolicy,$audit)] as $unsupported){
 $ordinary=new SoSecurity\Operation\Grants($store,$sessions,$unsupported,static function():bool{return true;},$grants->policy(),$clock,$boundary);
 Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($ordinary,$policy):void{$ordinary->forAddress($policy);});
}
Check::same(0,$unsupportedCalls);Check::same($before,$witness->inspect(static function():bool{return true;}));Check::same($before['digest'],$source->digest());
$boundary->run('owned.address.captured.scope',static function()use($adapter,$probeIntent,$token):void{Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($adapter,$probeIntent,$token):void{$adapter->consumeForAddress('tenant','fresh-user',$token,$probeIntent,'og1.'.str_repeat('a',32).'.'.str_repeat('b',64),new SoSecurity\Support\Deadline(30000));});});
$before=$witness->inspect(static function():bool{return true;});
if($case==='reentry'){$capturedAddressEvaluator->hook=static function()use($address,$policy,$token):void{$address->proposalFor($policy,'fresh-user','new@owned.example',$token,'owned-captured-address');};}
if($case==='budget-before'){$capturedAddressEvaluator->hook=static function():void{usleep(11000000);};}
if(in_array($case,['deny','fields','fault','selector-fault','reentry','budget-before'],true)){
 $error=null;try{$address->proposalFor($policy,'fresh-user','new@owned.example',$token,'owned-captured-address');}catch(SoSecurity\Exception\SecurityException $caught){$error=$caught;}
 Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same($case==='budget-before'?'account.timeout':(in_array($case,['fault','selector-fault','reentry'],true)?'authorization.unavailable':'authorization.denied'),$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos((string)$error,'PRIVATE-ADDRESS')!==false);Check::same($before,$witness->inspect(static function():bool{return true;}));Check::same($before['digest'],$source->digest());
 echo 'PASS captured address admission '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;return;
}
$intent=$address->proposalFor($policy,'fresh-user','new@owned.example',$token,'owned-captured-address');Check::same(true,$intent instanceof SoSecurity\Operation\Intent);
$approve=static function(SoSecurity\Operation\Intent $intent)use($grants,$auth,$clock,$password,&$token):string{$pending=$grants->begin('tenant','fresh-user',$token,$intent);++$clock->time;$login=$auth->password('tenant','owned-captured-address','fresh@example.test',$password,'',$token);Check::same('authenticated',$login->status());$token=$login->credential()->token();$grant=$grants->confirm('tenant','fresh-user',$token,$intent,$pending->token());Check::same(true,$grant instanceof SoSecurity\Operation\Grant);return $grant->token();};
$grant=$approve($intent);
$proofPresent=static function()use($policy,$source,$clock,$grants,&$grant):bool{
 $reference=SoSecurity\Operation\State::reference($grant,'og1');$context=SoSecurity\Storage\ProofEpochStore::context('operations','tenant');$expected=$source->digest();
 $raw=$policy->credentialBytes(SoSecurity\Operation\State::context('tenant','fresh-user',$clock->time),$expected);$marker=SoSecurity\Storage\ProofEpochStore::markerBytes($policy->credentialBytes(SoSecurity\Storage\ProofEpochStore::key($context),$expected),$context);
 $state=SoSecurity\Operation\State::read(SoSecurity\Storage\ProofEpochStore::payload($raw===null?null:SoSecurity\Storage\Codec::decode($raw,$clock->time),$marker,$context),$grants->policy(),$clock->time);return isset($state['entries'][$reference['id']]);
};
Check::same(true,$proofPresent());$baseCalls=$capturedAddressEvaluator->calls;
$addressFinalProbe=static function(string $mode,bool $completion,callable $operation)use(
    &$nativeFinalHook,&$addressActionHook,$address,$policy,&$token,$clock,
    $witness,$source,$pdo,$proofPresent,$capturedAddressEvaluator,$sessions
):void{
    if(!in_array($mode,['guard','fault','expiry','reentry','budget'],true)){
        throw new RuntimeException('Unknown final address probe mode.');
    }
    $currentAllowed=true;$armed=false;$hookRan=false;$guardCallsAfterFinal=0;$reentryAttempted=false;$reentryAccepted=false;
    // Until the witness final hook, every existing guard phase remains allowed.
    $addressActionHook=static function(string $action,string $phase)use(
        &$currentAllowed,&$armed,&$guardCallsAfterFinal,&$reentryAttempted,&$reentryAccepted,
        $mode,$address,$policy,&$token
    ):bool{
        if($armed){
            ++$guardCallsAfterFinal;
            if($mode==='fault'){throw new RuntimeException('PRIVATE-ADDRESS-FINAL-GUARD');}
            if($mode==='reentry'){
                $reentryAttempted=true;
                $address->proposalFor($policy,'fresh-user','other@owned.example',$token,'owned-final-reentry');
                $reentryAccepted=true;
                throw new RuntimeException('Final address guard reentry was accepted.');
            }
        }
        return $currentAllowed;
    };
    // Installed AFTER approval and immediately BEFORE the selected business call.
    // This hook changes no SQL/file source and never throws from the budget callback.
    $nativeFinalHook=static function()use(&$currentAllowed,&$armed,&$hookRan,$mode,$clock):void{
        $hookRan=true;$armed=true;
        if($mode==='guard'){$currentAllowed=false;}
        if($mode==='expiry'){$clock->time+=301;}
        if($mode==='budget'){usleep(11000000);}
    };
    $error=null;
    try{$operation();}catch(SoSecurity\Exception\SecurityException $caught){$error=$caught;}
    Check::same(true,$hookRan);
    Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);
    if($mode==='budget'){
        Check::same(true,in_array($error->reason(),['account.operation_timeout','account.timeout'],true));
    }else{
        Check::same($mode==='guard'?'account.denied':($mode==='expiry'?'operation.expired':'account.authority'),$error->reason());
    }
    Check::same(null,$error->getPrevious());
    Check::same(false,strpos((string)$error,'PRIVATE-ADDRESS-FINAL-GUARD')!==false);
    if(!in_array($mode,['expiry','budget'],true)){Check::same(true,$guardCallsAfterFinal>=1);}
    if($mode==='reentry'){Check::same(true,$reentryAttempted);Check::same(false,$reentryAccepted);}
    $state=$witness->inspect(static function():bool{return true;});
    Check::same('current',$state['status']);Check::same($source->digest(),$state['digest']);
    Check::same(false,$proofPresent());
    Check::same(1,$capturedAddressEvaluator->lastAllowed);
    Check::same(1,(int)$pdo->query('SELECT allowed FROM owned_address_permissions')->fetchColumn());
    Check::same($completion?'new@owned.example':'fresh@example.test',$pdo->query('SELECT address FROM account_example')->fetchColumn());
    Check::same($completion?5:3,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());
    if($completion){Check::same(null,$sessions->verify('tenant','fresh-user',$token));}
    echo 'PASS final address '.($completion?'complete':'request').' '.$mode.' '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; committed current state retained, no continuation'.PHP_EOL;
};

// HELPER INSERTION: beside addressFinalProbe. The existing approved grant is NOT consumed.
// A second proposal is the selected operation, so the hook is still armed only after approval.
$addressProposalFinalDenyProbe=static function(bool $completion,callable $operation)use(
    &$nativeFinalHook,&$addressActionHook,$witness,$source,$pdo,$proofPresent
):void{
    $currentAllowed=true;$hookRan=false;$deniedAfterFinal=false;
    $addressActionHook=static function(string $action,string $phase)use(&$currentAllowed,&$deniedAfterFinal):bool{
        if(!$currentAllowed){$deniedAfterFinal=true;}
        return $currentAllowed;
    };
    Check::same(true,$proofPresent());
    $nativeFinalHook=static function()use(&$currentAllowed,&$hookRan):void{
        $currentAllowed=false;$hookRan=true;
    };
    $error=null;
    try{$operation();}catch(SoSecurity\Exception\SecurityException $caught){$error=$caught;}
    Check::same(true,$hookRan);Check::same(true,$deniedAfterFinal);
    Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);
    Check::same('account.denied',$error->reason());Check::same(null,$error->getPrevious());
    $state=$witness->inspect(static function():bool{return true;});
    Check::same('current',$state['status']);Check::same($source->digest(),$state['digest']);
    Check::same(true,$proofPresent());
    Check::same(1,(int)$pdo->query('SELECT allowed FROM owned_address_permissions')->fetchColumn());
    Check::same('fresh@example.test',$pdo->query('SELECT address FROM account_example')->fetchColumn());
    Check::same($completion?3:0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());
    echo 'PASS final address '.($completion?'completion proposal':'proposal').' guard '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; current state and unconsumed approved grant retained'.PHP_EOL;
};


if($case==='effect-deny'){$capturedAddressEvaluator->denyAt=$baseCalls+2;}
if($case==='return-deny'){$capturedAddressEvaluator->denyAt=$baseCalls+3;}
if($case==='effect-fault'){$capturedAddressEvaluator->faultAt=$baseCalls+2;}
if($case==='return-fault'){$capturedAddressEvaluator->faultAt=$baseCalls+3;}
if(in_array($case,['budget-effect','budget-return'],true)){$capturedAddressEvaluator->hookAt=$baseCalls+($case==='budget-effect'?2:3);$capturedAddressEvaluator->hook=static function():void{usleep(11000000);};}
if($case==='effect-reentry'){$capturedAddressEvaluator->hookAt=$baseCalls+2;$capturedAddressEvaluator->hook=static function()use($adapter,$token,$intent,$grant):void{$adapter->consumeForAddress('tenant','fresh-user',$token,$intent,$grant,new SoSecurity\Support\Deadline(30000));};}
$freshBudgetRefused=false;
if($case==='fresh-budget'){$addressActionHook=static function(string $action,string $phase)use($adapter,$token,$intent,$grant,&$freshBudgetRefused):bool{if($action==='request'&&$phase==='review'){usleep(11000000);try{$adapter->consumeForAddress('tenant','fresh-user',$token,$intent,$grant,new SoSecurity\Support\Deadline(30000));}catch(SoSecurity\Storage\StorageException $error){Check::same('account.timeout',$error->reason());$freshBudgetRefused=true;}}return true;};}
if($case==='changed'){$addressActionHook=static function(string $action,string $phase)use($pdo):bool{if($action==='request'&&$phase==='review'){$pdo->exec('UPDATE owned_address_permissions SET allowed=0');}return true;};}
if(in_array($case,['effect-deny','return-deny','effect-fault','return-fault','budget-effect','budget-return','effect-reentry','changed','fresh-budget'],true)){
 $error=null;try{$address->requestFor($policy,'fresh-user','new@owned.example',$token,$grant,'owned-captured-address');}catch(SoSecurity\Exception\SecurityException $caught){$error=$caught;}
 Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same('account.completion_unknown',$error->reason());$cause=$error->getPrevious();Check::same(true,$cause instanceof SoSecurity\Exception\SecurityException);Check::same($case==='fresh-budget'?'sql.timeout':(in_array($case,['budget-effect','budget-return'],true)?'account.timeout':(in_array($case,['effect-fault','return-fault','effect-reentry'],true)?'authorization.unavailable':'authorization.denied')),$cause->reason());Check::same(null,$cause->getPrevious());Check::same(false,strpos((string)$error,'PRIVATE-ADDRESS')!==false);
 Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);Check::same(!in_array($case,['return-deny','return-fault','budget-return'],true),$proofPresent());Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());Check::same('fresh@example.test',$pdo->query('SELECT address FROM account_example')->fetchColumn());
 if($case==='fresh-budget'){Check::same(true,$freshBudgetRefused);}
 if($case==='changed'){Check::same(0,(int)$pdo->query('SELECT allowed FROM owned_address_permissions')->fetchColumn());}
 echo 'PASS captured address effect '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.'; pending retained, no continuation'.PHP_EOL;return;
}
$lateFailure=static function(callable $operation,string $phase,bool $completion)use($pdo,$witness,$proofPresent,$capturedAddressEvaluator):void{
 $error=null;try{$operation();}catch(SoSecurity\Exception\SecurityException $caught){$error=$caught;}
 Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same('account.completion_unknown',$error->reason());
 Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);Check::same(false,$proofPresent());
 Check::same(0,$capturedAddressEvaluator->lastAllowed);Check::same(0,(int)$pdo->query('SELECT allowed FROM owned_address_permissions')->fetchColumn());Check::same($completion?'new@owned.example':'fresh@example.test',$pdo->query('SELECT address FROM account_example')->fetchColumn());Check::same($completion?5:3,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());
 echo 'PASS captured address late revocation '.($completion?'complete':'request').'-'.$phase.' '.Check::$assertions.' PHP '.PHP_VERSION.'; committed state and pending retained, no continuation'.PHP_EOL;
};
if(strpos($case,'request-late-')===0){$phase=substr($case,strlen('request-late-'));$addressActionHook=static function(string $action,string $at)use($pdo,$phase):bool{if($action==='request'&&$at===$phase){$pdo->exec('UPDATE owned_address_permissions SET allowed=0');}return true;};$lateFailure(static function()use($address,$policy,$token,$grant):void{$address->requestFor($policy,'fresh-user','new@owned.example',$token,$grant,'owned-captured-address');},$phase,false);return;}
if($case==='proposal-final-guard'){
    $addressProposalFinalDenyProbe(false,static function()use($address,$policy,$token):void{
        $address->proposalFor($policy,'fresh-user','new@owned.example',$token,'owned-captured-address');
    });
    return;
}
if(strpos($case,'request-final-')===0){
    $mode=substr($case,strlen('request-final-'));
    $addressFinalProbe($mode,false,static function()use($address,$policy,$token,$grant):void{
        $address->requestFor($policy,'fresh-user','new@owned.example',$token,$grant,'owned-captured-address');
    });
    return;
}


$address->requestFor($policy,'fresh-user','new@owned.example',$token,$grant,'owned-captured-address');Check::same(false,$proofPresent());

if($case==='request-flow-final-expiry'){
 $flow=json_decode($pdo->query("SELECT payload FROM sosecurity_account_records WHERE kind='change'")->fetchColumn(),true);Check::same(true,is_array($flow)&&is_int($flow['valid_until']));$clock->time=$flow['valid_until']-10;
 $intent=$address->proposalFor($policy,'fresh-user','new@owned.example',$token,'owned-captured-address');$grant=$approve($intent);$hookRan=false;$nativeFinalHook=static function()use($clock,&$hookRan):void{$hookRan=true;$clock->time+=20;};
 $error=null;try{$address->requestFor($policy,'fresh-user','new@owned.example',$token,$grant,'owned-captured-address');}catch(SoSecurity\Exception\SecurityException $caught){$error=$caught;}
 Check::same(true,$hookRan);Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same('operation.expired',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,$proofPresent());$current=$witness->inspect(static function():bool{return true;});Check::same('current',$current['status']);Check::same($source->digest(),$current['digest']);Check::same(6,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());Check::same('fresh@example.test',$pdo->query('SELECT address FROM account_example')->fetchColumn());
 echo 'PASS final address request flow expiry '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; expired committed flow retained, no continuation'.PHP_EOL;return;
}

$afterRequest=$witness->inspect(static function():bool{return true;});Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($address,$policy,$token,$grant):void{$address->requestFor($policy,'fresh-user','new@owned.example',$token,$grant,'owned-captured-address');});Check::same($afterRequest,$witness->inspect(static function():bool{return true;}));
$ids=$pdo->query('SELECT payload_body FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_COLUMN);Check::same(3,count($ids));$deliveries=$boundary->run('owned.address.captured.notices',static function()use($address,$ids):array{$deliveries=[];foreach($ids as $id){$delivery=$address->notification($id);$deliveries[$delivery->notice()->type()]=$delivery;}return $deliveries;});$selector=$deliveries['verify_address_new']->selector();
foreach(['old','new'] as $side){Check::same(true,$address->confirm($selector,$side,$deliveries['verify_address_'.$side]->notice()->token(),'owned-captured-address'));}
$intent=$address->completionProposalFor($policy,'fresh-user',$selector,$token,'owned-captured-address');$grant=$approve($intent);
if(strpos($case,'complete-late-')===0){$phase=substr($case,strlen('complete-late-'));$addressActionHook=static function(string $action,string $at)use($pdo,$phase):bool{if($action==='complete'&&$at===$phase){$pdo->exec('UPDATE owned_address_permissions SET allowed=0');}return true;};$lateFailure(static function()use($address,$policy,$selector,$token,$grant):void{$address->completeFor($policy,'fresh-user',$selector,$token,$grant,'owned-captured-address');},$phase,true);return;}
if($case==='completion-proposal-final-guard'){
    $addressProposalFinalDenyProbe(true,static function()use($address,$policy,$selector,$token):void{
        $address->completionProposalFor($policy,'fresh-user',$selector,$token,'owned-captured-address');
    });
    return;
}
if(strpos($case,'complete-final-')===0){
    $mode=substr($case,strlen('complete-final-'));
    $addressFinalProbe($mode,true,static function()use($address,$policy,$selector,$token,$grant):void{
        $address->completeFor($policy,'fresh-user',$selector,$token,$grant,'owned-captured-address');
    });
    return;
}

Check::same(true,$address->completeFor($policy,'fresh-user',$selector,$token,$grant,'owned-captured-address'));
Check::same('new@owned.example',$pdo->query('SELECT address FROM account_example')->fetchColumn());Check::same(null,$sessions->verify('tenant','fresh-user',$token));Check::same('current',$witness->inspect(static function():bool{return true;})['status']);Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);
Check::same(true,$case==='role'?$capturedAddressEvaluator->calls===0:$capturedAddressEvaluator->calls>=3);
echo 'PASS captured native address '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
