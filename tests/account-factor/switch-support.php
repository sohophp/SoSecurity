<?php
declare(strict_types=1);
require __DIR__.'/support.php';
function switchService(ManagedEnvironment $e,callable $approval,?callable $event=null,?callable $authority=null,?callable $budget=null,?SoSecurity\Account\LocalEpochFence $fence=null):SoSecurity\Account\FactorRecovery
{
    $mysql=($GLOBALS['argv'][1]??'')==='mysql';
    foreach(['sosecurity_outbox_records','sosecurity_outbox_roots'] as $table){$e->pdo->exec('DROP TABLE IF EXISTS '.$table);}
    $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__,2).'/resources/sql/outbox-'.($mysql?'mysql':'sqlite').'.sql'));
    foreach(explode(';',$ddl) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},new SoSecurity\Outbox\Policy(),$e->clock,static function():bool{return true;});$queue->initialize('tenant','factor-recovery','system');
    $events=static function(string $type,string $scope,?SoSecurity\Account\AccountRecord $before,?SoSecurity\Account\AccountRecord $after,string $selector)use($queue,$e,$event):bool{
        $queue->enqueue(new SoSecurity\Outbox\Message($scope,'factor-recovery',SoSecurity\Outbox\Message::identifier($type.':'.$selector,$e->clock->time),'mail',$type,$selector,$selector),'system');
        return $event===null||$event($type,$before,$after,$selector)===true;
    };
    return $e->registry->recovery($authority??static function():bool{return true;},$budget??static function():bool{return true;},$approval,$events,$fence);
}
function switchLogin(ManagedEnvironment $e):array
{
    $hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);$dummy=$hasher->hash('Owned dummy switch password 49!');
    $provider=new SoSecurity\Auth\PasswordIdentityProvider(function(string $scope,string $identifier)use($e){$r=$e->accounts->findAddress($scope,new SoSecurity\Account\Address($identifier));return $r===null?null:$e->accounts->passwordRecord($r);},function(string $scope,string $subject)use($e){$r=$e->accounts->find($scope,$subject);return $r===null?null:$e->accounts->passwordRecord($r);},$hasher,$dummy);
    $store=new SoSecurity\Storage\FileStore($e->directory.'/factors','managed-switch-auth',$e->clock);$adapter=$e->registry->secondFactor();$sessions=new SoSecurity\Auth\SessionRegistry($store,$provider,$adapter,$e->clock);$flow=new SoSecurity\Auth\AuthenticationFlow($store,$provider,$sessions,static function():bool{return true;},$adapter,$e->clock);
    $pending=$flow->password('tenant','browser','owned@example.test',$e->password);$e->clock->time=(intdiv($e->clock->time,30)+1)*30;
    $login=$flow->secondFactor('tenant','browser',$pending->challenge(),['type'=>'totp','code'=>(new SoSecurity\Mfa\Totp())->codeAt($e->secret,$e->clock->time)]);
    Check::same('authenticated',$login->status());return [$flow,$sessions,$login];
}
function switchProvision(SoSecurity\Account\FactorRecovery $service,ManagedEnvironment $e):array
{
    $pending=$service->begin('user','owned-source');parse_str(parse_url($pending->enrollment()->provisioningUri(),PHP_URL_QUERY),$parts);return [$pending,$parts['secret']];
}
function switchApproval(array &$receipt):callable
{
    return static function(string $phase,SoSecurity\Account\FactorReplacementApproval $request,array $proof)use(&$receipt):bool{
        $receipt['phases'][]=$phase;
        if($request->purpose()!=='replace_factor'||$request->context()!==($receipt['context']??null)||$proof!==['type'=>'approved','code'=>'owned-strong-approval']){return false;}
        if($phase==='verify'){if($receipt['spent']??false){return false;}$receipt['spent']=true;return true;}
        return ($receipt['spent']??false)===true;
    };
}
function switchPrepareProven(ManagedEnvironment $e,SoSecurity\Account\FactorRecovery $service,array &$receipt):array
{
    list($pending,$secret)=switchProvision($service,$e);$codes=$service->prove($pending->selector(),(new SoSecurity\Mfa\Totp())->codeAt($secret,$e->clock->time),'owned-source');
    if($codes===null){throw new RuntimeException('Owned preparation proof failed.');}$review=$service->approvalRequest($pending->selector(),'owned-review');$receipt['context']=$review->context();return [$pending,$secret,$codes,$review];
}
function switchReadFlow(ManagedEnvironment $e,string $selector):array
{
    $q=$e->pdo->prepare('SELECT payload FROM sosecurity_account_records WHERE record_id=?');$q->execute([$selector]);$row=$q->fetchColumn();$q->closeCursor();return json_decode($row,true);
}
