<?php
declare(strict_types=1);
require __DIR__.'/account-factor/registered-support.php';
use SoSecurity\Account\FactorDirectoryState;
use SoSecurity\Account\LedgerState;
use SoSecurity\Account\Policy;
use SoSecurity\Mfa\ManagedFactorFrame;
use SoSecurity\Mfa\TotpFactorState;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\Codec;
use SoSecurity\Support\Guard;
if(!extension_loaded('sodium')){throw new RuntimeException('The state-codec integration requires sodium; do not count a skipped encrypted lifecycle as acceptance.');}
function codecReason(callable $body):string
{
    ++Check::$assertions;
    try{$body();}catch(SoSecurity\Exception\SecurityException $error){return $error->reason();}
    catch(SoSecurity\Exception\ConfigurationException $error){return $error->reason();}
    throw new RuntimeException('Expected authenticated state refusal.');
}
managedCase(static function(ManagedEnvironment $e):void{
    registeredSetup($e);$slot=$e->registry->current('user');$epoch=str_repeat('e',64);
    $site='account-factor-directory:'.hash('sha256',json_encode(['managed-test','user']));
    $namespace=hash('sha256',json_encode(['SoSecurity.Account.Ledger.1',$site,'tenant',$epoch],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
    $q=$e->pdo->prepare('SELECT * FROM sosecurity_account_roots WHERE namespace=?');$q->execute([$namespace]);$root=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();
    $q=$e->pdo->prepare('SELECT * FROM sosecurity_account_records WHERE namespace=?');$q->execute([$namespace]);$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();
    foreach(SoSecurity\Account\Ledger::rootTypes() as $field=>$type){if($type==='int'){$root[$field]=SoSecurity\Support\SqlSchema::integer($root[$field]);}}
    foreach(SoSecurity\Account\Ledger::recordTypes() as $field=>$type){if($type==='int'){$row[$field]=SoSecurity\Support\SqlSchema::integer($row[$field]);}}
    $policy=new Policy();$queries=$e->pdo->queries;
    $decode=static function(array $r,array $v)use($e,$namespace,$epoch,$policy):array{
        $r=LedgerState::authenticate($r,true,$namespace,$epoch,$policy->fingerprint(),1,$policy->maximumEntries(),$e->keys,$e->clock->time);
        $payload=$v['payload'];unset($v['payload']);$v['body_length']=strlen($payload);
        $v=LedgerState::authenticate($v,false,$namespace,$epoch,$policy->fingerprint(),1,$policy->maximumEntries(),$e->keys,$e->clock->time);
        LedgerState::single($r,$v,1);$v['payload']=LedgerState::payload($v,$payload);
        return FactorDirectoryState::read('managed-test','tenant',$epoch,$v,'user');
    };
    $data=$decode($root,$row);Check::same($slot->factorId(),$data['factor_id']);Check::same($slot->binding(),FactorDirectoryState::binding('managed-test','tenant',$epoch,$data));Check::same($queries,$e->pdo->queries);
    // Install signed but semantically invalid synthetic directory data, so rejection cannot be attributed only to an invalid outer HMAC.
    $install=static function(string $payload)use($e,$row,$root,$namespace):array{
        $v=$row;$v['payload']=$payload;$v['payload_bytes']=strlen($payload);$v['payload_digest']=hash('sha256',$payload);$v['seal']=bin2hex($e->keys->sign(LedgerState::encoded($v,false)));
        $r=$root;$r['history_digest']=hash('sha256','SoSecurity.Account.History.1.'.$namespace.$v['record_id'].$v['seal']);$r['seal']=bin2hex($e->keys->sign(LedgerState::encoded($r,true)));
        $e->pdo->beginTransaction();
        try{
            $q=$e->pdo->prepare('UPDATE sosecurity_account_records SET payload=:payload,payload_bytes=:bytes,payload_digest=:digest,seal=:seal WHERE namespace=:namespace');
            $q->bindValue(':payload',$payload,PDO::PARAM_LOB);$q->bindValue(':bytes',$v['payload_bytes'],PDO::PARAM_INT);$q->bindValue(':digest',$v['payload_digest']);$q->bindValue(':seal',$v['seal']);$q->bindValue(':namespace',$namespace);$q->execute();$q->closeCursor();
            $q=$e->pdo->prepare('UPDATE sosecurity_account_roots SET history_digest=?,seal=? WHERE namespace=?');$q->execute([$r['history_digest'],$r['seal'],$namespace]);$q->closeCursor();$e->pdo->commit();
        }catch(Throwable $error){if($e->pdo->inTransaction()){$e->pdo->rollBack();}throw $error;}
        return [$r,$v];
    };
    foreach(['subject','factor_id','extra','origin'] as $case){
        $bad=$data;
        if($case==='subject'){$bad['subject']='another-user';}
        elseif($case==='factor_id'){$bad['factor_id']='bad';}
        elseif($case==='origin'){$bad['origin']='unknown';}
        else{$bad['extra']='unexpected';}
        list($r,$v)=$install(json_encode($bad,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        Check::same('account.factor_corrupt',codecReason(static function()use($decode,$r,$v):void{$decode($r,$v);}));
        Check::same('account.factor_corrupt',codecReason(static function()use($e):void{$e->registry->current('user');}));
        $install($row['payload']);
    }
    Check::same($slot->binding(),$e->registry->current('user')->binding());
    // Capture the actual managed FileStore envelope. The pure readers have no PDO, authority callback, or storage handle.
    $files=glob($e->directory.'/factors/*.json');Check::same(1,count($files));$path=$files[0];$before=file_get_contents($path);$raw=Codec::decode($before,$e->clock->time);
    $context=hash('sha256',json_encode(['SoSecurity.Mfa.ManagedContext.1','managed-test','tenant',$epoch],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));$key=Guard::key('mfa-totp','tenant','user');$queries=$e->pdo->queries;
    $frame=ManagedFactorFrame::read($context,$e->keys,$key,$raw);$factor=TotpFactorState::read($frame['payload'],$e->clock->time);
    Check::same($slot->factorId(),$factor['enabled']['id']);Check::same(null,$factor['pending']);Check::same($queries,$e->pdo->queries);Check::same($before,file_get_contents($path));
    foreach(['seal','context','migration'] as $case){
        $bad=$raw;
        if($case==='seal'){$bad['seal']=str_repeat('0',64);}
        elseif($case==='context'){$bad['context']=str_repeat('0',64);}
        else{$bad['v']=3;$bad['migration']=['state'=>'committed'];}
        $expected=codecReason(static function()use($context,$e,$key,$bad):void{ManagedFactorFrame::read($context,$e->keys,$key,$bad);});
        try{file_put_contents($path,Codec::encode(new Change($bad,0,null)));Check::same($expected,codecReason(static function()use($e):void{$e->factors->status('tenant','user');}));}
        finally{file_put_contents($path,$before);}
    }
    $badFactor=$factor;$badFactor['pending']=$factor['enabled']+['expires'=>$e->clock->time];$badFactor['failures']=1;$badFactor['blocked_until']=$e->clock->time;
    $normalized=TotpFactorState::read($badFactor,$e->clock->time);Check::same(null,$normalized['pending']);Check::same(0,$normalized['failures']);Check::same(1,$badFactor['failures']);Check::same($before,file_get_contents($path));
});
$hookCalls=0;$object=new class($hookCalls) implements JsonSerializable {
    private $calls;
    public function __construct(int &$calls){$this->calls=&$calls;}
    #[\ReturnTypeWillChange]
    public function jsonSerialize(){++$this->calls;return 'must-not-run';}
};
Check::same('mfa.managed_corrupt',codecReason(static function()use($object):void{ManagedFactorFrame::encode(['untrusted'=>$object]);}));Check::same(0,$hookCalls);
echo 'PASS shared state codecs: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; real registered directory/managed envelope and pure views agree on malformed state, with no pure-reader SQL or physical writes',PHP_EOL;
