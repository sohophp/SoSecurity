<?php
declare(strict_types=1);
namespace SoSecurity\Api;

use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use SoSecurity\Support\Guard;
use SoSecurity\Exception\ValidationException;

/** Random bearer credentials; storage contains digest/identity/expiry, never the plaintext token. */
final class ApiKeys
{
    private $store;
    private $clock;
    private $state;
    private $nativeBusy=false;
    public function __construct(AtomicStore $store,?Clock $clock=null,?\SoSecurity\Account\StateApiKeyConnection $state=null) { $this->store=$store; $this->clock=$clock ?? new SystemClock();$this->state=$state;if($state!==null){$state->validate($store,$this->clock);} }
    public function issue(string $subject,array $scopes=[],int $ttl=86400): Credential
    {
        Guard::label($subject); $scopes=Identity::validateScopes($scopes); Guard::duration($ttl);
        if($this->state!==null){return $this->nativeIssue($subject,$scopes,$ttl);}
        $now=$this->now();
        if ($now<0 || $now>PHP_INT_MAX-$ttl) { throw new \SoSecurity\Exception\ConfigurationException('Clock cannot represent credential expiry.','configuration.clock'); }
        $expires=$now+$ttl;$seen=$now;$epoch=$this->epoch($subject);if(!$this->current($seen,$expires)){throw new \SoSecurity\Exception\SecurityException('Credential issuance expired before allocation.','api.expired');}
        for ($attempt=0;$attempt<4;++$attempt) {
            $id=bin2hex(random_bytes(16)); $token='sosk_'.$id.'.'.bin2hex(random_bytes(32));
            $record=['v'=>$epoch===null?1:2,'id'=>$id,'subject'=>$subject,'scopes'=>$scopes,'digest'=>hash('sha256',$token),'created'=>$now,'expires'=>$expires];if($epoch!==null){$record['epoch']=$epoch;}
            $created=$this->store->transact($this->key($id),function ($old) use ($record) {
                if ($old!==null) { $this->record($old,$record['id']); return new Change($old,$old['expires'],false); }
                return new Change($record,$record['expires'],true);
            });
            if ($created) {try{if(!$this->current($seen,$expires)){throw new \RuntimeException('Issuance expired.');}if($this->epoch($subject)!==$epoch||!$this->current($seen,$expires)){throw new \RuntimeException('Issuance changed.');}}catch(\Throwable $error){throw new StorageException('Credential issuance completion is unknown.','api.issuance_unknown');}return new Credential($token,new Identity($id,$subject,$scopes),$expires); }
            if(!$this->current($seen,$expires)){throw new \SoSecurity\Exception\SecurityException('Credential issuance expired before allocation.','api.expired');}
        }
        throw new StorageException('Credential allocation exhausted.','api.capacity');
    }
    public function authenticate($token,?string $requiredScope=null): ?Identity
    {
        if ($requiredScope!==null) { Identity::validateScopes([$requiredScope]); }
        if (!is_string($token) || !preg_match('/\Asosk_([a-f0-9]{32})\.([a-f0-9]{64})\z/D',$token,$parts)) { return null; }
        if($this->state!==null){return $this->native('authenticate',$parts[1],['digest'=>hash('sha256',$token),'scope'=>$requiredScope]);}
        $id=$parts[1];$digest=hash('sha256',$token);$now=$this->now();if($now<0){return null;}
        $record=$this->store->transact($this->key($id),function($record)use($id,$digest,$requiredScope,$now){
            if($record===null){return new Change(null,0,null);}$this->record($record,$id);$identity=new Identity($id,$record['subject'],$record['scopes']);
            return new Change($record,$record['expires'],hash_equals($record['digest'],$digest)&&$record['created']<=$now&&$record['expires']>$now&&($requiredScope===null||$identity->allows($requiredScope))?$record:null);
        });
        if($record===null){return null;}$seen=$now;if(!$this->current($seen,$record['expires'])){return null;}$epoch=$this->epoch($record['subject']);if(!$this->allowedEpoch($record,$epoch)||!$this->current($seen,$record['expires'])){return null;}
        $current=$this->store->transact($this->key($id),function($current)use($record,$id){if($current!==null){$this->record($current,$id);}return new Change($current,$current===null?0:$current['expires'],$current===$record);});
        if(!$current||!$this->current($seen,$record['expires'])){return null;}$finalEpoch=$this->epoch($record['subject']);return $finalEpoch!==$epoch||!$this->current($seen,$record['expires'])?null:new Identity($id,$record['subject'],$record['scopes']);
    }
    public function fromAuthorization($header,?string $requiredScope=null): ?Identity
    {
        if (!is_string($header) || strlen($header)>128 || !preg_match('/\ABearer +(sosk_[a-f0-9]{32}\.[a-f0-9]{64})\z/iD',$header,$parts)) { return null; }
        return $this->authenticate($parts[1],$requiredScope);
    }
    /** Same ID/identity/expiry, atomic digest replacement. Lost replies can invalidate the old key: host must recover explicitly. */
    public function rotate(string $id): ?Credential
    {
        $this->id($id);if($this->state!==null){$this->state->assertEntry();return $this->native('rotate',$id,['token'=>'sosk_'.$id.'.'.bin2hex(random_bytes(32))]);}$now=$this->now();if($now<0){return null;}
        $old=$this->store->transact($this->key($id),function($record)use($id,$now){if($record===null){return new Change(null,0,null);}$this->record($record,$id);return new Change($record,$record['expires'],$record['created']<=$now&&$record['expires']>$now?$record:null);});
        if($old===null){return null;}$seen=$now;if(!$this->current($seen,$old['expires'])){return null;}$epoch=$this->epoch($old['subject']);if(!$this->allowedEpoch($old,$epoch)||!$this->current($seen,$old['expires'])){return null;}$token='sosk_'.$id.'.'.bin2hex(random_bytes(32));$digest=hash('sha256',$token);
        $rotated=$this->store->transact($this->key($id),function($record)use($old,$digest,$id){if($record!==null){$this->record($record,$id);}if($record!==$old){return new Change($record,$record===null?0:$record['expires'],false);}$record['digest']=$digest;return new Change($record,$record['expires'],true);});
        if(!$rotated){return null;}try{if(!$this->current($seen,$old['expires'])){throw new \RuntimeException('Rotation expired.');}if($this->epoch($old['subject'])!==$epoch||!$this->current($seen,$old['expires'])){throw new \RuntimeException('Rotation changed.');}}catch(\Throwable $error){throw new StorageException('Credential rotation completion is unknown.','api.rotation_unknown');}return new Credential($token,new Identity($id,$old['subject'],$old['scopes']),$old['expires']);
    }
    public function revoke(string $id): bool
    {
        $this->id($id);if($this->state!==null){return $this->native('revoke',$id,[])===true;}
        return $this->store->transact($this->key($id),function ($record) { return new Change(null,0,$record!==null); });
    }
    private function nativeTick(\SoSecurity\Support\Deadline $deadline,int &$seen):int
    {
        $deadline->check('api.timeout');$now=$this->now();if($now<0||$now>PHP_INT_MAX-31536001||$now<$seen){throw new StorageException('Invalid API credential time.','api.clock');}$seen=$now;return $now;
    }
    private function nativeValue(string $key,string $expected):?array
    {
        $raw=$this->state->bytes($key,$expected);if($raw===null){return null;}$value=\SoSecurity\Storage\Codec::decode($raw,0);$envelope=json_decode($raw,true,32);return ['value'=>$value,'expires'=>$envelope['expires']];
    }
    private function nativeEpoch(string $subject,string $expected):?string
    {
        $v=$this->nativeValue($this->epochKey($subject),$expected);if($v===null){return null;}if($v['expires']!==0){throw new StorageException('Permanent API epoch cannot expire.','storage.corrupt');}return $this->epochState($v['value'],$subject);
    }
    private function nativeIssue(string $subject,array $scopes,int $ttl):Credential
    {
        if(preg_match('//u',$subject)!==1){throw new \SoSecurity\Exception\ConfigurationException('Native API key subjects must be UTF-8.','configuration.state_api_keys');}
        $this->state->assertEntry();$deadline=new \SoSecurity\Support\Deadline($this->state->milliseconds());$seen=0;$created=$this->nativeTick($deadline,$seen);$expires=$created+$ttl;
        // Candidate randomness is outside every read-only admission callback.
        for($attempt=0;$attempt<4;++$attempt){$id=bin2hex(random_bytes(16));$token='sosk_'.$id.'.'.bin2hex(random_bytes(32));$collision=false;
            $result=$this->native('issue',$id,['subject'=>$subject,'scopes'=>$scopes,'created'=>$created,'expires'=>$expires,'token'=>$token],$deadline,$seen,$collision);
            if($result instanceof Credential){return $result;}if(!$collision){throw new \SoSecurity\Exception\SecurityException('API key issuance denied.','api.denied');}
        }throw new StorageException('Credential allocation exhausted.','api.capacity');
    }
    private function native(string $action,string $id,array $input,?\SoSecurity\Support\Deadline $budget=null,int &$initialSeen=0,?bool &$collision=null)
    {
        if($this->nativeBusy){throw new \SoSecurity\Exception\ConfigurationException('Do not nest native API key operations.','configuration.state_request_nested');}$this->nativeBusy=true;
        $deadline=$budget??new \SoSecurity\Support\Deadline($this->state->milliseconds());$seen=$initialSeen;$admitted=null;$read=null;
        try{
            $result=$this->state->run($action,function(string $expected)use($action,$id,$input,$deadline,&$seen,&$admitted,&$read,&$collision){
                $now=$this->nativeTick($deadline,$seen);$value=$this->nativeValue($this->key($id),$expected);$old=$value===null?null:$value['value'];
                if($old!==null){$this->record($old,$id);if($value['expires']!==$old['expires']){throw new StorageException('Credential storage expiry differs from its record.','storage.corrupt');}}
                if($action==='issue'){
                    if($old!==null&&$old['expires']>$now){$collision=true;return false;}$subject=$input['subject'];$epoch=$this->nativeEpoch($subject,$expected);
                    $next=['v'=>$epoch===null?1:2,'id'=>$id,'subject'=>$subject,'scopes'=>$input['scopes'],'digest'=>hash('sha256',$input['token']),'created'=>$input['created'],'expires'=>$input['expires']];if($epoch!==null){$next['epoch']=$epoch;}$old=null;
                }else{
                    if($old===null){return false;}$subject=$old['subject'];$next=$old;$epoch=null;
                    if($action!=='revoke'){
                        if($old['created']>$now||$old['expires']<=$now){return false;}$epoch=$this->nativeEpoch($subject,$expected);if(!$this->allowedEpoch($old,$epoch)){return false;}
                    }
                    if($action==='authenticate'&&(!hash_equals($old['digest'],$input['digest'])||($input['scope']!==null&&!(new Identity($id,$subject,$old['scopes']))->allows($input['scope'])))){return false;}
                    if($action==='rotate'){$next['digest']=hash('sha256',$input['token']);}
                }
                $metadata=['id'=>$id,'scopes'=>$next['scopes'],'created'=>$next['created'],'expires'=>$next['expires']];$actor=$this->state->authority($action,$subject,$metadata);$now=$this->nativeTick($deadline,$seen);if($actor===null){return false;}
                if($action!=='revoke'&&($next['created']>$now||$next['expires']<=$now)){return false;}
                if($action==='issue'&&!$this->state->capacity($this->key($id),$expected)){throw new \SoSecurity\Exception\SecurityException('API key physical capacity reached.','api.capacity');}
                $now=$this->nativeTick($deadline,$seen);if($action!=='revoke'&&$next['expires']<=$now){return false;}
                $admitted=['old'=>$old,'next'=>$next,'subject'=>$subject,'epoch'=>$epoch,'actor'=>$actor,'metadata'=>$metadata];
                if($action==='authenticate'){$read=new Identity($id,$subject,$old['scopes']);return false;}
                $request=hash('sha256',json_encode(['SoSecurity.ApiKeys.Native.Request.1',$action,$id,$next,$epoch,$expected]));
                return \SoSecurity\Account\StateOperation::legacyApi('api.keys.'.$action,$this->state->scope(),$actor,hash('sha256',$id),$request,$this->state->binding(),$now);
            },function()use($action,$id,$input,$deadline,&$seen,&$admitted){
                /** @var array|null $admitted Assigned by the preceding admission callback. */
                if($admitted===null){throw new StorageException('Missing admitted API key operation.','api.changed');}$a=$admitted;
                $now=$this->nativeTick($deadline,$seen);if($this->state->authority($action,$a['subject'],$a['metadata'])!==$a['actor']){throw new \SoSecurity\Exception\SecurityException('API key authority changed.','api.denied');}$now=$this->nativeTick($deadline,$seen);
                if($action!=='revoke'&&($a['next']['created']>$now||$a['next']['expires']<=$now)){throw new \SoSecurity\Exception\SecurityException('Admitted API key expired.','api.expired');}
                $expired=$a['old']!==null&&$a['old']['expires']<=$now;
                $written=$this->store->transact($this->key($id),function($old)use($a,$action,$expired){
                    if($old!==$a['old']&&!($action==='revoke'&&$expired&&$old===null)){return new Change($old,$old===null?0:$old['expires'],false);}
                    return $action==='revoke'?new Change(null,0,true):new Change($a['next'],$a['next']['expires'],true);
                });
                if(!$written){throw new StorageException('Admitted API key record changed.','api.changed');}$now=$this->nativeTick($deadline,$seen);
                if($action!=='revoke'&&$this->epoch($a['subject'])!==$a['epoch']){throw new StorageException('Admitted API key epoch changed.','api.changed');}
                $this->nativeTick($deadline,$seen);$current=$this->store->transact($this->key($id),static function($v){return new Change($v,$v===null?0:$v['expires'],$v);});
                if($current!==($action==='revoke'?null:$a['next'])){throw new StorageException('API key completion changed.','api.changed');}
                if($this->state->authority($action,$a['subject'],$a['metadata'])!==$a['actor']){throw new \SoSecurity\Exception\SecurityException('API key completion denied.','api.denied');}$now=$this->nativeTick($deadline,$seen);
                if($action!=='revoke'&&$a['next']['expires']<=$now){throw new \SoSecurity\Exception\SecurityException('API key completion expired.','api.expired');}
                return $action==='revoke'?true:new Credential($input['token'],new Identity($id,$a['subject'],$a['next']['scopes']),$a['next']['expires']);
            });
            if($action==='authenticate'&&$read!==null){
                /** @var array $admitted Authenticated read admission populated this context. */
                $now=$this->nativeTick($deadline,$seen);return $admitted['next']['expires']<=$now?null:$read;
            }
            return $result;
        }finally{$initialSeen=$seen;$this->nativeBusy=false;}
    }
    private function now():int
    {
        try{return $this->clock->now();}catch(\Throwable $error){throw new StorageException('API credential clock unavailable.','api.clock');}
    }
    /** Observe after I/O; never extend the original expiry or accept backwards time.
     * @phpstan-impure
     */
    private function current(int &$seen,int $expires):bool
    {
        $now=$this->now();if($now<$seen||$now>=$expires){return false;}$seen=$now;return true;
    }
    private function epochKey(string $subject):string{Guard::label($subject);return 'api-key-epoch:'.hash('sha256',$subject);}
    private function epoch(string $subject):?string
    {
        return $this->store->transact($this->epochKey($subject),function($state)use($subject){
            return new Change($state,0,$this->epochState($state,$subject));
        });
    }
    private function epochState(?array $state,string $subject):?string
    {
        if($state===null){return null;}if(array_keys($state)!==['v','subject','epoch']||$state['v']!==1||$state['subject']!==$subject||!is_string($state['epoch'])||preg_match('/\A[a-f0-9]{64}\z/D',$state['epoch'])!==1){throw new StorageException('Corrupt permanent API key epoch.','storage.corrupt');}return $state['epoch'];
    }
    private function allowedEpoch(array $record,?string $epoch):bool{return $record['v']===1?$epoch===null:($epoch!==null&&hash_equals($record['epoch'],$epoch));}
    /** Pure native coordinate and fixed bytes, never a write or approval. Legacy subjects have no inferred tenant mapping. */
    public function stateEpoch(\SoSecurity\Storage\FileStore $store,Clock $clock,string $subject,string $epoch):?array
    {
        if($this->store!==$store||$this->clock!==$clock){return null;}if(preg_match('/\A[a-f0-9]{64}\z/D',$epoch)!==1){throw new \SoSecurity\Exception\ConfigurationException('Use an exact API key epoch.','configuration.api_epoch');}$key=$this->epochKey($subject);$context=hash('sha256','SoSecurity.ApiKeys.Epoch.Context.1.'.json_encode($store->snapshotReference($this->epochKey('state-api-context'))));
        return ['context'=>$context,'key'=>$key,'reference'=>$store->snapshotReference($key),'after'=>\SoSecurity\Storage\Codec::encode(new Change(['v'=>1,'subject'=>$subject,'epoch'=>$epoch],0,true))];
    }
    private function id(string $id): void { if (!preg_match('/\A[a-f0-9]{32}\z/D',$id)) { throw new ValidationException('Invalid credential identifier.','api.identifier'); } }
    private function key(string $id): string { return 'api-key:'.hash('sha256',$id); }
    private function record(array $record,string $id): void
    {
        if (!in_array($record['v']??null,[1,2],true)||count($record)!==($record['v']===1?7:8)||($record['v']===2&&(!is_string($record['epoch']??null)||preg_match('/\A[a-f0-9]{64}\z/D',$record['epoch'])!==1)) || ($record['id'] ?? null)!==$id || !isset($record['subject'],$record['scopes'],$record['digest'],$record['created'],$record['expires'])
            || !is_string($record['subject']) || !is_array($record['scopes']) || !is_string($record['digest']) || !preg_match('/\A[a-f0-9]{64}\z/D',$record['digest'])
            || !is_int($record['created']) || !is_int($record['expires']) || $record['created']<0 || $record['expires']<$record['created']) {
            throw new StorageException('Corrupt API credential record.','storage.corrupt');
        }
        try { new Identity($id,$record['subject'],$record['scopes']); } catch (\InvalidArgumentException $e) { throw new StorageException('Corrupt API credential identity.','storage.corrupt',$e); }
    }
}
