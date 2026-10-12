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
    public function __construct(AtomicStore $store,?Clock $clock=null) { $this->store=$store; $this->clock=$clock ?? new SystemClock(); }
    public function issue(string $subject,array $scopes=[],int $ttl=86400): Credential
    {
        Guard::label($subject); $scopes=Identity::validateScopes($scopes); Guard::duration($ttl);
        $now=$this->clock->now();
        if ($now<0 || $now>PHP_INT_MAX-$ttl) { throw new \SoSecurity\Exception\ConfigurationException('Clock cannot represent credential expiry.','configuration.clock'); }
        $expires=$now+$ttl;
        for ($attempt=0;$attempt<4;++$attempt) {
            $id=bin2hex(random_bytes(16)); $token='sosk_'.$id.'.'.bin2hex(random_bytes(32));
            $record=['v'=>1,'id'=>$id,'subject'=>$subject,'scopes'=>$scopes,'digest'=>hash('sha256',$token),'created'=>$now,'expires'=>$expires];
            $created=$this->store->transact($this->key($id),function ($old) use ($record) {
                if ($old!==null) { $this->record($old,$record['id']); return new Change($old,$old['expires'],false); }
                return new Change($record,$record['expires'],true);
            });
            if ($created) { return new Credential($token,new Identity($id,$subject,$scopes),$expires); }
        }
        throw new StorageException('Credential allocation exhausted.','api.capacity');
    }
    public function authenticate($token,?string $requiredScope=null): ?Identity
    {
        if ($requiredScope!==null) { Identity::validateScopes([$requiredScope]); }
        if (!is_string($token) || !preg_match('/\Asosk_([a-f0-9]{32})\.([a-f0-9]{64})\z/D',$token,$parts)) { return null; }
        $id=$parts[1]; $digest=hash('sha256',$token);
        $result=$this->store->transact($this->key($id),function ($record) use ($id,$digest,$requiredScope) {
            if ($record===null) { return new Change(null,0,null); }
            $this->record($record,$id); $identity=new Identity($id,$record['subject'],$record['scopes']);
            $now=$this->clock->now();
            $valid=$now>=0 && hash_equals($record['digest'],$digest) && $record['expires']>$now && ($requiredScope===null || $identity->allows($requiredScope));
            return new Change($record,$record['expires'],$valid?['identity'=>$identity,'expires'=>$record['expires']]:null);
        });
        $now=$this->clock->now();
        return $result===null || $now<0 || $result['expires']<=$now ? null : $result['identity'];
    }
    public function fromAuthorization($header,?string $requiredScope=null): ?Identity
    {
        if (!is_string($header) || strlen($header)>128 || !preg_match('/\ABearer +(sosk_[a-f0-9]{32}\.[a-f0-9]{64})\z/iD',$header,$parts)) { return null; }
        return $this->authenticate($parts[1],$requiredScope);
    }
    /** Same ID/identity/expiry, atomic digest replacement. Lost replies can invalidate the old key: host must recover explicitly. */
    public function rotate(string $id): ?Credential
    {
        $this->id($id); $token='sosk_'.$id.'.'.bin2hex(random_bytes(32)); $digest=hash('sha256',$token);
        return $this->store->transact($this->key($id),function ($record) use ($id,$token,$digest) {
            if ($record===null) { return new Change(null,0,null); }
            $this->record($record,$id);
            if ($record['expires']<=$this->clock->now()) { return new Change(null,0,null); }
            $record['digest']=$digest;
            return new Change($record,$record['expires'],new Credential($token,new Identity($id,$record['subject'],$record['scopes']),$record['expires']));
        });
    }
    public function revoke(string $id): bool
    {
        $this->id($id);
        return $this->store->transact($this->key($id),function ($record) { return new Change(null,0,$record!==null); });
    }
    private function id(string $id): void { if (!preg_match('/\A[a-f0-9]{32}\z/D',$id)) { throw new ValidationException('Invalid credential identifier.','api.identifier'); } }
    private function key(string $id): string { return 'api-key:'.hash('sha256',$id); }
    private function record(array $record,string $id): void
    {
        if (count($record)!==7 || ($record['v'] ?? null)!==1 || ($record['id'] ?? null)!==$id || !isset($record['subject'],$record['scopes'],$record['digest'],$record['created'],$record['expires'])
            || !is_string($record['subject']) || !is_array($record['scopes']) || !is_string($record['digest']) || !preg_match('/\A[a-f0-9]{64}\z/D',$record['digest'])
            || !is_int($record['created']) || !is_int($record['expires']) || $record['created']<0 || $record['expires']<$record['created']) {
            throw new StorageException('Corrupt API credential record.','storage.corrupt');
        }
        try { new Identity($id,$record['subject'],$record['scopes']); } catch (\InvalidArgumentException $e) { throw new StorageException('Corrupt API credential identity.','storage.corrupt',$e); }
    }
}
