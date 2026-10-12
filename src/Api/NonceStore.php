<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use SoSecurity\Support\Guard;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

final class NonceStore
{
    private $store;
    private $clock;
    private $maximumTtl;
    public function __construct(AtomicStore $store,?Clock $clock=null,int $maximumTtl=3600)
    {
        if ($maximumTtl<1 || $maximumTtl>86400) { throw new ConfigurationException('Nonce TTL bound must be 1-86400 seconds.'); }
        $this->store=$store; $this->clock=$clock ?? new SystemClock(); $this->maximumTtl=$maximumTtl;
    }
    /** Call only after signature/identity/time checks; invalid signatures must not allocate nonce records. */
    public function consume(string $scope,string $nonce,int $expiresAt): bool
    {
        Guard::label($scope);
        if (!preg_match('/\A[A-Za-z0-9_-]{16,128}\z/D',$nonce)) { throw new ValidationException('Invalid nonce.','api.nonce'); }
        $now=$this->clock->now();
        if ($expiresAt<=$now || $expiresAt-$now>$this->maximumTtl) { return false; }
        $key='api-nonce:'.hash('sha256',strlen($scope).':'.$scope.':'.$nonce);
        return $this->store->transact($key,function ($record) use ($expiresAt) {
            if ($record!==null) {
                if (count($record)!==3 || ($record['v'] ?? null)!==1 || ($record['used'] ?? null)!==true || !isset($record['expires']) || !is_int($record['expires']) || $record['expires']<1) { throw new StorageException('Corrupt nonce record.','storage.corrupt'); }
                return new Change($record,$record['expires'],false);
            }
            if ($expiresAt<=$this->clock->now()) { return new Change(null,0,false); }
            return new Change(['v'=>1,'used'=>true,'expires'=>$expiresAt],$expiresAt,true);
        });
    }
}
