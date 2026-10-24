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
    public function stateContext(AtomicStore $store,Clock $clock):bool{return $this->store===$store&&$this->clock===$clock;}
    public function maximumTtl():int{return $this->maximumTtl;}
    public function assertActive():void{\SoSecurity\Storage\FileStateBoundary::assertStoreActive($this->store);}
    public static function stateKey(string $scope,string $nonce):string
    {
        Guard::label($scope);if(!preg_match('/\A[A-Za-z0-9_-]{16,128}\z/D',$nonce)){throw new ValidationException('Invalid nonce.','api.nonce');}return 'api-nonce:'.hash('sha256',strlen($scope).':'.$scope.':'.$nonce);
    }
    private static function validate($record):void
    {
        if($record!==null&&(!is_array($record)||count($record)!==3||($record['v']??null)!==1||($record['used']??null)!==true||!isset($record['expires'])||!is_int($record['expires'])||$record['expires']<1)){throw new StorageException('Corrupt nonce record.','storage.corrupt');}
    }
    /** Exact read-only native admission, using the same representation and lifetime bound. */
    public function stateAvailable(?string $raw,int $now,int $expiresAt):bool
    {
        if($now<0||$expiresAt<=$now||$expiresAt-$now>$this->maximumTtl){return false;}$record=$raw===null?null:\SoSecurity\Storage\Codec::decode($raw,$now);self::validate($record);return $record===null;
    }
    /** Call only after signature/identity/time checks; invalid signatures must not allocate nonce records. */
    public function consume(string $scope,string $nonce,int $expiresAt): bool
    {
        $this->assertActive();$key=self::stateKey($scope,$nonce);$now=$this->clock->now();if($now<0||$expiresAt<=$now||$expiresAt-$now>$this->maximumTtl){return false;}
        $created=$this->store->transact($key,static function($record)use($expiresAt):Change{
            self::validate($record);if($record!==null){return new Change($record,$record['expires'],false);}return new Change(['v'=>1,'used'=>true,'expires'=>$expiresAt],$expiresAt,true);
        });
        if(!$created){return false;}$later=$this->clock->now();return $later>=$now&&$later<$expiresAt;
    }
}
