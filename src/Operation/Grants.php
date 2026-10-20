<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Prepare -> new reauthentication -> explicit confirmation -> atomic one-use consume. No business effects in callbacks. */
final class Grants
{
    private $store;
    private $sessions;
    private $authorizer;
    private $guard;
    private $policy;
    private $clock;
    public function __construct(AtomicStore $store,SessionRegistry $sessions,Authorizer $authorizer,callable $requestGuard,?Policy $policy = null,?Clock $clock = null)
    {
        $this->store=$store;$this->sessions=$sessions;$this->authorizer=$authorizer;$this->guard=$requestGuard;$this->policy=$policy ?? new Policy();$this->clock=$clock ?? new SystemClock();
    }
    public function policy(): Policy { return $this->policy; }
    public function begin(string $scope,string $subject,string $sessionToken,Intent $intent): Confirmation
    {
        $this->guard();$facts=$this->facts($scope,$subject,$sessionToken,$intent,false);$now=$facts['now'];$key=State::context($scope,$subject,$now);
        $id=bin2hex(random_bytes(16));$token='oc1.'.$id.'.'.bin2hex(random_bytes(32));$reference=State::reference($token,'oc1');
        $entry=['phase'=>'pending','digest'=>$reference['digest'],'intent'=>$intent->fingerprint(),'account'=>$facts['account'],'session'=>$facts['session'],
            'created'=>$facts['created'],'session_digest'=>$facts['session_digest'],'issued'=>$now,'expires'=>min($now+$this->policy->ttl(),$facts['expires']),
            'authenticated'=>$facts['authenticated'],'method'=>$facts['method']];
        $this->store->transact($key,function ($state) use ($now,$id,$entry) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);
            if (count($state['entries']) >= $this->policy->capacity() || isset($state['entries'][$id])) { throw new SecurityException('Pending operation capacity reached.','operation.capacity'); }
            $state['entries'][$id]=$entry;return State::change($state,null);
        });
        $this->finish($scope,$subject,$sessionToken,$intent,$facts,$entry,$reference,'pending',false);
        return new Confirmation($token,$intent,$entry['expires']);
    }
    public function confirm(string $scope,string $subject,string $sessionToken,Intent $intent,string $confirmation): ?Grant
    {
        $this->guard();$reference=State::reference($confirmation,'oc1');if ($reference===null) { return null; }
        $facts=$this->facts($scope,$subject,$sessionToken,$intent,true);$now=$facts['now'];$key=State::context($scope,$subject,$now);
        $token='og1.'.$reference['id'].'.'.bin2hex(random_bytes(32));$grantReference=State::reference($token,'og1');
        $entry=$this->store->transact($key,function ($state) use ($now,$reference,$grantReference,$facts,$intent) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$reference['id']] ?? null;
            if ($entry===null || $entry['phase']!=='pending' || !hash_equals($entry['digest'],$reference['digest']) || !State::matches($entry,$facts)) { return State::change($state,null); }
            if (!hash_equals($entry['intent'],$intent->fingerprint())) { unset($state['entries'][$reference['id']]);return State::change($state,null); }
            if (hash_equals($entry['session_digest'],$facts['session_digest']) || $facts['authenticated']<$entry['issued']) { return State::change($state,null); }
            $entry['phase']='granted';$entry['digest']=$grantReference['digest'];$entry['session_digest']=$facts['session_digest'];
            $entry['authenticated']=$facts['authenticated'];$entry['method']=$facts['method'];
            $entry['expires']=min($entry['expires'],$facts['expires'],$facts['authenticated']+$this->policy->maximumAge());
            $state['entries'][$reference['id']]=$entry;return State::change($state,$entry);
        });
        if ($entry===null) { $this->finished($now);return null; }
        $this->finish($scope,$subject,$sessionToken,$intent,$facts,$entry,$grantReference,'granted',true);
        return new Grant($token,$entry['expires']);
    }
    public function consume(string $scope,string $subject,string $sessionToken,Intent $intent,string $grant): ?Permit
    {
        $this->guard();$reference=State::reference($grant,'og1');if ($reference===null) { return null; }
        $facts=$this->facts($scope,$subject,$sessionToken,$intent,true);$now=$facts['now'];$key=State::context($scope,$subject,$now);
        $entry=$this->store->transact($key,function ($state) use ($now,$reference,$facts,$intent) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$reference['id']] ?? null;
            if ($entry===null || $entry['phase']!=='granted' || !hash_equals($entry['digest'],$reference['digest']) || !State::matches($entry,$facts)
                || !hash_equals($entry['session_digest'],$facts['session_digest'])) { return State::change($state,null); }
            // The real bound credential is burned even when its operation data was tampered with.
            unset($state['entries'][$reference['id']]);
            if (!hash_equals($entry['intent'],$intent->fingerprint()) || $entry['authenticated']!==$facts['authenticated'] || $entry['method']!==$facts['method']) { return State::change($state,null); }
            $entry['expires']=min($entry['expires'],$facts['expires']);return State::change($state,$entry);
        });
        if ($entry===null) { $this->finished($now);return null; }
        $after=$this->finish($scope,$subject,$sessionToken,$intent,$facts,$entry,$reference,'granted',true);
        return new Permit($reference['id'],$intent,$after['authority']->account(),$after['session'],$after['method'],$after['authenticated'],$entry['expires']);
    }
    /** Current-session cancellation; request guard and current subject authentication are still mandatory. */
    public function revoke(string $scope,string $subject,string $sessionToken,string $id): bool
    {
        $this->guard();if (!State::hex($id,32)) { return false; }$facts=$this->facts($scope,$subject,$sessionToken,null,false);$now=$facts['now'];
        $result=$this->store->transact(State::context($scope,$subject,$now),function ($state) use ($now,$facts,$id) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$id] ?? null;
            $exists=$entry!==null && State::matches($entry,$facts);if ($exists) { unset($state['entries'][$id]); }return State::change($state,$exists);
        });$this->finished($now);return $result;
    }
    /** Explicit subject-wide cancellation by a current authenticated account. Does not authorize business work. */
    public function revokeAll(string $scope,string $subject,string $sessionToken): void
    {
        $this->guard();$facts=$this->facts($scope,$subject,$sessionToken,null,false);$now=$facts['now'];
        $this->store->transact(State::context($scope,$subject,$now),function ($state) use ($now) { State::read($state,$this->policy,$now);return new Change(null,0,null); });$this->finished($now);
    }
    private function guard(): void
    {
        try { $allowed=($this->guard)(); }catch (\Throwable $e) { throw new DependencyException('Operation request protection unavailable.','operation.request_unavailable'); }
        if ($allowed!==true) { throw new SecurityException('Operation request protection failed.','operation.request_denied'); }
    }
    private function facts(string $scope,string $subject,string $token,?Intent $intent,bool $strong): array
    {
        State::context($scope,$subject,$this->now());
        try { $session=$this->sessions->verify($scope,$subject,$token); }
        catch (\Throwable $e) { throw new DependencyException('Operation authentication authority unavailable.','operation.authentication_unavailable'); }
        if ($session===null) { throw new SecurityException('Current operation authentication required.','operation.authentication'); }
        if ($intent!==null) { $this->authorizer->assertAllowed($scope,$session->account(),$intent->action(),$intent->resource(),$intent->fields()); }
        $now=$this->now();
        if ($session->expiresAt()<=$now || $session->createdAt()>$now || $session->authenticatedAt()>$now || ($strong && !$this->policy->accepts($session,$now))) {
            throw new SecurityException('Recent approved authentication required.','operation.authentication');
        }
        return ['authority'=>$session,'now'=>$now,'account'=>$session->account()->fingerprint(),'session'=>$session->id(),'created'=>$session->createdAt(),
            'session_digest'=>hash('sha256',$token),'authenticated'=>$session->authenticatedAt(),'method'=>$session->method(),'expires'=>$session->expiresAt()];
    }
    private function finish(string $scope,string $subject,string $sessionToken,Intent $intent,array $before,array $entry,array $reference,string $phase,bool $strong): array
    {
        try {
            $this->finished($before['now'],$entry['expires']);$after=$this->facts($scope,$subject,$sessionToken,$intent,$strong);$this->finished($before['now'],$entry['expires']);
            foreach (['account','session','created','session_digest','authenticated','method'] as $field) {
                if ($before[$field]!==$after[$field]) { throw new SecurityException('Operation authority changed.','operation.changed'); }
            }
            if ($after['expires']<$entry['expires']) { throw new SecurityException('Operation session deadline changed.','operation.changed'); }
            return $after;
        } catch (\Throwable $e) {
            // Exact-token cleanup never removes a later phase, another session, or a replacement record.
            $this->drop($scope,$subject,$reference,$phase,max($before['now'],$this->now()));throw $e;
        }
    }
    private function drop(string $scope,string $subject,array $reference,string $phase,int $now): void
    {
        $this->store->transact(State::context($scope,$subject,$now),function ($state) use ($reference,$phase,$now) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$reference['id']] ?? null;
            if ($entry!==null && $entry['phase']===$phase && hash_equals($entry['digest'],$reference['digest'])) { unset($state['entries'][$reference['id']]); }
            return State::change($state,null);
        });
    }
    private function finished(int $started,?int $expires = null): void
    {
        $now=$this->now();if ($now<$started) { throw new StorageException('Operation clock moved backwards during I/O.','operation.clock'); }
        if ($expires!==null && $expires<=$now) { throw new SecurityException('Operation authorization expired during I/O.','operation.expired'); }
    }
    private function now(): int
    {
        $now=$this->clock->now();if ($now<0 || $now>PHP_INT_MAX-86400) { throw new StorageException('Invalid operation clock.','operation.clock'); }return $now;
    }
    public function __sleep(): array { throw new ConfigurationException('Rebuild operation authorization services from trusted configuration.','configuration.operation_serialization'); }
    public function __debugInfo(): array { return ['operation_authorizations'=>'[redacted]']; }
}
