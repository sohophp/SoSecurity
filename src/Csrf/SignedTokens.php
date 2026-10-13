<?php
declare(strict_types=1);
namespace SoSecurity\Csrf;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use SoSecurity\Support\Guard;
use SoSecurity\Exception\ConfigurationException;

/** No token state. Requires a trustworthy current-login binding; supports explicit signed double-submit. */
final class SignedTokens
{
    private $keys;
    private $audience;
    private $ttl;
    private $clock;
    public function __construct(HmacKeys $keys,string $audience,int $ttl=7200,?Clock $clock=null)
    {
        Guard::label($audience);
        if ($ttl<1 || $ttl>86400) { throw new ConfigurationException('Signed CSRF TTL must be 1-86400 seconds.','configuration.csrf_ttl'); }
        $this->keys=$keys; $this->audience=$audience; $this->ttl=$ttl; $this->clock=$clock ?? new SystemClock();
    }
    public function issue(string $scope,string $binding): string
    {
        Guard::key('csrf-signed',$scope,$binding); $now=$this->clock->now();
        if ($now<0 || $now>PHP_INT_MAX-$this->ttl || strlen((string)($now+$this->ttl))>10) {
            throw new ConfigurationException('Clock cannot represent signed CSRF expiry.','configuration.clock');
        }
        $prefix='socs1.'.$this->keys->currentId().'.'.$now.'.'.($now+$this->ttl).'.'.bin2hex(random_bytes(32));
        return $prefix.'.'.bin2hex($this->keys->sign($this->base($scope,$binding,$prefix)));
    }
    /** Reuse a valid cookie token so rendering another tab does not invalidate its double-submit pair. */
    public function reuseOrIssue(string $scope,string $binding,$existing): string
    {
        return $this->verify($scope,$binding,$existing) ? $existing : $this->issue($scope,$binding);
    }
    public function verify(string $scope,string $binding,$token): bool
    {
        Guard::key('csrf-signed',$scope,$binding);
        if (!is_string($token) || strlen($token)>256 || !preg_match('/\Asocs1\.([A-Za-z][A-Za-z0-9_-]{0,31})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.([a-f0-9]{64})\.([a-f0-9]{64})\z/D',$token,$parts)) { return false; }
        if ((string)(int)$parts[2]!==$parts[2] || (string)(int)$parts[3]!==$parts[3]) { return false; }
        $created=(int)$parts[2]; $expires=(int)$parts[3]; $now=$this->clock->now();
        if ($now<0 || $created>$now || $expires<=$now || $expires<=$created || $expires-$created>$this->ttl) { return false; }
        $prefix=substr($token,0,-65); $mac=hex2bin($parts[5]);
        if (!$this->keys->verify($parts[1],$this->base($scope,$binding,$prefix),$mac)) { return false; }
        $finalNow=$this->clock->now(); return $finalNow>=$created && $finalNow<$expires;
    }
    public function verifyDoubleSubmit(string $scope,string $binding,$cookie,$submitted): bool
    {
        Guard::key('csrf-signed',$scope,$binding);
        if (!is_string($cookie) || !is_string($submitted) || strlen($cookie)>256 || strlen($submitted)>256 || !hash_equals($cookie,$submitted)) { return false; }
        return $this->verify($scope,$binding,$submitted);
    }
    private function base(string $scope,string $binding,string $prefix): string
    {
        // Lengths count bytes, including binary binding bytes; identity never appears in the public token.
        return "SoSecurity.CSRF.v1\n".strlen($this->audience).':'.$this->audience."\n".strlen($scope).':'.$scope."\n".strlen($binding).':'.$binding."\n".$prefix;
    }
}
