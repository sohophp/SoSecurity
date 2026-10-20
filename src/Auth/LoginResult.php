<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

/** Result of server-side authentication only; objects must never be restored from untrusted serialized data. */
final class LoginResult
{
    private $status;
    private $challenge;
    private $expires;
    private $credential;
    private $account;
    public function __construct(string $status, ?string $challenge = null, ?int $expiresAt = null, ?SessionCredential $credential = null, ?Account $account = null)
    {
        if (!in_array($status, ['denied', 'mfa_required', 'enrollment_required', 'authenticated'], true)) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid login outcome.', 'configuration.authentication');
        }
        if (($status === 'authenticated') !== ($credential !== null) || ($status === 'authenticated') !== ($account !== null)
            || ($status === 'mfa_required' && ($challenge === null || !preg_match('/\A[a-f0-9]{64}\z/D', $challenge) || $expiresAt === null || $expiresAt < 1))
            || ($status !== 'mfa_required' && ($challenge !== null || $expiresAt !== null))) {
            throw new \SoSecurity\Exception\ConfigurationException('Inconsistent login outcome.', 'configuration.authentication');
        }
        $this->status = $status;
        $this->challenge = $challenge === null ? null : static function()use($challenge):string{return $challenge;};
        $this->expires = $expiresAt; $this->credential = $credential; $this->account = $account;
    }
    public function status(): string { return $this->status; }
    public function challenge(): ?string
    {
        if($this->challenge===null){return null;}
        if(!($this->challenge instanceof \Closure)){throw new \SoSecurity\Exception\ConfigurationException('Reload login results from current authentication state.','configuration.credential_serialization');}
        return ($this->challenge)();
    }
    public function expiresAt(): ?int { return $this->expires; }
    public function credential(): ?SessionCredential { return $this->credential; }
    public function account(): ?Account { return $this->account; }
    public function __debugInfo(): array { return ['status' => $this->status, 'expires' => $this->expires, 'secrets' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Do not serialize login results.', 'configuration.credential_serialization'); }
    public function __wakeup(): void { throw new \SoSecurity\Exception\ConfigurationException('Reload login results from current authentication state.', 'configuration.credential_serialization'); }
    public function __set(string $name, $value): void { throw new \SoSecurity\Exception\ConfigurationException('Login results are immutable.', 'configuration.immutable'); }
}
