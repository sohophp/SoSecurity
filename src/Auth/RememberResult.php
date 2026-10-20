<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

final class RememberResult
{
    private $status;
    private $session;
    private $next;
    private $account;
    private $reason;
    public function __construct(string $status, ?SessionCredential $session = null, ?RememberCredential $next = null, ?Account $account = null, ?string $reason = null)
    {
        if (!in_array($status, ['authenticated', 'retry', 'invalid', 'replayed', 'step_up', 'blocked'], true)
            || ($status === 'authenticated') !== ($session !== null) || ($status === 'authenticated') !== ($next !== null)
            || ($status === 'authenticated') !== ($account !== null)
            || (($status === 'step_up' || $status === 'blocked') !== ($reason !== null))
            || ($status === 'step_up' && !in_array($reason, ['anomalous', 'changed', 'reauth_required'], true))
            || ($status === 'blocked' && $reason !== 'compromised')) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid persistent-login outcome.', 'configuration.remember');
        }
        $this->status = $status; $this->session = $session; $this->next = $next; $this->account = $account; $this->reason = $reason;
    }
    public function status(): string { return $this->status; }
    public function session(): ?SessionCredential { return $this->session; }
    public function nextCredential(): ?RememberCredential { return $this->next; }
    public function account(): ?Account { return $this->account; }
    public function reason(): ?string { return $this->reason; }
    public function __debugInfo(): array { return ['status' => $this->status, 'secrets' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Do not serialize persistent-login outcomes.', 'configuration.credential_serialization'); }
    public function __set(string $name, $value): void { throw new \SoSecurity\Exception\ConfigurationException('Outcomes are immutable.', 'configuration.immutable'); }
}
