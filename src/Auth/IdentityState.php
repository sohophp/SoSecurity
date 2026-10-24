<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\SecurityException;
use SoSecurity\Support\Guard;

/** Internal authority snapshot. I/O is deliberately kept outside every retryable state transaction. */
final class IdentityState
{
    private $provider;
    private $factor;
    public function __construct(IdentityProvider $provider, ?SecondFactor $factor) { $this->provider = $provider; $this->factor = $factor; }
    public function matchesStatePolicy(\SoSecurity\Account\ManagedSecondFactor $factor):bool{return $this->provider instanceof PasswordIdentityProvider&&$this->factor===$factor;}
    public function matchesRecoveryRegistry(\SoSecurity\Account\FactorRegistry $registry):bool{return $this->provider instanceof PasswordIdentityProvider&&$this->factor instanceof \SoSecurity\Account\ManagedSecondFactor&&$this->factor->usesRegistry($registry);}
    public function matchesProviders(IdentityProvider $provider,?SecondFactor $factor):bool{return $this->provider===$provider&&$this->factor===$factor;}
    public function operationRolePolicy(\SoSecurity\Authorization\Authorizer $authorizer):?\SoSecurity\Authorization\RolePolicy{return $authorizer->stateRolePolicy($this->provider);}
    /** Pure exact identity/source match; effectful audit is not supported by these native proof paths. */
    public function operationSnapshotPolicy(\SoSecurity\Authorization\Authorizer $authorizer,\SoSecurity\Account\StateAccountPolicy $state):?\SoSecurity\Authorization\SnapshotPolicy
    {
        $declared=$authorizer->stateSnapshotPolicy($this->provider,$state);return $declared!==null&&$declared['audit']===null?$declared['policy']:null;
    }
    public function load(string $scope, string $subject): ?array
    {
        $account = $this->provider->find($scope, $subject);
        if ($account === null) { return null; }
        if ($account->scope() !== $scope || $account->subject() !== $subject) { throw new SecurityException('Identity scope mismatch.', 'auth.provider'); }
        return $this->snapshot($account);
    }
    public function snapshot(Account $account): ?array
    {
        if (!$account->enabled()) { return null; }
        if ($account->mfaRequired() && $this->factor === null) { throw new \SoSecurity\Exception\ConfigurationException('Required MFA has no verification adapter.', 'configuration.second_factor'); }
        $binding = $this->factor === null ? null : $this->factor->binding($account->scope(), $account->subject());
        if ($binding !== null) {
            Guard::label($binding);
            if (!preg_match('//u', $binding)) { throw new SecurityException('Second-factor binding is not UTF-8.', 'auth.factor_contract'); }
        }
        return ['account' => $account, 'factor' => $binding,
            'fingerprint' => hash('sha256', $account->fingerprint() . ':' . ($binding === null ? 'none' : strlen($binding) . ':' . $binding)),
            'mfa_required' => $account->mfaRequired() || $binding !== null];
    }
}
