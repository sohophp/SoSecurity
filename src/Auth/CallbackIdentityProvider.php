<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\SecurityException;

/** Adapts an existing local/config/remote authority. Callbacks are server-owned and bounded by the host. */
final class CallbackIdentityProvider implements IdentityProvider
{
    private $authenticate;
    private $find;
    public function __construct(callable $authenticate, callable $find) { $this->authenticate = $authenticate; $this->find = $find; }
    public function authenticate(string $scope, string $identifier, string $password): ?Account
    {
        return $this->result(($this->authenticate)($scope, $identifier, $password), $scope);
    }
    public function find(string $scope, string $subject): ?Account { return $this->result(($this->find)($scope, $subject), $scope, $subject); }
    private function result($account, string $scope, ?string $subject = null): ?Account
    {
        if ($account === null) { return null; }
        if (!$account instanceof Account || $account->scope() !== $scope || ($subject !== null && $account->subject() !== $subject)) {
            throw new SecurityException('Identity provider returned an invalid or cross-scope result.', 'auth.provider');
        }
        return $account->enabled() ? $account : null;
    }
    public function __debugInfo(): array { return ['callbacks' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Do not serialize identity providers.', 'configuration.identity_serialization'); }
}
