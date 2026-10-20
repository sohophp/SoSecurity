<?php
declare(strict_types=1);
// Fixed test authority for process-concurrency tests; native password work is covered by auth.php/auth_http.py.
function concurrentAuthProvider(): SoSecurity\Auth\IdentityProvider
{
    return new SoSecurity\Auth\CallbackIdentityProvider(
        static function (string $scope, string $identifier, string $password): ?SoSecurity\Auth\Account {
            return $scope === 'form' && $identifier === 'auth-worker' && $password === 'auth-test-password'
                ? new SoSecurity\Auth\Account('form', 'auth-worker', '1') : null;
        },
        static function (string $scope, string $subject): ?SoSecurity\Auth\Account {
            return $scope === 'form' && $subject === 'auth-worker' ? new SoSecurity\Auth\Account('form', 'auth-worker', '1') : null;
        });
}
