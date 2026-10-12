<?php
declare(strict_types=1);

namespace SoSecurity\Password;

use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Support\Clock;

/** Reuses the reviewed token lifecycle. Bind to account AND current password/reset version. */
final class ResetTokens
{
    private $tokens;

    public function __construct(AtomicStore $store, int $ttl = 1800, ?Clock $clock = null)
    {
        $this->tokens = new CsrfTokens($store, $ttl, 4, $clock);
    }

    public function issue(string $accountVersion): string
    {
        return $this->tokens->issue('password-reset', $accountVersion);
    }

    public function consume(string $accountVersion, $token): bool
    {
        return $this->tokens->verify('password-reset', $accountVersion, $token, true);
    }

    public function revoke(string $accountVersion): void
    {
        $this->tokens->revoke('password-reset', $accountVersion);
    }
}
