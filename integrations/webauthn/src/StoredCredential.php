<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use Webauthn\CredentialRecord;

/** Snapshot used for compare-and-swap credential updates. */
final class StoredCredential
{
    private $record;
    private $revision;

    public function __construct(CredentialRecord $record, int $revision)
    {
        if ($revision < 1) {
            throw new \InvalidArgumentException('Invalid credential revision');
        }
        $this->record = clone $record;
        $this->revision = $revision;
    }

    public function record(): CredentialRecord { return clone $this->record; }
    public function revision(): int { return $this->revision; }
}
