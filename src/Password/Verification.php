<?php
declare(strict_types=1);

namespace SoSecurity\Password;

final class Verification
{
    public $valid;
    public $replacementHash;

    public function __construct(bool $valid, ?string $replacementHash = null)
    {
        $this->valid = $valid;
        $this->replacementHash = $replacementHash;
    }
}
