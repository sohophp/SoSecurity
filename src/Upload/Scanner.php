<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

/** Trusted adapter owns its transport deadlines. False rejects; exceptions never count as clean. */
interface Scanner
{
    public function scan(Candidate $candidate): bool;
}
