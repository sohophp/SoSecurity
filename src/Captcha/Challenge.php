<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

final class Challenge
{
    public $id;
    public $prompt;
    public $image;
    public $expiresAt;

    public function __construct(string $id, string $prompt, ?string $image, int $expiresAt)
    {
        $this->id = $id;
        $this->prompt = $prompt;
        $this->image = $image;
        $this->expiresAt = $expiresAt;
    }
}
