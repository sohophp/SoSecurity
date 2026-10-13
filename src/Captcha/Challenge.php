<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

final class Challenge
{
    public $id;
    public $prompt;
    public $image;
    public $expiresAt;
    /** Public rendering metadata only; never contains a solution or digest. */
    public $presentation;

    public function __construct(string $id, string $prompt, ?string $image, int $expiresAt, array $presentation = [])
    {
        $this->id = $id;
        $this->prompt = $prompt;
        $this->image = $image;
        $this->expiresAt = $expiresAt;
        $this->presentation = $presentation;
    }
}
