<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

/** reCAPTCHA v2 by default; an expected action enables v3 with a mandatory score check. */
final class Recaptcha
{
    private $secret;
    private $hostname;
    private $action;
    private $minimumScore;
    private $transport;

    public function __construct(string $secret, string $hostname, ?string $action = null,
        float $minimumScore = 0.5, ?callable $transport = null)
    {
        SiteVerify::secret($secret);
        if (!preg_match('/^[a-z0-9.-]{1,253}$/D', $hostname)
            || ($action !== null && !preg_match('/^[A-Za-z0-9_\/]{1,100}$/D', $action))
            || !is_finite($minimumScore) || $minimumScore < 0 || $minimumScore > 1) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid reCAPTCHA hostname, action or score threshold.');
        }
        $this->secret = $secret; $this->hostname = $hostname; $this->action = $action;
        $this->minimumScore = $minimumScore; $this->transport = $transport;
    }

    public function verify($token, ?string $clientIp = null): bool
    {
        if (!SiteVerify::token($token)) { return false; }
        $data = SiteVerify::verify('recaptcha', ['secret' => $this->secret, 'response' => $token], $clientIp, $this->transport);
        if (!$data['success'] || ($data['hostname'] ?? null) !== $this->hostname) { return false; }
        if ($this->action === null) { return !array_key_exists('score', $data) && !array_key_exists('action', $data); }
        $score = $data['score'] ?? null;
        return ($data['action'] ?? null) === $this->action && (is_int($score) || is_float($score))
            && is_finite((float) $score) && $score >= $this->minimumScore && $score <= 1;
    }
}
