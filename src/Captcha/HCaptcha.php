<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

/** hCaptcha validates expiry, single use and the expected sitekey at its server. */
final class HCaptcha
{
    private $secret;
    private $siteKey;
    private $transport;

    public function __construct(string $secret, string $siteKey, ?callable $transport = null)
    {
        SiteVerify::secret($secret);
        if (!preg_match('/^[A-Za-z0-9_-]{1,256}$/D', $siteKey)) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid expected hCaptcha sitekey.');
        }
        $this->secret = static function () use ($secret): string { return $secret; }; $this->siteKey = $siteKey; $this->transport = $transport;
    }

    public function verify($token, ?string $clientIp = null): bool
    {
        if (!SiteVerify::token($token)) { return false; }
        $data = SiteVerify::verify('hcaptcha', ['secret' => $this->secret(), 'response' => $token, 'sitekey' => $this->siteKey], $clientIp, $this->transport);
        // hCaptcha documents hostname as browser-supplied statistics, not an authentication boundary.
        return $data['success'];
    }

    private function secret(): string
    {
        if (!$this->secret instanceof \Closure) { throw new \SoSecurity\Exception\ConfigurationException('Reload private CAPTCHA configuration.', 'configuration.captcha_secret'); }
        return ($this->secret)();
    }

    public function __debugInfo(): array { return ['provider' => 'hcaptcha', 'secret' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Do not serialize CAPTCHA configuration.', 'configuration.captcha_serialization'); }
    public function __wakeup(): void { throw new \SoSecurity\Exception\ConfigurationException('Rebuild CAPTCHA configuration from trusted input.', 'configuration.captcha_serialization'); }
}
