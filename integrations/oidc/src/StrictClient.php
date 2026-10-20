<?php
declare(strict_types=1);

namespace SoSecurity\Oidc;

use InvalidArgumentException;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use RuntimeException;

/** Authorization-code client with fixed provider metadata and stricter ID-token claims. */
class StrictClient extends OpenIDConnectClient
{
    private $expectedIssuer;
    private $expectedAudience;
    private $fixedProviderConfig = [];
    private $authorizationEndpoint;
    private $tokenEndpoint;
    private $jwksEndpoint;
    private $configured = false;
    private $privateSecret;
    private $tokenExchange = false;
    private $subjectFlow = false;

    public function __debugInfo(): array
    {
        return ['issuer' => $this->expectedIssuer, 'client_id' => $this->expectedAudience,
            'credentials' => '[redacted]'];
    }

    public function __sleep(): array { throw new RuntimeException('Do not serialize OIDC client credentials.'); }
    public function __wakeup(): void { throw new RuntimeException('Rebuild OIDC clients from trusted configuration.'); }

    public function __construct(string $issuer, string $clientId, string $clientSecret, string $redirectUri,
        string $authorizationEndpoint, string $tokenEndpoint, string $jwksUri)
    {
        foreach ([$issuer, $redirectUri, $authorizationEndpoint, $tokenEndpoint, $jwksUri] as $uri) {
            self::httpsUrl($uri);
        }
        if ($clientId === '' || strlen($clientId) > 256 || preg_match('/[\x00-\x1f\x7f]/', $clientId)
            || strlen($clientSecret) < 16 || strlen($clientSecret) > 512 || preg_match('/[\x00-\x1f\x7f]/', $clientSecret)) {
            throw new InvalidArgumentException('Use a registered OIDC client and private client secret.');
        }
        // The upstream class exposes its private fields to var_export(). Keep
        // the credential in a closure and install it only during token exchange.
        $this->privateSecret = static function () use ($clientSecret): string { return $clientSecret; };
        parent::__construct($issuer, $clientId, '', $issuer);
        $this->expectedIssuer = $issuer;
        $this->expectedAudience = $clientId;
        $this->authorizationEndpoint = $authorizationEndpoint;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->jwksEndpoint = $jwksUri;
        $this->setIssuerValidator(static function ($actual) use ($issuer): bool {
            return is_string($actual) && hash_equals($issuer, $actual);
        });
        $this->setRedirectURL($redirectUri);
        $this->setResponseTypes(['code']);
        $this->setAllowImplicitFlow(false);
        $this->setCodeChallengeMethod('S256');
        $this->providerConfigParam([
            'issuer' => $issuer,
            'authorization_endpoint' => $authorizationEndpoint,
            'token_endpoint' => $tokenEndpoint,
            'jwks_uri' => $jwksUri,
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]);
        $this->configured = true;
    }

    private function requireConfigurationPhase(): void
    {
        if ($this->configured) {
            throw new RuntimeException('OIDC security configuration is immutable after construction.');
        }
    }

    final public function setProviderURL($provider_url) { $this->requireConfigurationPhase(); parent::setProviderURL($provider_url); }
    final public function setIssuer($issuer) { $this->requireConfigurationPhase(); parent::setIssuer($issuer); }
    final public function setResponseTypes($response_types) { $this->requireConfigurationPhase(); parent::setResponseTypes($response_types); }
    final public function addAuthParam(array $param) { $this->requireConfigurationPhase(); parent::addAuthParam($param); }
    final public function setWellKnownConfigParameters(array $params = []) { $this->requireConfigurationPhase(); parent::setWellKnownConfigParameters($params); }
    final public function setRedirectURL(string $url) { $this->requireConfigurationPhase(); parent::setRedirectURL($url); }
    final public function setHttpProxy(string $httpProxy) { $this->requireConfigurationPhase(); parent::setHttpProxy($httpProxy); }
    final public function setCertPath(string $certPath) { $this->requireConfigurationPhase(); parent::setCertPath($certPath); }
    final public function setVerifyPeer(bool $verifyPeer) { $this->requireConfigurationPhase(); parent::setVerifyPeer($verifyPeer); }
    final public function setVerifyHost(bool $verifyHost) { $this->requireConfigurationPhase(); parent::setVerifyHost($verifyHost); }
    final public function setHttpUpgradeInsecureRequests(bool $enabled) { $this->requireConfigurationPhase(); parent::setHttpUpgradeInsecureRequests($enabled); }
    final public function setIssuerValidator(callable $validator) { $this->requireConfigurationPhase(); parent::setIssuerValidator($validator); }
    final public function setPrivateKeyJwtGenerator(callable $generator) { $this->requireConfigurationPhase(); parent::setPrivateKeyJwtGenerator($generator); }
    final public function setAllowImplicitFlow(bool $allowed) { $this->requireConfigurationPhase(); parent::setAllowImplicitFlow($allowed); }
    final public function providerConfigParam(array $params) { $this->requireConfigurationPhase(); $this->fixedProviderConfig = array_merge($this->fixedProviderConfig, $params); parent::providerConfigParam($params); }
    final public function setClientSecret(string $secret) { $this->requireConfigurationPhase(); parent::setClientSecret($secret); }
    final public function setClientID(string $id) { $this->requireConfigurationPhase(); parent::setClientID($id); }
    final public function setUrlEncoding($encoding) { $this->requireConfigurationPhase(); parent::setUrlEncoding($encoding); }
    final public function setCodeChallengeMethod(string $method) { $this->requireConfigurationPhase(); parent::setCodeChallengeMethod($method); }
    final public function setTokenEndpointAuthMethodsSupported(array $methods) { throw new RuntimeException('OIDC token endpoint authentication is fixed.'); }
    final public function addRegistrationParam(array $params) { throw new RuntimeException('OIDC dynamic registration is not supported.'); }
    final public function setAccessToken(string $accessToken) { throw new RuntimeException('OIDC bearer tokens must not be retained on this client.'); }
    final public function setIdToken(string $idToken) { throw new RuntimeException('OIDC ID tokens must not be retained on this client.'); }
    final public function refreshToken(string $refresh_token) { throw new RuntimeException('OIDC refresh-token flow is not supported by this adapter.'); }
    final public function verifyLogoutToken(): bool { throw new RuntimeException('Use verified back-channel logout tokens.'); }
    final public function verifyLogoutTokenClaims($claims): bool { throw new RuntimeException('Use verified back-channel logout tokens.'); }
    final public function requestClientCredentialsToken() { throw new RuntimeException('OIDC client-credentials grant is not supported.'); }
    final public function requestResourceOwnerToken(bool $bClientAuth = false) { throw new RuntimeException('OIDC password grant is not supported.'); }
    final public function requestTokenExchange(string $subjectToken, string $subjectTokenType, string $audience = '') { throw new RuntimeException('OIDC token exchange is not supported.'); }
    final public function signOut(string $idToken, $redirect) { throw new RuntimeException('Use the host-approved logout flow.'); }
    final public function register() { throw new RuntimeException('OIDC dynamic registration is not supported.'); }
    final public function requestUserInfo(string $attribute = null) { throw new RuntimeException('OIDC UserInfo requests are not supported.'); }
    final public function introspectToken(string $token, string $token_type_hint = '', string $clientId = null, string $clientSecret = null) { throw new RuntimeException('OIDC token introspection is not supported.'); }
    final public function revokeToken(string $token, string $token_type_hint = '', string $clientId = null, string $clientSecret = null) { throw new RuntimeException('OIDC token revocation is not supported.'); }

    public function getClientSecret()
    {
        if (!$this->tokenExchange || !$this->privateSecret instanceof \Closure) {
            throw new RuntimeException('OIDC client credentials are not available outside token exchange.');
        }
        return ($this->privateSecret)();
    }

    protected function requestTokens(string $code, array $headers = [])
    {
        if (!$this->privateSecret instanceof \Closure || $this->tokenExchange) {
            throw new RuntimeException('OIDC token exchange is unavailable.');
        }
        $this->tokenExchange = true;
        try {
            parent::setClientSecret(($this->privateSecret)());
            return parent::requestTokens($code, $headers);
        }
        finally { parent::setClientSecret(''); $this->tokenExchange = false; }
    }

    public function authenticate(): bool
    {
        if (!$this->subjectFlow) {
            throw new RuntimeException('Use the verified OIDC subject flow.');
        }
        return parent::authenticate();
    }

    public function redirect(string $url)
    {
        if (!$this->subjectFlow || strpos($url, $this->authorizationEndpoint . '?') !== 0) {
            throw new RuntimeException('Only the fixed OIDC authorization redirect is allowed.');
        }
        parent::redirect($url);
    }

    /** No parent discovery request may supply an endpoint or security policy implicitly. */
    protected function getProviderConfigValue(string $param, $default = null)
    {
        if (!array_key_exists($param, $this->fixedProviderConfig)) {
            throw new RuntimeException('OIDC provider parameter was not approved: ' . $param);
        }
        return $this->fixedProviderConfig[$param];
    }

    /** Only fixed endpoints are contacted; redirects and oversized responses are refused. */
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = [])
    {
        if (($url !== $this->tokenEndpoint && $url !== $this->jwksEndpoint)
            || ($url === $this->tokenEndpoint) !== ($post_body !== null)
            || ($post_body !== null && strlen($post_body) > 8192)
            || count($headers) > 8) {
            throw new OpenIDConnectClientException('Unapproved OIDC request.');
        }
        foreach ($headers as $header) {
            if (!is_string($header) || strlen($header) > 1024 || preg_match('/[\r\n\x00]/', $header)) {
                throw new OpenIDConnectClientException('Invalid OIDC request header.');
            }
        }
        if ($post_body !== null) { $headers[] = 'Content-Type: application/x-www-form-urlencoded'; }
        $handle = curl_init();
        if ($handle === false) { throw new OpenIDConnectClientException('OIDC transport unavailable.'); }
        $body = '';
        $tooLarge = false;
        try {
            $options = [
                CURLOPT_URL => $url,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_MAXREDIRS => 0,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_PROXY => '',
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_WRITEFUNCTION => static function ($stream, string $chunk) use (&$body, &$tooLarge): int {
                    if (strlen($chunk) > 131072 - strlen($body)) { $tooLarge = true; return 0; }
                    $body .= $chunk;
                    return strlen($chunk);
                },
            ];
            if ($post_body !== null) {
                $options[CURLOPT_POST] = true;
                $options[CURLOPT_POSTFIELDS] = $post_body;
            }
            if (!curl_setopt_array($handle, $options)) {
                throw new OpenIDConnectClientException('OIDC transport configuration failed.');
            }
            $ok = curl_exec($handle);
            $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
            if ($tooLarge) { throw new OpenIDConnectClientException('OIDC response exceeds 128 KiB.'); }
            if ($ok === false || $status !== 200) {
                throw new OpenIDConnectClientException('OIDC endpoint failed.');
            }
            return $body;
        } finally {
            curl_close($handle);
        }
    }

    /** Returns only the stable issuer/subject pair after the upstream library authenticates the callback. */
    public function authenticateSubject(): ?array
    {
        try {
            $this->assertCallbackState();
            $this->subjectFlow = true;
            if ($this->authenticate() !== true) { return null; }
            $claims = $this->getVerifiedClaims();
            if (!is_object($claims) || !isset($claims->iss, $claims->sub, $claims->iat)
                || $claims->iss !== $this->expectedIssuer || !self::subject($claims->sub)
                || !is_int($claims->iat) || (property_exists($claims, 'sid') && !self::subject($claims->sid))) {
                throw new RuntimeException('Verified OIDC subject is unavailable.');
            }
            return ['issuer' => $this->expectedIssuer, 'subject' => $claims->sub,
                'issued_at' => $claims->iat, 'sid' => $claims->sid ?? null];
        } finally {
            $this->subjectFlow = false;
            // v1.0.2 declares these fields without PHP types, but its public
            // setters accept only strings and its PHPDoc omits the null state.
            foreach (['idToken', 'accessToken', 'tokenResponse', 'refreshToken', 'verifiedClaims'] as $name) {
                $property = new \ReflectionProperty(OpenIDConnectClient::class, $name);
                $property->setAccessible(true);
                $property->setValue($this, $name === 'verifiedClaims' ? (object)[] : null);
            }
        }
    }

    /** Reject a forged callback before the upstream client sends its code to the token endpoint. */
    protected function assertCallbackState(): void
    {
        if (!isset($_REQUEST['code'])) { return; }
        $code = $_REQUEST['code'];
        $state = $_REQUEST['state'] ?? null;
        $expected = $this->getState();
        if (!is_string($code) || $code === '' || strlen($code) > 2048
            || !is_string($state) || $state === '' || strlen($state) > 2048
            || !is_string($expected) || $expected === '' || !hash_equals($expected, $state)) {
            throw new RuntimeException('Invalid OIDC callback state.');
        }
    }

    /** Invoked by the upstream client after signature verification, before it accepts the ID token. */
    protected function verifyJWTClaims($claims, ?string $accessToken = null): bool
    {
        if (!is_object($claims) || !isset($claims->iss, $claims->sub, $claims->aud, $claims->nonce, $claims->iat, $claims->exp)
            || $claims->iss !== $this->expectedIssuer || !self::subject($claims->sub)
            || $claims->aud !== $this->expectedAudience || !is_string($claims->nonce)
            || (property_exists($claims, 'sid') && !self::subject($claims->sid))) {
            return false;
        }
        $nonce = $this->getNonce();
        if (!is_string($nonce) || $nonce === '' || !hash_equals($nonce, $claims->nonce)) { return false; }
        $now = time();
        if (!is_int($claims->iat) || !is_int($claims->exp) || $claims->iat > $now + 60
            || $claims->iat < $now - 86400 || $claims->exp <= $now || $claims->exp > $now + 86400
            || $claims->exp <= $claims->iat || (isset($claims->azp) && $claims->azp !== $this->expectedAudience)
            || (isset($claims->auth_time) && (!is_int($claims->auth_time) || $claims->auth_time > $now + 60))) {
            return false;
        }
        $header = $this->getIdTokenHeader();
        if (!is_object($header) || !isset($header->alg) || !in_array($header->alg, ['RS256', 'PS256'], true)) { return false; }
        return parent::verifyJWTClaims($claims, $accessToken);
    }

    private static function subject($value): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= 255
            && preg_match('/\A[\x21-\x7e]+\z/D', $value) === 1;
    }

    private static function httpsUrl(string $uri): void
    {
        if ($uri === '' || strlen($uri) > 2048 || preg_match('/[\x00-\x20\x7f]/', $uri)) {
            throw new InvalidArgumentException('Use a fixed HTTPS OIDC URL.');
        }
        $parts = parse_url($uri);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || isset($parts['query']) || filter_var($parts['host'], FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException('Use a fixed HTTPS OIDC URL.');
        }
    }
}
