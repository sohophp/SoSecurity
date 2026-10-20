<?php
declare(strict_types=1);
// CLI-only creation of an isolated test factor; excluded from distribution and public routing.
require __DIR__ . '/bootstrap.php';
$input = json_decode(stream_get_contents(STDIN), true);
$store = new SoSecurity\Storage\FileStore($input['directory'], 'auth-example');
$cipher = new SoSecurity\Crypto\Cipher('current', ['current' => base64_decode($input['key'], true)], 'auth-example:mfa');
$factors = new SoSecurity\Mfa\TotpFactors($store, $cipher, 'Auth example');
$pending = $factors->begin('example', 'demo-account', 'test@example.test');
parse_str(parse_url($pending->provisioningUri(), PHP_URL_QUERY), $parts);
$codes = $factors->confirm('example', 'demo-account', $pending->id(), (new SoSecurity\Mfa\Totp())->codeAt($parts['secret'], time()));
echo json_encode(['uri' => $pending->provisioningUri(), 'recovery' => $codes]);
