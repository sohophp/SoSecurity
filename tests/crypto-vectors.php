<?php
declare(strict_types=1);
// Test-only stdin protocol with public fixed vector material. Never expose as an HTTP endpoint.
require __DIR__ . '/bootstrap.php';
$input = json_decode(stream_get_contents(STDIN), true);
$cipher = new SoSecurity\Crypto\Cipher('vector', ['vector' => hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')], 'vector-purpose');
try {
    if ($input['mode'] === 'encrypt') { echo json_encode(['envelope' => $cipher->encrypt(base64_decode($input['plain'], true), $input['binding'])]); }
    else { echo json_encode(['valid' => true, 'plain' => base64_encode($cipher->decrypt($input['envelope'], $input['binding']))]); }
} catch (SoSecurity\Exception\ValidationException $e) { echo json_encode(['valid' => false]); }
