<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
// Fixed public interop material only; no HTTP route or production key handling.
$input = json_decode(stream_get_contents(STDIN, 4096), true);
$codec = new SoSecurity\Auth\RememberCodec(new SoSecurity\Support\HmacKeys($input['kid'], [$input['kid'] => hex2bin($input['key'])]));
if ($input['operation'] === 'issue') { echo json_encode($codec->issue($input['scope'], $input['selector'], $input['generation'], $input['secret'])); }
else { echo json_encode($codec->parse($input['scope'], $input['token'])); }
