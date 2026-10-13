<?php
declare(strict_types=1);

/** Test-only access to private storage, never available in a demo or library response. */
function captchaTestRecord(SoSecurity\Storage\AtomicStore $store, string $scope, string $binding, string $id): array
{
    return $store->transact(SoSecurity\Support\Guard::key('captcha', $scope, $binding), function (?array $state) use ($id) {
        if (!$state || !isset($state[$id])) { throw new RuntimeException('Missing private CAPTCHA test record.'); }
        return new SoSecurity\Storage\Change($state, max(array_column($state, 'expires')), $state[$id]);
    });
}

function captchaTestSolution(SoSecurity\Storage\AtomicStore $store, SoSecurity\Captcha\Challenge $challenge,
    string $scope = 'form', string $binding = 'binding'): string
{
    $digest = captchaTestRecord($store, $scope, $binding, $challenge->id)['digest'];
    if (($challenge->presentation['kind'] ?? null) === 'slider') {
        for ($i = 0; $i <= 260; ++$i) {
            if (hash_equals($digest, hash('sha256', $challenge->id . ':' . $i))) { return (string) $i; }
        }
    } elseif (($challenge->presentation['kind'] ?? null) === 'click') {
        for ($a = 0; $a < 9; ++$a) { for ($b = 0; $b < 9; ++$b) { for ($c = 0; $c < 9; ++$c) {
            if ($a === $b || $b === $c || $a === $c) { continue; }
            $answer = "$a,$b,$c";
            if (hash_equals($digest, hash('sha256', $challenge->id . ':' . $answer))) { return $answer; }
        } } }
    } else {
        // Bounded arithmetic image / four-digit challenge search, independent of generator implementation.
        for ($i = 0; $i <= 9999; ++$i) {
            foreach ([(string) $i, str_pad((string) $i, 4, '0', STR_PAD_LEFT)] as $answer) {
                if (hash_equals($digest, hash('sha256', $challenge->id . ':' . $answer))) { return $answer; }
            }
        }
    }
    throw new RuntimeException('No solution in the bounded private test space.');
}

function captchaTestLettersSolution(SoSecurity\Storage\AtomicStore $store, SoSecurity\Captcha\Challenge $challenge): string
{
    $digest = captchaTestRecord($store, 'letters', 'binding', $challenge->id)['digest'];
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $base = strlen($alphabet);
    for ($number = 0; $number < $base * $base * $base * $base; ++$number) {
        $value = $number; $answer = '';
        for ($i = 0; $i < 4; ++$i) { $answer .= $alphabet[$value % $base]; $value = intdiv($value, $base); }
        if (hash_equals($digest, hash('sha256', $challenge->id . ':' . $answer))) { return $answer; }
    }
    throw new RuntimeException('The letter image answer was outside its documented alphabet.');
}
