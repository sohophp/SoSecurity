<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/captcha-support.php';

use SoSecurity\Captcha\Captcha;
use SoSecurity\Captcha\ImageRenderer;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

if (!extension_loaded('gd')) {
    $captcha = new Captcha(new SoSecurity\Storage\MemoryStore());
    foreach (['imageDigits', 'imageLetters', 'imageArithmetic', 'slider', 'click'] as $method) {
        Check::throws(SoSecurity\Exception\DependencyException::class, function () use ($captcha, $method) { $captcha->$method('form', 'binding'); });
    }
    $challenge = $captcha->arithmetic('form', 'binding');
    preg_match('/^(\d+) \+ (\d+)/', $challenge->prompt, $parts);
    Check::same(true, $captcha->verify('form', 'binding', $challenge->id, (string) ($parts[1] + $parts[2])));
    echo 'PASS CAPTCHA: ' . Check::$assertions . " no-GD dependency refusal/arithmetic assertions; NOT RUN PNG/interactive workflows without GD\n";
    exit;
}
$directory = privateDirectory(); $sessions = privateDirectory();
ini_set('session.save_path', $sessions); session_id(bin2hex(random_bytes(16))); session_start();
try {
    $clock = new TestClock();
    $stores = ['memory' => new SoSecurity\Storage\MemoryStore($clock),
        'file' => new SoSecurity\Storage\FileStore($directory, 'captcha-new', $clock),
        'session' => new SoSecurity\Storage\SessionStore('captcha-new', $clock)];
    foreach ($stores as $kind => $store) {
        $captcha = new Captcha($store, 30, 3, 4, $clock);
        foreach (['add', 'subtract', 'multiply', 'divide', 'mixed'] as $operation) {
            for ($i = 0; $i < 8; ++$i) {
                $challenge = $captcha->arithmetic('form', 'binding', $operation);
                Check::same(1, preg_match('/^(\d+) ([+*\/-]) (\d+) = \?$/D', $challenge->prompt, $parts));
                $left = (int) $parts[1]; $right = (int) $parts[3];
                switch ($parts[2]) {
                    case '+': $answer = $left + $right; break;
                    case '-': $answer = $left - $right; break;
                    case '*': $answer = $left * $right; break;
                    default: Check::same(0, $left % $right); $answer = intdiv($left, $right);
                }
                Check::same(true, $answer >= 0 && $answer <= 81);
                Check::same(true, $captcha->verify('form', 'binding', $challenge->id, (string) $answer));
                Check::same(false, $captcha->verify('form', 'binding', $challenge->id, (string) $answer));
            }
        }
        foreach (['slider', 'click', 'imageArithmetic', 'imageDigits'] as $method) {
            $issue = function () use ($captcha, $method) {
                return $method === 'imageDigits' ? $captcha->imageDigits('form', 'binding', null, 4) : $captcha->$method('form', 'binding');
            };
            $challenge = $issue(); $answer = captchaTestSolution($store, $challenge);
            Check::same("\x89PNG\r\n\x1a\n", substr($challenge->image, 0, 8));
            Check::same(false, property_exists($challenge, 'answer'));
            Check::same(false, array_key_exists('answer', $challenge->presentation));
            Check::same(false, array_key_exists('digest', $challenge->presentation));
            Check::same(false, array_key_exists('target_x', $challenge->presentation));
            Check::same(false, $captcha->verify('other', 'binding', $challenge->id, $answer));
            Check::same(false, $captcha->verify('form', 'other', $challenge->id, $answer));
            Check::same(false, $captcha->verify('form', 'binding', $challenge->id, []));
            Check::same(true, $captcha->verify('form', 'binding', $challenge->id, $answer));
            Check::same(false, $captcha->verify('form', 'binding', $challenge->id, $answer));
            $challenge = $issue(); $answer = captchaTestSolution($store, $challenge);
            foreach (['-1', '999999', '0,0,0'] as $wrong) { Check::same(false, $captcha->verify('form', 'binding', $challenge->id, $wrong)); }
            Check::same(false, $captcha->verify('form', 'binding', $challenge->id, $answer));
            $challenge = $issue(); $answer = captchaTestSolution($store, $challenge);
            $clock->time += 30;
            Check::same(false, $captcha->verify('form', 'binding', $challenge->id, $answer));
            $challenge = $issue(); $answer = captchaTestSolution($store, $challenge); $captcha->revoke('form', 'binding');
            Check::same(false, $captcha->verify('form', 'binding', $challenge->id, $answer));
        }
        for ($offset = -4; $offset <= 4; ++$offset) {
            $challenge = $captcha->slider('form', 'binding'); $center = (int) captchaTestSolution($store, $challenge);
            Check::same(abs($offset) <= 3, $captcha->verify('form', 'binding', $challenge->id, (string) ($center + $offset)));
            if (abs($offset) <= 3) { Check::same(false, $captcha->verify('form', 'binding', $challenge->id, (string) $center)); }
        }
        $challenge = $captcha->click('form', 'binding'); $answer = captchaTestSolution($store, $challenge);
        $reverse = implode(',', array_reverse(explode(',', $answer)));
        Check::same(false, $captcha->verify('form', 'binding', $challenge->id, $reverse));
        Check::same(true, $captcha->verify('form', 'binding', $challenge->id, $answer));
        $old = $captcha->slider('form', 'binding'); $answer = captchaTestSolution($store, $old);
        for ($i = 0; $i < 4; ++$i) { $captcha->click('form', 'binding'); }
        Check::same(false, $captcha->verify('form', 'binding', $old->id, $answer));
        $letters = $captcha->imageLetters('letters', 'binding', null, 4);
        Check::same('', $letters->prompt); Check::same([], $letters->presentation);
        Check::same(180, getimagesizefromstring($letters->image)[0]);
        $answer = captchaTestLettersSolution($store, $letters);
        Check::same(true, $captcha->verify('letters', 'binding', $letters->id, strtolower($answer)));
        Check::same(false, $captcha->verify('letters', 'binding', $letters->id, $answer));
    }
    $captcha = new Captcha($stores['memory'], 30, 3, 4, $clock);
    Check::throws(ConfigurationException::class, function () use ($captcha) { $captcha->arithmetic('form', 'binding', 'eval'); });
    Check::throws(ConfigurationException::class, function () use ($captcha) { $captcha->imageArithmetic('form', 'binding', 'unknown'); });
    $renderer = new ImageRenderer(); Check::same(180, getimagesizefromstring($renderer->render('0012'))[0]);
    foreach (['4 / 2 = ?', '81 / 9 = ?', '20 - 20 = ?'] as $question) { Check::same(180, getimagesizefromstring($renderer->renderQuestion($question))[0]); }
    foreach (['1;exec(1)', '1 + 2 = 3', '999 + 1 = ?', '1 + -2 = ?'] as $question) { Check::throws(ConfigurationException::class, function () use ($renderer, $question) { $renderer->renderQuestion($question); }); }
    $id = str_repeat('a', 32);
    foreach ([null, [], array_fill(0, 8, str_repeat('a', 64)), array_fill(0, 7, 'bad')] as $alternatives) {
        $stores['memory']->transact(Guard::key('captcha', 'corrupt', 'binding'), function () use ($id, $clock, $alternatives) {
            return new Change([$id => ['digest' => str_repeat('a', 64), 'expires' => $clock->time + 30, 'remaining' => 3, 'alternatives' => $alternatives]], $clock->time + 30, null);
        });
        Check::throws(StorageException::class, function () use ($captcha, $id) { $captcha->verify('corrupt', 'binding', $id, '1'); });
    }
    $failure = new class implements SoSecurity\Storage\AtomicStore {
        public function transact(string $key, callable $callback) { throw new StorageException('Unavailable private test storage.'); }
    };
    foreach (['slider', 'click', 'imageDigits', 'imageLetters', 'imageArithmetic'] as $method) {
        Check::throws(StorageException::class, function () use ($failure, $method) { (new Captcha($failure))->$method('form', 'binding'); });
    }
} finally { session_destroy(); cleanDirectory($directory); cleanDirectory($sessions); }
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " extended CAPTCHA assertions passed (memory/file/session; private test solution access)\n";
