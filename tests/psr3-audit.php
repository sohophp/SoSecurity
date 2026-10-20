<?php
declare(strict_types=1);
require $argv[1];
error_reporting(E_ALL);
set_error_handler(static function (int $severity, string $message): void {
    if (error_reporting() & $severity) { throw new ErrorException($message, 0, $severity); }
});

final class CaptureAuditLogger extends \Psr\Log\AbstractLogger
{
    public $entries = [];
    public $fail = false;
    public $privateMarker = 'PRIVATE-LOGGER-MARKER';
    public function log($level, $message, array $context = []): void
    {
        if ($this->fail) { throw new RuntimeException('private writer failure'); }
        $this->entries[] = [$level, $message, $context];
    }
}

function auditAssert($expected, $actual): void
{
    if ($expected !== $actual) {
        throw new RuntimeException('Unexpected PSR-3 audit result.');
    }
}
function auditThrows(string $type, callable $operation): void
{
    try { $operation(); } catch (Throwable $failure) {
        if ($failure instanceof $type) { return; }
        throw $failure;
    }
    throw new RuntimeException('Expected PSR-3 audit failure.');
}

$logger = new CaptureAuditLogger();
$sink = new \SoSecurity\Psr3\AuditSink($logger, \Psr\Log\LogLevel::WARNING);
$audit = new \SoSecurity\Audit\AuditLogger($sink, str_repeat('a', 32));
$audit->record('login.failed', 'login', "actor\0suffix", ['allowed' => false, 'status' => 401]);
auditAssert(1, count($logger->entries));
auditAssert(\Psr\Log\LogLevel::WARNING, $logger->entries[0][0]);
auditAssert('security.audit', $logger->entries[0][1]);
auditAssert(hash_hmac('sha256', "actor\0suffix", str_repeat('a', 32)), $logger->entries[0][2]['subject']);
auditAssert(['allowed' => false, 'status' => 401], $logger->entries[0][2]['context']);
auditAssert(false, strpos(json_encode($logger->entries), 'actor') !== false);
auditThrows(\SoSecurity\Exception\ConfigurationException::class, static function () use ($sink): void {
    $sink(['time' => 1, 'event' => 'login.failed', 'scope' => 'login', 'subject' => null,
        'context' => [], 'password' => 'secret']);
});
auditThrows(\SoSecurity\Exception\ConfigurationException::class, static function () use ($sink): void {
    $sink(['time' => 1, 'event' => 'login.failed', 'scope' => 'login', 'subject' => null,
        'context' => ['allowed' => "false"]]);
});
auditAssert(1, count($logger->entries));
auditThrows(\SoSecurity\Exception\ConfigurationException::class, static function () use ($logger): void {
    new \SoSecurity\Psr3\AuditSink($logger, 'untrusted-level');
});
auditThrows(\SoSecurity\Exception\ConfigurationException::class, static function () use ($sink): void { serialize($sink); });
auditAssert(false, strpos(var_export($sink, true), $logger->privateMarker) !== false);
$logger->fail = true;
auditThrows(RuntimeException::class, static function () use ($audit): void { $audit->record('login.failed', 'login', 'actor'); });
auditAssert(1, count($logger->entries));
echo 'PASS optional PSR-3 audit sink PHP '.PHP_VERSION.'; structured record, NUL pseudonym, invalid input, writer failure'.PHP_EOL;
