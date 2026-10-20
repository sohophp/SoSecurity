<?php
declare(strict_types=1);

require $argv[1];
require dirname($argv[1]).'/sohophp/sosecurity/examples/psr15-account-budget.php';

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Psr15\BudgetMiddleware;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\SecurityException;
use SoSecurity\RateLimit\BudgetLimiter;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\StorageException;

function check($expected, $actual): void
{
    if ($expected !== $actual) { throw new RuntimeException('PSR-15 consumer assertion failed.'); }
}
function rejects(string $type, callable $operation): void
{
    try { $operation(); } catch (Throwable $error) {
        if ($error instanceof $type) { return; }
        throw $error;
    }
    throw new RuntimeException('Expected PSR-15 rejection.');
}

$handled = 0;
$handler = new class($handled) implements RequestHandlerInterface {
    private $handled;
    public function __construct(&$handled) { $this->handled =& $handled; }
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        ++$this->handled;
        return new Response(200);
    }
};
$request = new ServerRequest('POST', 'https://example.test/private');
$limiter = new BudgetLimiter(new MemoryStore(), new BudgetPolicy('fixed_window', 1, 60));
$middleware = new BudgetMiddleware($limiter, 'private-post', static function (ServerRequestInterface $request): string {
    return $request->getMethod() === 'POST' ? 'account-1' : 'account-2';
}, new Response(429));
check(200, $middleware->process($request, $handler)->getStatusCode());
$denied = $middleware->process($request, $handler);
check(429, $denied->getStatusCode());
check(1, $handled);
check(true, (int) $denied->getHeaderLine('Retry-After') > 0);
check(200, $middleware->process(new ServerRequest('GET', 'https://example.test/private'), $handler)->getStatusCode());
check(2, $handled);

$invalid = new BudgetMiddleware($limiter, 'private-post', static function () { return null; }, new Response(429));
rejects(ConfigurationException::class, static function () use ($invalid, $request, $handler): void { $invalid->process($request, $handler); });
check(2, $handled);
rejects(ConfigurationException::class, static function () use ($limiter): void {
    new BudgetMiddleware($limiter, 'bad scope', static function (): string { return 'account'; }, new Response(429));
});
rejects(ConfigurationException::class, static function () use ($limiter): void {
    new BudgetMiddleware($limiter, 'private-post', static function (): string { return 'account'; }, new Response(200));
});

$faultyStore = new class implements AtomicStore {
    public function transact(string $key, callable $callback) { throw new StorageException('test outage'); }
};
$faulty = new BudgetMiddleware(new BudgetLimiter($faultyStore, new BudgetPolicy()), 'private-post',
    static function (): string { return 'account'; }, new Response(429));
rejects(StorageException::class, static function () use ($faulty, $request, $handler): void { $faulty->process($request, $handler); });
check(2, $handled);

$tooExpensive = new BudgetMiddleware($limiter, 'other-post', static function (): string { return 'account'; }, new Response(429), 2);
$response = $tooExpensive->process($request, $handler);
check(429, $response->getStatusCode());
check('', $response->getHeaderLine('Retry-After'));
check(2, $handled);

$accountLimiter = new BudgetLimiter(new MemoryStore(), new BudgetPolicy('fixed_window', 1, 60));
$accountMiddleware = SoSecurity\Examples\Psr15\accountWriteBudget($accountLimiter, new Response(429));
$alice = new Account('tenant', 'alice', 'v1');
$bob = new Account('tenant', 'bob', 'v1');
$accountRequest = $request->withHeader('X-Account-Id', 'bob')->withAttribute('verified_account', $alice);
check(200, $accountMiddleware->process($accountRequest, $handler)->getStatusCode());
check(429, $accountMiddleware->process($accountRequest, $handler)->getStatusCode());
check(3, $handled);
check(200, $accountMiddleware->process($request->withAttribute('verified_account', $bob), $handler)->getStatusCode());
check(4, $handled);
rejects(SecurityException::class, static function () use ($accountMiddleware, $request, $handler): void {
    $accountMiddleware->process($request->withHeader('X-Account-Id', 'alice'), $handler);
});
rejects(SecurityException::class, static function () use ($accountMiddleware, $request, $handler): void {
    $accountMiddleware->process($request->withAttribute('verified_account', new Account('tenant', 'disabled', 'v1', false)), $handler);
});
check(4, $handled);

echo 'PHP '.PHP_VERSION.": PSR-15 budget consumer passed\n";
