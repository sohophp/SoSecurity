<?php
declare(strict_types=1);

namespace SoSecurity\Psr15;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\RateLimit\BudgetLimiter;

/** Request budget before the application handler, with no implicit identity or response factory. */
final class BudgetMiddleware implements MiddlewareInterface
{
    private $read;

    public function __construct(BudgetLimiter $limiter, string $scope, callable $subject, ResponseInterface $denied, int $cost = 1)
    {
        if ($scope === '' || strlen($scope) > 128 || preg_match('/\A[a-zA-Z0-9_.:-]+\z/D', $scope) !== 1
            || $cost < 1 || $cost > 1000000 || $denied->getStatusCode() < 400 || $denied->getStatusCode() > 599) {
            throw new ConfigurationException('Invalid PSR-15 budget scope, cost or denial response.', 'configuration.budget');
        }
        // Keep retained host services and denial bodies out of object export/debug output.
        $this->read = static function () use ($limiter, $scope, $subject, $denied, $cost): array {
            return [$limiter, $scope, $subject, $denied, $cost];
        };
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        [$limiter, $scope, $resolve, $denied, $cost] = ($this->read)();
        $subject = $resolve($request);
        if (!is_string($subject)) {
            throw new ConfigurationException('PSR-15 subject resolver must return a string.', 'configuration.budget');
        }
        $decision = $limiter->consume($scope, $subject, $cost);
        if (!$decision->allowed()) {
            return $decision->retryAfter() > 0
                ? $denied->withHeader('Retry-After', (string) $decision->retryAfter())
                : $denied;
        }
        return $handler->handle($request);
    }

    public function __debugInfo(): array { return ['budget_middleware' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild PSR-15 middleware from trusted services.', 'configuration.budget_serialization');
    }
    public function __wakeup(): void
    {
        throw new ConfigurationException('Rebuild PSR-15 middleware from trusted services.', 'configuration.budget_serialization');
    }
}
