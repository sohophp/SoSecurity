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
    private $limiter;
    private $scope;
    private $subject;
    private $denied;
    private $cost;

    public function __construct(BudgetLimiter $limiter, string $scope, callable $subject, ResponseInterface $denied, int $cost = 1)
    {
        if ($scope === '' || strlen($scope) > 128 || preg_match('/\A[a-zA-Z0-9_.:-]+\z/D', $scope) !== 1
            || $cost < 1 || $cost > 1000000 || $denied->getStatusCode() < 400 || $denied->getStatusCode() > 599) {
            throw new ConfigurationException('Invalid PSR-15 budget scope, cost or denial response.', 'configuration.budget');
        }
        $this->limiter = $limiter;
        $this->scope = $scope;
        $this->subject = $subject;
        $this->denied = $denied;
        $this->cost = $cost;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $subject = ($this->subject)($request);
        if (!is_string($subject)) {
            throw new ConfigurationException('PSR-15 subject resolver must return a string.', 'configuration.budget');
        }
        $decision = $this->limiter->consume($this->scope, $subject, $this->cost);
        if (!$decision->allowed()) {
            return $decision->retryAfter() > 0
                ? $this->denied->withHeader('Retry-After', (string) $decision->retryAfter())
                : $this->denied;
        }
        return $handler->handle($request);
    }
}
