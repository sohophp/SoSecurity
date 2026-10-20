<?php
declare(strict_types=1);

namespace SoSecurity\Examples\Psr15;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Psr15\BudgetMiddleware;
use SoSecurity\RateLimit\BudgetLimiter;

/** Install after the host has verified the current session and set a fresh Account attribute. */
function accountWriteBudget(BudgetLimiter $limiter, ResponseInterface $denied): BudgetMiddleware
{
    return new BudgetMiddleware($limiter, 'account-write', static function (ServerRequestInterface $request): string {
        $account = $request->getAttribute('verified_account');
        if (!$account instanceof Account || !$account->enabled()) {
            throw new SecurityException('Verified account required before request budget.', 'auth.required');
        }
        return hash('sha256', json_encode([$account->scope(), $account->subject()]));
    }, $denied);
}
