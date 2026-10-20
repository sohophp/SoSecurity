<?php
declare(strict_types=1);
namespace SoSecurity\Examples;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\Resource;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\RateLimit\BudgetResult;
use SoSecurity\Security;

/** Call after trusted login/tenant/CSRF/authorization checks and before costly report work.
 * $clientIp comes from the host's configured trusted-proxy resolver; $actor is its freshly verified account.
 * Host maps the named ip/account/tenant policies in configuration. This function sends no headers or business output.
 */
function reserveReportBudget(Security $security, string $action, string $clientIp, Account $actor): BudgetResult
{
    $costs = ['report.preview' => 1, 'report.export' => 3];
    if (!isset($costs[$action]) || !$actor->enabled() || filter_var($clientIp, FILTER_VALIDATE_IP) === false) {
        throw new \SoSecurity\Exception\ValidationException('Invalid trusted report-budget context.', 'rate.context');
    }
    // JSON array hashing avoids tenant/subject delimiter collisions and does not reveal account names in keys.
    $account = hash('sha256', json_encode([$actor->scope(), $actor->subject()]));
    return $security->budgetComposite(['ip', 'account', 'tenant'])->consume('reports',
        ['ip' => inet_ntop(inet_pton($clientIp)), 'account' => $account, 'tenant' => $actor->scope()],
        ['ip' => 1, 'account' => $costs[$action], 'tenant' => $costs[$action]]);
    // The caller must require result.allowed(), handle 429/Retry-After or storage failure, then run the operation.
    // Never refund on failure or reset after success; these are attempt budgets, not concurrency leases.
}

/** Native POST order: current session, CSRF, current resource load/permission, budget, business work.
 * Subject, scope and CSRF binding come from the protected host session. The loader reads current server data.
 * The host maps this outcome to HTTP and must recheck resource version in its business write transaction.
 */
function runReportPost(Security $security, SessionRegistry $sessions, CsrfTokens $csrf, Authorizer $authorizer,
    string $serverScope, callable $loadResource, string $method, string $serverSessionSubject, $sessionToken, string $serverCsrfBinding, $csrfToken,
    string $action, string $trustedClientIp, callable $work): array
{
    if ($method !== 'POST') { return ['status' => 405, 'retry_after' => 0, 'value' => null]; }
    $verified = $sessions->verify($serverScope, $serverSessionSubject, $sessionToken);
    if ($verified === null) { return ['status' => 401, 'retry_after' => 0, 'value' => null]; }
    if (!$csrf->verify('reports:write', $serverCsrfBinding, $csrfToken)) {
        return ['status' => 403, 'retry_after' => 0, 'value' => null];
    }
    $resource = $loadResource($verified->account());
    if ($resource === null) { return ['status' => 404, 'retry_after' => 0, 'value' => null]; }
    if (!$resource instanceof Resource || $resource->scope() !== $serverScope) {
        throw new \SoSecurity\Exception\SecurityException('Current resource loader returned an invalid scope.', 'authorization.resource');
    }
    if (!$authorizer->decide($serverScope, $verified->account(), $action, $resource)->allowed()) {
        return ['status' => 403, 'retry_after' => 0, 'value' => null];
    }
    $budget = reserveReportBudget($security, $action, $trustedClientIp, $verified->account());
    if (!$budget->allowed()) { return ['status' => 429, 'retry_after' => $budget->retryAfter(), 'value' => null]; }
    return ['status' => 200, 'retry_after' => 0, 'value' => $work($verified->account(), $resource)];
}
