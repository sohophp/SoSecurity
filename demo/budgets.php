<?php
declare(strict_types=1);
namespace SoSecurityDemo;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\RateLimit\BudgetLimiter;
use SoSecurity\RateLimit\BudgetGroup;
use SoSecurity\RateLimit\CompositeLimiter;
use SoSecurity\Storage\SessionStore;

/** Visitor-owned teaching counters. Production factories require a genuinely shared store. */
final class BudgetSamples
{
    private $clock;
    private $store;
    public function __construct() { $this->clock = new DemoClock('budgets'); $this->store = new SessionStore('demo-budgets', $this->clock); }
    private function options(): array { return $_SESSION['demo_budget_options'] ?? ['algorithm' => 'token_bucket', 'mode' => 'single', 'ip' => 'ip-one', 'account' => 'alice']; }
    private function policy(string $algorithm): BudgetPolicy { return new BudgetPolicy($algorithm, 5, 60, null, $algorithm === 'sliding_window' ? 4 : 512); }
    private function service(array $options)
    {
        $work = $this->policy($options['algorithm']);
        if ($options['mode'] === 'atomic') { return new BudgetGroup($this->store, ['requests' => new BudgetPolicy('fixed_window', 2, 60), 'work' => $work], $this->clock); }
        if ($options['mode'] === 'ordered') { return new CompositeLimiter(['ip' => new BudgetLimiter($this->store, new BudgetPolicy('fixed_window', 20, 60), $this->clock), 'account' => new BudgetLimiter($this->store, $work, $this->clock)], $this->clock); }
        return new BudgetLimiter($this->store, $work, $this->clock);
    }
    private function evaluate(array $options, int $cost, bool $consume)
    {
        $service = $this->service($options); $method = $consume ? 'consume' : 'inspect'; $scope = 'demo-budget-' . $options['mode'] . '-' . $options['algorithm'];
        if ($options['mode'] === 'atomic') { return $service->$method($scope, 'visitor', ['requests' => 1, 'work' => $cost]); }
        if ($options['mode'] === 'ordered') { return $service->$method($scope, ['ip' => $options['ip'], 'account' => $options['account']], ['ip' => 1, 'account' => $cost]); }
        return $service->$method($scope, 'visitor', $cost);
    }
    public function run(string $action, string $algorithm, string $mode): array
    {
        if (!in_array($algorithm, ['token_bucket','fixed_window','sliding_window'], true) || !in_array($mode, ['single','atomic','ordered'], true)) { throw new \SoSecurity\Exception\ConfigurationException('Invalid demo budget selection.'); }
        $options = $this->options(); $options['algorithm'] = $algorithm; $options['mode'] = $mode; $_SESSION['demo_budget_options'] = $options;
        if ($action === 'advance') { $this->clock->advance(61); return ['valid' => true, 'message' => '仅当前访客的测试时间前进 61 秒。']; }
        if ($action === 'change_ip' || $action === 'change_account') {
            $field = $action === 'change_ip' ? 'ip' : 'account'; $values = $field === 'ip' ? ['ip-one','ip-two'] : ['alice','bob'];
            $options[$field] = $options[$field] === $values[0] ? $values[1] : $values[0]; $_SESSION['demo_budget_options'] = $options;
            return ['valid' => true, 'message' => '已切换隔离测试身份，其他维度计数继续保留。'];
        }
        if ($action === 'reset') {
            foreach (['token_bucket','fixed_window','sliding_window'] as $algorithm) {
                $p = $this->policy($algorithm); (new BudgetLimiter($this->store, $p, $this->clock))->reset('demo-budget-single-' . $algorithm, 'visitor');
                $this->service(['mode' => 'atomic', 'algorithm' => $algorithm])->reset('demo-budget-atomic-' . $algorithm, 'visitor');
                foreach (['ip' => ['ip-one','ip-two'], 'account' => ['alice','bob']] as $dimension => $subjects) {
                    $limiter = new BudgetLimiter($this->store, $dimension === 'ip' ? new BudgetPolicy('fixed_window', 20, 60) : $p, $this->clock);
                    foreach ($subjects as $subject) { $limiter->reset(CompositeLimiter::scopeFor('demo-budget-ordered-' . $algorithm, $dimension), $subject); }
                }
            }
            $_SESSION['demo_budget_work'] = 0; return ['valid' => true, 'message' => '已清除当前访客的全部测试预算，正式业务只允许授权运维重置。'];
        }
        if ($action === 'store_failure') {
            $fault = new class implements \SoSecurity\Storage\AtomicStore { public function transact(string $key, callable $callback) { throw new \SoSecurity\Storage\StorageException('Fixed demo store failure.'); } };
            (new BudgetLimiter($fault, new BudgetPolicy(), $this->clock))->consume('demo-fault', 'visitor');
        }
        $cost = $action === 'batch' ? 3 : ($action === 'oversize' ? 100 : 1); $decision = $this->evaluate($options, $cost, $action !== 'inspect');
        if ($action !== 'inspect' && $decision->allowed()) { $_SESSION['demo_budget_work'] = ($_SESSION['demo_budget_work'] ?? 0) + 1; }
        $composite = $decision instanceof \SoSecurity\RateLimit\BudgetResult;
        return ['valid' => $decision->allowed(), 'retry_after' => $decision->retryAfter(), 'cost' => $cost,
            'charged' => $composite ? $decision->charged() : ($action !== 'inspect' && $decision->allowed() ? ['work'] : []),
            'message' => $action === 'inspect' ? '只检查余额，未执行业务。' : ($decision->allowed() ? '预算扣减成功，测试业务执行一次。' : '预算拒绝，测试业务执行次数保持不变。')];
    }
    public function state(): array
    {
        $options = $this->options(); $result = $this->evaluate($options, 1, false); $decisions = $result instanceof \SoSecurity\RateLimit\BudgetResult ? $result->decisions() : ['work' => $result]; $balances = [];
        foreach ($decisions as $name => $decision) { $balances[$name] = ['remaining' => $decision->remaining(), 'allowed' => $decision->allowed(), 'reason' => $decision->reason(), 'retry_after' => $decision->retryAfter()]; }
        return $options + ['executed' => $_SESSION['demo_budget_work'] ?? 0, 'balances' => $balances, 'storage' => 'visitor_session_only', 'clock_resolution' => 'seconds'];
    }
}
