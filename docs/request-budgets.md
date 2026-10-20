# 加权请求预算与组合限流

请求预算（request budget）统计已接受的尝试成本，用于在查询、导出、哈希或发送任务前限制资源消耗。旧 `RateLimiter`／`Policy` 及其固定窗口、封禁阶梯和管理方法保持兼容；新组件显式启用，不自动封禁，也不替代身份、授权、CSRF、请求体限制、队列或并发租约。

## 算法与边界

| `BudgetPolicy` 算法 | `limit`／`window` | 行为 |
| --- | --- | --- |
| `token_bucket` | 每 `window` 秒补充 `limit` 单位 | 初始装满，`burst` 为容量、默认等于limit；整数信用单位计算分数余额，避免浮点误差 |
| `fixed_window` | 一个窗口最多limit单位 | 首次接受请求建立窗口；拒绝不顺延期限，边界允许相邻窗口突发 |
| `sliding_window` | 最近window秒最多limit单位 | 精确保存已接受请求的秒级历史，同秒成本合并；统计区间 `(now-window, now]`，不使用前一窗口占比估算 |

`Clock` 精度为整秒，令牌补充也按整秒进行；不能把它描述成毫秒级平滑速率。同一部署必须使用一致且同步的时钟，后端和服务共用时间源。记录仍存在时检测时间回退并拒绝；不能检测已被后端正常清除的历史。基础设施还需限制应用进程之前的请求流量。

默认策略为令牌桶10单位／60秒；limit和burst为1—1,000,000，window为1—86,400秒。burst只用于令牌桶。完整补充期限不得超过一年，容量乘窗口不得溢出平台整数。滑动窗口 `maximumEntries` 默认512、范围1—1024，只能对滑动算法修改。达到不同秒的记录容量后即使尚有成本余额也返回 `rate.capacity`，等待最早记录过期；拒绝不增添历史，不近似放行。单个原子组最多1,536个滑动历史项，满足共享存储64KiB与节点预算。

成本为服务器定义的正整数1—1,000,000，例如预览1、导出3；禁止让客户端直接指定成本或通过0跳过检查。成本大于容量时 `rate.cost_exceeds_limit` 永不适配，retryAfter为0；应减少业务规模或由运维审查策略，反复等待无效。其余拒绝的retryAfter是按当前状态计算的最早重试秒数，不保证后续竞争请求之后仍可通过。

## 单项与只读检查

```php
$policy = new SoSecurity\RateLimit\BudgetPolicy('token_bucket', 30, 60, 10);
$budget = new SoSecurity\RateLimit\BudgetLimiter($sharedStore, $policy, $clock);
$result = $budget->consume('reports', $serverSubject, 3);
if (!$result->allowed()) {
    // 宿主返回429；仅当retryAfter()>0时设置Retry-After，不执行导出。
    return;
}
// 立即开始已授权的导出；失败也保留尝试成本，不自动退还。
```

`remaining()` 对consume返回扣减后完整单位余额，对inspect返回当前余额。`inspect(scope, subject, cost)` 不扣减、创建新记录或改变原状态／TTL，但仍需要访问存储；不能先inspect再执行业务。原子consume才可决定是否开始操作。超容量成本的remaining统一为0，不表示实际余额已耗尽。

成功consume提供排他的 `reservedUntil()` 边界；只读和拒绝为0。组件在存储返回后复核时间，如果配额记录已过期则抛 `rate.expired`，时钟回退抛 `rate.clock`，都不得开始业务。存储异常可能发生在提交之后，扣减可能已经保留，不能以异常为由补发或退款。结果只能在本次请求立即使用，不能缓存、序列化、作为后续授权凭据，或在长时间排队之后继续使用。

预算只限制尝试频率；业务开始后的执行期限、并发数、取消和旧工作进程隔离需另外控制。允许开始也不保证整个业务在配额记录过期之前完成。

## 两种组合方式

| 组件 | 原子范围 | 后项拒绝时 | 合适用途 |
| --- | --- | --- | --- |
| `BudgetGroup` | 同scope、同主体、一个独立账本，一次AtomicStore事务 | 全部不扣减 | 同账号每分钟／每日预算、次数与工作量须一起扣减 |
| `CompositeLimiter` | 每个维度各自原子，按配置顺序处理 | 保留前项已提交成本，后续项不访问 | IP、账号、租户、API凭据等独立主体预算 |

```php
$group = new SoSecurity\RateLimit\BudgetGroup($sharedStore, [
    'requests' => new SoSecurity\RateLimit\BudgetPolicy('fixed_window', 10, 60),
    'work' => new SoSecurity\RateLimit\BudgetPolicy('sliding_window', 20, 60),
], $clock);
$result = $group->consume('reports', $accountKey, ['requests' => 1, 'work' => 3]);
```

原子组拥有独立账本，不与单项BudgetLimiter共用计数，也不合并其他主体的配额。组内策略名称或参数改变时不能继续读取旧活动账本；仅调整成员顺序不改变指纹。拒绝不改子项余额或TTL；可更新组时钟防回退。

```php
$combined = new SoSecurity\RateLimit\CompositeLimiter([
    'ip' => $ipBudget, 'account' => $accountBudget, 'tenant' => $tenantBudget,
], $clock);
$result = $combined->consume('reports', [
    'ip' => $trustedClientIp, 'account' => $tenantAccountKey, 'tenant' => $tenantKey,
], ['ip' => 1, 'account' => 3, 'tenant' => 3]);
```

组合最多8项，名称为小写字母开头的1—64个小写字母／数字／下划线／连字符。subjects必须完整且无额外项；costs为空时所有维度默认1，非空时必须完整提供严格整数成本。全部绑定和成本校验在首次扣减之前完成。维度顺序由服务器固定，建议先检查宽松的入口预算再检查细分预算，不能让客户端选择略过某一维度。

跨维度拒绝或存储故障会保留前项扣减，这限制被拒绝的尝试反复消耗入口资源。组件不进行跨键退款，不承诺跨键、跨后端或跨业务数据库事务。改变IP不能清除账号预算，改变账号不能清除IP或租户预算；对账号硬限流要结合防恶意锁定策略。只有整体 `result.allowed()` 可放行业务，不能使用某个子项的allowed代替。`decisions()` 只含实际检查的项；`blocked()` 为已检查的拒绝项，`charged()` 明确列出本次已扣项，inspect始终为空。异常时没有完整result，也不能假定之前未扣。

独立维度使用 `CompositeLimiter::scopeFor($scope, $dimension)` 生成稳定子作用域。运维检查／重置单项必须使用该作用域和对应主体；直接使用reports不会访问组合的计数。多个组合实例中同scope、同维度名、同主体有意共享计数；不同路由若需要独立预算，应使用不同scope。

## 工厂与宿主接入

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/my-site/security'],
    'budgets' => [
        'ip' => ['algorithm' => 'fixed_window', 'limit' => 100, 'window' => 60],
        'account' => ['algorithm' => 'token_bucket', 'limit' => 10, 'window' => 60, 'burst' => 5],
        'tenant' => ['algorithm' => 'sliding_window', 'limit' => 500, 'window' => 60, 'maximum_entries' => 60],
    ],
]);
$single = $security->budgetLimiter('account');
$atomic = $security->budgetGroup(['account', 'tenant']); // 同一主体的独立组账本，不是两个全局主体计数
$ordered = $security->budgetComposite(['ip', 'account', 'tenant']);
```

最多配置64个命名策略，默认不启用budgets。工厂拒绝MemoryStore／SessionStore作为共享预算后端；直接构造仍允许测试场景。File仅同主机且共享私有目录适用，Redis／MySQL适用边界沿用各自指南。自定义AtomicStore需由宿主证明单键原子性、过期语义和恢复策略。

[报表接入示例](../examples/request-budgets.php)固定动作成本，使用已验证账号的租户和主体构造无歧义键，并规范化已解析的IP。`runReportPost()`演示原生PHP的明确顺序：仅POST，使用服务端Session保存的作用域／主体和令牌复核当前`SessionRegistry`，验证宿主Session绑定的CSRF，才调用宿主的当前业务`Resource`加载器并经`Authorizer`重新授权，扣IP／账号／租户预算，最后调用业务回调。会话或CSRF拒绝时不读取业务资源；资源不存在返回404，跨作用域加载结果安全拒绝。返回的`status`／`retry_after`由宿主映射为HTTP响应；存储或加载器异常向外抛出，应由最外层错误处理器返回安全失败，不能运行或重试业务。业务回调仍必须在自己的写事务中核对对象版本；其失败不会退还已扣额度。单独的[本地顺序测试](../tests/native-report-budget.php)覆盖拒绝、故障和业务失败。

昂贵认证前另外检查匿名入口预算。持有Account对象本身不构成登录证明；`serverSessionSubject`、CSRF绑定和`Resource`只能来自受保护的服务端状态与当前业务查询。不要把原始转发头、客户端tenant、Session ID或随机请求ID当稳定全局预算身份。这个示例不自动修改任何使用方路由或真实业务。

## 状态、策略变更及故障处理

记录严格校验v1格式、策略指纹、时钟、数值、事件顺序和期限。活动记录损坏、后端不可用或策略不同均抛异常拒绝，不静默重置或切换进程内存。改变策略使用受控新scope／版本，或排空原窗口后切换；如必须reset，应由授权运维明确承担清除额度的影响，同步所有工作进程，不能在成功登录、正常业务或异常恢复时自动调用reset。

缺失／被运维清空／被Redis淘汰的记录无法与首次访问区分。部署需保证共享状态持久性、禁止驱逐、控制键基数并有监控，恢复期间如不能证明预算可信应停止敏感入口。总键数、IP来源、账号规范化、匿名主体生命周期和后端容量由宿主控制；组件只限制单条状态。诊断只提示绑定、时钟和组合范围仍需人工核对，不把检查到配置当作已接入业务。

网页演示 `?module=budgets` 使用当前访客Session和隔离测试时间，可操作三算法、成本、原子／顺序组合、IP／账号切换及故障；它不证明跨Session全局限流。真实共享File／Redis／MySQL的24进程证据单独记录在[验证记录](verification.md)。

设计参考：[Symfony Rate Limiter](https://symfony.com/doc/current/rate_limiter.html)、[Redis rate limiting](https://redis.io/tutorials/rate-limiting-in-dotnet-with-redis/)。采用概念与工程边界独立实现，不依赖这些框架或声称协议互通。
