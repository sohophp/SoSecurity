# 可选 PSR-15 请求预算适配

`integrations/psr15` 是独立 Composer 包 `sohophp/sosecurity-psr15`。核心包不依赖 PSR HTTP 接口；只有使用中间件的项目才安装适配包及 PSR-7 响应实现。当前适配包仍在本地工作树，尚未发布到包仓库；可用 Composer path repository 指向本仓库及 `integrations/psr15` 做接入验证。

`SoSecurity\Psr15\BudgetMiddleware` 实现 PSR-15 的 `MiddlewareInterface`。它在调用下游 `RequestHandlerInterface::handle()` 之前，使用已注入的 `BudgetLimiter` 消耗固定作用域的一次预算。调用方注入从可信请求上下文取得主体标识的回调，以及状态码为 4xx／5xx 的拒绝响应。超限时不调用下游；有重试时间时在拒绝响应上设置 `Retry-After`。主体解析、存储故障和损坏状态抛出异常，须由宿主的最外层异常处理器安全转换为失败响应，不得继续调用业务处理器。

```php
use SoSecurity\Psr15\BudgetMiddleware;

// $limiter 使用生产共享原子存储；$denied 是宿主 PSR-7 实现的 429 响应。
$middleware = new BudgetMiddleware(
    $limiter,
    'api-write',
    static function ($request): string {
        return $request->getAttribute('authenticated_account_id');
    },
    $denied
);
```

把中间件放在可信代理地址规范化及必要的身份识别之后、昂贵正文解析和业务副作用之前。若身份识别本身昂贵，先按经过可信代理规则确认的客户端地址设置独立预算，再在认证后使用账号预算；不要直接信任请求头里的账号或客户端地址。`MemoryStore` 仅用于单进程测试，生产须使用共享原子后端。调用方仍负责路由、认证、CSRF、响应创建和异常处理；本适配层不自动启动 Session、读取请求正文或改写宿主响应。已放行的请求即使后续业务失败也已经消耗预算。

原生宿主可参考[账号预算示例](../examples/psr15-account-budget.php)：完成当前会话验证后，把新鲜的`Account`对象设置为服务端请求属性`verified_account`，再运行`accountWriteBudget($limiter, $denied)`；示例将站点作用域和账号标识一起形成预算主体，缺失或停用账号时拒绝继续。请求头`X-Account-Id`不会成为身份来源。持有`Account`对象本身不证明已登录，宿主必须先完成会话与当前权限核验；CSRF、路由授权和错误响应仍需按实际操作配置，不能把预算结果当作授权。

本地独立消费者验证：`python3 tests/psr15_consumer.py php72 php73 php74 php80 php81 php82 php83 php84 php85`。九版均已通过。该脚本只在临时目录安装 Composer 依赖，使用内存测试存储，不连接业务数据库。当前覆盖正常放行、预算拒绝与 `Retry-After`、下游调用次数、错误主体、错误拒绝响应、存储故障、无重试时间的拒绝，以及账号属性缺失／停用和伪造账号头不改变预算主体。完整 R4.5 的实际宿主调用顺序仍待验收。
