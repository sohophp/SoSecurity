# SoSecurity PSR-15 request budget adapter

This optional Composer package exposes `SoSecurity\Psr15\BudgetMiddleware`. It requires the core SoSecurity package and PSR HTTP interfaces; the core package does not depend on PSR-15.

Construct the middleware with a `BudgetLimiter`, a fixed server-side scope, a subject resolver that reads a freshly verified host identity, and a host-created 4xx/5xx denial response. The middleware consumes the request budget before invoking the downstream handler. A denied request never invokes that handler; a positive retry delay is returned in `Retry-After`.

Identity resolution and storage failures propagate to the host's outer error handler. The host remains responsible for authentication, CSRF checks, authorization, response generation, and the ordering of these checks around business work. Do not derive the budget subject from a client-supplied account header. The package is currently a local candidate, not a published release.

Middleware diagnostics redact retained host services and denial-response contents. Serialization and deserialization are rejected; rebuild the middleware from trusted services for each container lifecycle. This does not prevent a trusted in-process debugger from inspecting application memory.

中间件的调试／导出输出不展开宿主服务和拒绝响应内容；禁止序列化及反序列化，请由可信服务容器重新构造。此保护不限制进程内可信调试器对应用内存的访问。
