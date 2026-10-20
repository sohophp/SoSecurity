# 受管理 MFA 原生登录接入

`examples/managed-authentication.php` 是最小原生 HTTP 样例：GET 返回无缓存表单或 JSON，POST 执行密码、二次验证与退出。它只读取宿主私有引导文件；不创建账号、迁移因子或初始化工作进程权威。正式宿主应将同一当前账号 PDO 同时用于 `Auth\IdentityProvider` 和 `Account\FactorRepository`，并按[受管理因子指南](account-factors.md)先完成迁移与停旧进程。

设置两个私有路径：`SOSECURITY_MANAGED_AUTH_EXAMPLE_BOOTSTRAP` 指向 Web 根目录外、权限为 `0600` 的 PHP 文件；`SOSECURITY_MANAGED_AUTH_EXAMPLE_STATE` 指向 Web 根目录外、权限为 `0700` 的本机请求预算目录。引导文件在当前请求作用域内取得 `$requestGuard`，返回一个 `Security` 对象；配置必须有 `authentication.managed_factors=true`、当前 `account_factors` 和共享认证存储。宿主注入实际当前身份、同 PDO 仓储、原始物理因子、准确 `LocalEpochFence`、完整权限回调与同步持久化回调。不要把测试中的固定密钥或固定放行回调复制到实际部署。测试专用引导文件在 `tests/managed-auth-http-bootstrap.php`，只可用于受控本地测试。

样例对每次 POST 检查服务器会话绑定的 CSRF、8 KiB 请求上限和共享文件预算；成功完成二次验证后轮换原生 Session ID，旧 CSRF 失效。令牌和恢复码只存在于受保护请求与服务器状态，响应设为 `Cache-Control: no-store`，并发送 `HttpOnly`、`SameSite=Lax` 会话 Cookie。生产请求要求 PHP 直接确认 HTTPS；`SOSECURITY_MANAGED_AUTH_EXAMPLE_HTTP=1` 只允许来自回环地址的本地测试。若目标部署在反向代理之后，宿主需先建立可信 TLS／代理边界再改造入口，不能直接信任客户端的 `X-Forwarded-*`。

本地专项由控制器创建临时 SQLite、因子存储、权威文件、私有引导文件与回环 HTTP 服务，结束后关闭服务并删除测试目录：

```sh
python3 tests/managed_auth_http.py /path/to/php-with-sodium
SOSECURITY_PLAYWRIGHT_MODULE=/path/to/playwright python3 tests/managed_auth_http.py --browser /path/to/php-with-sodium
```

第一条验证真实 POST／CSRF／无缓存、密码加 TOTP、会话轮换、旧 Cookie 和退出；第二条另用 Chromium 完成表单登录、恢复码、`HttpOnly` Cookie 轮换和退出。本地结果不证明目标宿主的身份／权限源、真实持久化、代理 TLS、生产请求预算、远端 CI 或正式发布。
