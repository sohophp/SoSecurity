# G5 受保护宿主的 HTTP、TLS 与浏览器接入

日期：2026-10-21（Asia/Shanghai）。继续原 P1／G5，31 项／80 个有效工作小时上限保持。扩展现有 `examples/managed-authentication.php`，让同一真实服务图完成密码／MFA、浏览器会话、账号 API 管理及独立 Bearer 身份读取。本组为本地 SQLite 宿主，不代表全部宿主、MySQL HTTP、业务事务组合或最终恢复通过。

## 示例接线

私有引导文件继续可以返回原 `Security`，原登录／退出表单保留。保护模式须配置固定 `SOSECURITY_MANAGED_AUTH_EXAMPLE_ORIGIN`，来源、会话／因子／身份服务、工作进程围栏必须来自同一准确图。支持 API 时，私有文件按顺序返回 `['security'=>$sdk, 'state_policy'=>$stateAccountPolicy]`；策略须由这个 SDK 的 `stateAccountPolicy()` 生成。示例不初始化数据库、因子或独立见证，不自动采用现有来源。

引导文件在隔离作用域内接收三个闭包：`$requestGuard` 执行外层 CSRF／预算前置检查，`$requestCurrent` 只读观察本次已通过的检查，`$apiRequestGuard` 分离 API 认证与管理。保护模式的认证服务使用 `StateRequests($requestGuard,$requestCurrent)`，账号凭证配置的 request_guard 使用 `$apiRequestGuard`。它们不允许在见证锁内再次消费 CSRF 或预算。真实宿主仍须声明完整实际来源和纯策略；测试引导文件不能直接当生产配置。

所有控制动作先验证请求方法、固定路由、字段及 CSRF，再调用可能更新原生会话 seen 的验证。六个 API 管理动作仅接受 JSON 响应的 POST：`api_issue/api_all/api_rotate/api_replace/api_revoke/api_revoke_all`，目标来自实际 PHP 会话里的服务器身份，经 SDK 再验证；不接受客户端 owner。scopes 为逗号分隔字符串，TTL／generation 要求有界规范整数。表单仅允许有限个扁平字段，重复名称、别名、嵌套数组、非法百分号、非 UTF-8 和未知字段明确拒绝。

`GET ?api=identity` 必须提供满足 `records:read` 的有效 Authorization Bearer。该路由不启动 PHP 会话、不创建 CSRF、不设置 Cookie；Cookie 不能充当 Bearer，混合请求仍只按 Bearer 判断。它只返回最小已认证身份，不是业务读写事务示例。普通未保护引导文件不会因此自动开放 API。

固定 Origin 同时约束 Host 和传输，现有代理头不能推断 HTTPS；生产默认 HTTPS，明文开关仅用于回环测试。POST 若提供 Origin，必须与配置精确一致，`null` 也拒绝。HTML 使用 `Referrer-Policy: same-origin`，JSON 保留 `no-referrer`；这是为修复 Chromium 表单在旧 no-referrer 策略下实测发送 Origin:null、从而被严格检查拒绝的问题。跨来源不发送回引 URL。CSP 仅增加同源 connect-src 供原生 API 调用，其他默认拒绝、frame-ancestors 和 form-action 限制保留。

## 已冻结验证与边界

**已执行并通过：固定 11 条命令全部退出 0，准确输入保持一致，四个临时受保护宿主目录和服务器已清理。** 两端各通过原 HTTP 74 项、新 HTTP 297 项、TLS 305 项；四次 Chromium 流程（原示例两次、新保护 TLS 两次）通过。PHP7.2／8.5 语法、261 类公开契约及全库 src 静态分析通过，保留既有可选 turbo 扩展 GLIBC 加载警告。库 src 和公开契约与前一意图快照逐字节相同。

固定 11 条命令，两端各执行示例语法、原 HTTP＋Chromium 兼容、新 HTTP、新 TLS＋Chromium、公开签名，另做全库 src 静态分析。输入包括示例、库、测试 Python／PHP／CJS、资源契约及配置；见[执行记录](state-http-evidence-2026-10-21/execution.json)和[交付核对](state-http-evidence-2026-10-21/delivery-check.json)。本组停止扩测，不以历史检查合并成九版整轮。

真实证据包含密码、TOTP、恢复码、Cookie 轮换及 HttpOnly／SameSite／Secure；无效 CSRF／Origin（含 null）、重复表单／查询、错误方法、越权范围、Owner 注入和旧令牌拒绝时比较完整认证 SQL、原生认证文件及独立见证。错误密码／MFA 允许记录合法尝试，但必须保持已确认 current。独立公共预算与 PHP 会话容器可能更新，不能把“原生认证来源无变化”说成所有外部状态均无效果。

Chromium 从另一同站点、不同 Origin 的真实页面发送带 Cookie／有效 CSRF 的 POST。CORS 禁止脚本读取响应；测试使用服务端仅含 method／origin／Cookie 存在性／status 的独立记录确认 403，并比较完整来源摘要和见证版本不变。不读取或记录 Cookie 值，也不关闭 CORS 来读取响应。

联合备份回归实际恢复旧 SQL、全部认证 JSON 和 PHP 会话文件，保留新的独立见证。此前已撤销的旧 Bearer、旧 Cookie／CSRF 管理请求均返回 503，认证来源和权威未继续写入；这不是仅恢复数据库或仅断言某个模拟回调失败。没有恢复／替换见证文件或将旧数据认作新基线。

TLS 使用私有自签本地 CA 和受控回环桥接，Python 客户端实际校验证书；Chromium 对这份测试证书设置 ignoreHTTPSErrors。桥接的私有测试 nonce 仅在测试路由器识别，生产示例没有该入口；直接后端加 X-Forwarded-Proto 无法绕过 HTTPS 检查。实体设备、第三方证书、生产源站隔离、重复首部及真实代理／WAF 仍须独立验收。

测试专用重建以当次实际墙上时间初始化每请求时钟，未覆盖单请求内跨秒到期或生产成本；旧 CLI 时间故障专项属于各自快照。PHP7.2 使用私有 sodium／posix／原生单调时钟，不称原版系统整轮通过。新保护图 16 MiB；没有新增 Composer 或生产 Node 依赖。可选浏览器由现有 Playwright 提供，`SOSECURITY_REQUIRE_STATE_BROWSER=1` 在主门禁中强制执行，缺工具应失败。

## 首次失败保留

首轮 Chromium 登录 403，经脱敏头部诊断确认 Origin:null；HTML 策略修复后合法表单 Origin 正确，null 仍拒绝。首次控制器错误日志还因漏导入 sys 产生二次异常，已修复。后续跨来源检查先后发现 Playwright 无法取得被 CORS 阻止响应的 response 事件／完整安全首部，改为保留实际请求与服务端状态观察；未更改 403、Cookie 存在及来源无变化的判据，也未延长等待上限。原日志、失败版本和准确限定见[登记](state-http-evidence-2026-10-21/failure-register.json)。开发预检与最终冻结结果分开。

## 仍未完成

自定义／带效果审计委托、其他授权／一次性证明和后台写入者、旧工作进程交接、最终账号启用／新密码与 MFA 登录仍开放。MySQL 真实 HTTP、业务 PDO 事务组合、全部宿主、长期运行容量、见证／审计自身中断与维护、通知／队列、SMTP／OIDC／实体设备／WAF、远端 CI、独立复核和最终同源码九版整轮未由本组关闭。完整 G1／G4／G5／F01／R1—R6 仍未完成。未提交、推送或发布。
