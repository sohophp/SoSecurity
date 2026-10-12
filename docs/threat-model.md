# 威胁模型和安全边界

资产：登录身份、Session/CSRF/重置令牌、验证码答案、密码哈希、限流状态及日志。攻击者可构造请求、表单和转发头，可并发调用并不断更换 Session/IP/账号；不能被假定只能从 UI 提交。

| 威胁 | 0.1 控制 | 宿主责任/限制 |
| --- | --- | --- |
| 跨站伪造/跨作用域令牌 | 随机摘要令牌、服务器绑定、作用域隔离 | 所有状态变化后端验证；GET 无写操作；XSS 能绕过 CSRF；不要把令牌写日志/URL |
| 重放及并发消费 | 锁/Redis CAS 内单次消费 | 普通 CSRF 重用是明确策略；重置消费与业务写库不是跨资源事务，写库失败需重新发令牌 |
| 验证码猜测 | 有限错误次数、过期、原子删除、创建端限流 | 数学题和简单图片不能抵御自动识别；刷新、业务请求及 Session 创建仍须限流 |
| 暴力破解/凭据填充 | 验证前预算、IP+账号作用域、封禁阶梯 | 分布式 IP 可绕过单一主体预算；需要应用及基础设施综合控制；不是网络 DDoS 防护 |
| IP 欺骗 | 默认 REMOTE_ADDR、明确 CIDR、从右至左代理链 | 可信入口须覆盖或追加真实上一跳；禁止任意客户端直达未正确配置的可信代理；不盲信 CF 头 |
| Session 固定/超时 | strict_mode、显式更新 ID、超时失效 | 自定义驱动支持 validateId/锁；所有认证入口接入检查；PHP 7.2 手动发 SameSite；更新 ID 有并行旧请求竞态，应处理重新登录 |
| 密码截断/旧哈希降级 | 原生算法、字节检查、明确升级回调 | MFA、账号恢复和参数化查询属于宿主；未知旧格式不能自动迁移；保持算法配置一致 |
| 状态故障/竞态 | 原子事务、有限重试、异常拒绝 | Redis 禁止逐出，磁盘容量监控、cron prune；应用或主机崩溃后的丢失不提供持久性保证；定时清理孤立 .write- 文件须在停止写入时进行 |
| 多站点串用/存储泄露 | namespace、散列键、私有文件权限 | namespace 应固定且唯一；宿主不能将 Session ID、秘密或答案作为公开 URL/业务字段；不同应用不能共享同一可读文件目录 |
| 日志泄露/注入 | 结构化事件、白名单数值字段、HMAC 假名化 | scope/event 使用服务器常量，subject 不得传入密码/令牌；日志系统保护、保留期、权限由宿主决定；不自动记录异常完整信息 |
| XSS | HTML/引用属性编码、JSON 数据编码 | 不能用于 JS 标识符、事件属性、CSS、srcdoc 或不安全 URL；Twig 不使用 raw；富文本后续接成熟清理库 |
| 文件上传/SSRF/API 签名 | 本里程碑未实现 | 不宣称 URL 格式验证能阻止 SSRF；不提供未测试的上传/签名安全保证 |

配置错误抛出异常，第三方验证码不可达抛出异常；宿主返回 503 并停止业务。拒绝后不能在 catch 中继续登录。攻击者能直接改写共享安全存储时，防护不再成立。

SoSecurity 不替代授权检查、参数化 SQL、HTTPS、基础设施防护或运行时更新。PHP 7.2 等停止维护的版本仅做代码兼容；组件不能补上运行时本身的全部漏洞。本次内部代码审查和测试不是独立安全审计。

## 参考来源

- [OWASP CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)：有状态同步令牌、上下文与登录会话绑定。
- [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)：限流与恶意账号锁定权衡。
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)：原生成熟算法及 bcrypt 长度边界。
- [OWASP Session](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)、[PHP Session 设置](https://www.php.net/manual/en/session.security.ini.php)：固定攻击、超时与 Cookie。
- [OWASP XSS](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)：上下文编码与 HTML 清理的区别。
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)：后续发布验收参考，不宣称已通过 ASVS 认证。
- [Cloudflare Siteverify](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)：服务端验证、300秒/单次使用及 hostname/action 检查。
- [Redis Transactions](https://redis.io/docs/latest/develop/using-commands/transactions/)：WATCH/MULTI/EXEC 乐观并发事务。
- [PHP 支持版本](https://www.php.net/supported-versions.php)：代码兼容不等于上游仍维护。
