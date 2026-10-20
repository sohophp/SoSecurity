# 威胁模型和安全边界

资产：登录身份、Session/CSRF/重置令牌、验证码答案、密码哈希、限流状态、上传内容、外部连接边界、API凭据/签名密钥/Nonce及日志。攻击者可构造请求、表单和转发头，可并发调用并不断更换 Session/IP/账号；不能被假定只能从 UI 提交。

| 威胁 | 当前候选控制 | 宿主责任/限制 |
| --- | --- | --- |
| 跨站伪造/跨作用域令牌 | 随机摘要令牌或绑定当前登录的HMAC签名/双重提交；固定站点/作用域；精确路由策略 | 所有状态变化后端验证；GET 无写操作；XSS 能绕过 CSRF；不要把令牌写日志/URL；无状态仅令牌不入库，不提供单次消费；不使用静态用户ID代替登录绑定；见signed-csrf.md |
| 重放及并发消费 | 锁/Redis CAS 内单次消费 | 普通 CSRF 重用是明确策略；重置消费与业务写库不是跨资源事务，写库失败需重新发令牌 |
| 验证码猜测 | 有限错误次数、过期、原子删除、创建端限流 | 数学题和简单图片不能抵御自动识别；刷新、业务请求及 Session 创建仍须限流 |
| 暴力破解/凭据填充 | 验证前预算、IP+账号作用域、封禁阶梯 | 分布式 IP 可绕过单一主体预算；需要应用及基础设施综合控制；不是网络 DDoS 防护 |
| 加权资源耗尽／多维预算绕过 | 整数成本、三算法、单主体原子组、跨主体顺序预占及期限复核 | 宿主固定成本和维度、同步时钟、后端不驱逐与总键数控制；后项拒绝保留前项，异常不退款；结果不得缓存；不是并发租约，见 request-budgets.md |
| 超额并发／崩溃／旧任务继续写入 | 单键名额、绑定凭据、有界续期、永久序号、缺失账本拒绝；SQL固定epoch／序号／摘要／版本／数据库期限 | 租约到期不能停止旧进程，宿主逐步复核并执行写入隔离；持久性、备份／时钟／副本切换仍须验收；先提交SQL退休权限再提前释放，见 leases.md |
| IP 欺骗 | 默认 REMOTE_ADDR、明确 CIDR、从右至左代理链 | 可信入口须覆盖或追加真实上一跳；禁止任意客户端直达未正确配置的可信代理；不盲信 CF 头 |
| Session 固定/超时 | strict_mode、显式更新 ID、超时失效 | 自定义驱动支持 validateId/锁；所有认证入口接入检查；PHP 7.2 手动发 SameSite；更新 ID 有并行旧请求竞态，应处理重新登录 |
| 对象／字段／跨租户越权 | 默认拒绝、当前身份前后复核、精确角色／归属／属性、字段投影、整批授权及资源版本条件更新 | 宿主先验证身份并保留API scope，资源从带租户条件的权威查询加载；全批事务失败回滚，不能将UI或一次旧Decision当作权限证明；见 authorization.md |
| 旧认证冒充本次确认／参数替换／授权重放 | 准备后轮换同会话秘密、精确意图指纹、明确确认和单次消费、前后权限核验；原生表单绑定公开工作流ID | 展示真实关键数据、CSRF／预算、权威资源重载、SQL唯一执行记录／版本及期限、失败回滚；密码有效身份不能直接比较业务原始版本，见 operations.md；不承诺跨资源恰好一次或可信显示设备 |
| 签名URL篡改／撤销绕过／预取消耗 | 固定来源及原始规范URL、用途／版本／方法／全查询签名，共享保留账本查询／撤销／单次消费，状态字段与信封交叉核验 | 签发管理身份、资源／绑定刷新、HTTPS／Host、日志脱敏／缓存／条件请求；明确兑换采用POST及所需CSRF，不能回收已读内容；见 signed-links.md，私有文件读取另见downloads.md |
| 私有文件越权／校验后替换／读取耗尽 | 当前会话或真实签名URL、摘要／索引版本绑定、私有目录链及描述符身份、匿名完整快照，逐块读取前后复核；原生组合全源成本与四名额租约 | 权威索引／ready状态、私有部署与磁盘容量、实际输出和代理限制；客户端收完不表示服务器finally完成，失效不能追回已输出字节；同UID恶意进程／网络文件系统未保证，见 downloads.md |
| 持久Cookie泄露／重放／期限滑动 | 随机秘密摘要、作用域签名代际、同账本原子轮换和重放撤销、固定原认证期限、恢复来源标记 | 用户主动选择、HTTPS／CSRF／签发与存储预算；恢复后敏感操作重新认证；短并发只重试，丢失响应可要求重新登录；已泄露Cookie首次消费不能预先识别；见 remembered-login.md |
| 密码截断/旧哈希降级 | 原生算法、字节检查、明确升级回调 | 宿主负责完整 MFA 接入、账号恢复策略和参数化查询；未知旧格式不能自动迁移；保持算法配置一致 |
| 弱密码／泄露与计算耗尽 | 算法匹配的字节预算、有界全串拒绝表、可选HIBP前缀查询、原生哈希成本预检、隔离CLI校准 | 数据来源／覆盖与更新、部署成本预算、密码变更授权；服务失败不当作无命中；不逐键查询；查询DNS／HTTP共用期限；见 passwords.md |
| TOTP／恢复码猜测与重放 | 本轮增加加密因子、确认后启用、时间步／恢复码原子消费、共享错误预算和有限冷却 | 宿主保护管理入口、待 MFA 身份、CSRF、外层分配预算、恢复流程、会话撤销及通知；TOTP 不抗钓鱼；详见 mfa.md |
| 因子秘密泄露或跨对象搬移 | 可选 sodium 认证加密、用途／对象绑定、密钥版本与比较更新重加密 | 密钥与数据分开管理；验证密钥备份／退役，保护运行时内存和存储写权限；已被读取的秘密需要重新绑定 |
| 状态故障/竞态 | 原子事务、有限重试、异常拒绝 | Redis 禁止逐出，磁盘容量监控、cron prune；应用或主机崩溃后的丢失不提供持久性保证；定时清理孤立 .write- 文件须在停止写入时进行 |
| 多站点串用/存储泄露 | namespace、散列键、私有文件权限 | namespace 应固定且唯一；宿主不能将 Session ID、秘密或答案作为公开 URL/业务字段；不同应用不能共享同一可读文件目录 |
| 日志泄露/注入 | 结构化事件、白名单数值字段、HMAC 假名化 | scope/event 使用服务器常量，subject 不得传入密码/令牌；日志系统保护、保留期、权限由宿主决定；不自动记录异常完整信息 |
| XSS | HTML/引用属性编码、JSON 数据编码 | 不能用于 JS 标识符、事件属性、CSS、srcdoc 或不安全 URL；Twig 不使用 raw；富文本显式接受限HTML Purifier适配、资源预算和正文上下文；自定义适配/复杂策略须宿主复核，见html-cleaning.md |
| 文件上传 | 内容/类型/大小/图片解码预算、重新编码和私有排他保存 | 授权、CSRF、全局容量、保留及安全下载由宿主承担；未接真实扫描/CDR；见upload.md |
| SSRF | 精确目标、全部A/AAAA公开地址、逐跳DNS/URI及实际peer pin、TLS和累计预算 | 不接受任意URL代理；真实基础设施路由/自定义适配/企业DNS及业务路径授权仍须验证；见outbound.md |
| API伪造/篡改/重放 | 随机Bearer摘要及原子轮换撤销；固定RFC 9421配置档、绑定方法/完整URI/体摘要/Content-Type，共享Nonce | TLS、原始请求交付、密钥管理、权限/资源归属、入口预算及业务幂等由宿主承担；状态恢复/时钟异常不提供永久历史重放保证；见api.md |
| 加入宿主事务时意外提交／局部写入残留 | 内部实际事务检查、固定局部回滚边界、独立事务见证；失败语句释放游标，清理不确定拒绝复用 | 宿主负责外层提交／回滚及异常中止，不能以局部保存点代替完整业务一致性；已经错误提交的副作用不可撤销，完整Outbox仍未交付；见sql-transactions.md |
| 写接口重复执行／结果篡改 | 可选SQL幂等将业务与结果同事务提交，当前授权下重放，同键内容冲突和过期键拒绝；独立HMAC与实际正文摘要／长度核对 | 不覆盖外部副作用、完整有效旧备份、已泄露封存密钥或非法回调自行提交；宿主规划容量、可信时间、业务唯一账本及恢复对账；见idempotency.md，R4.3实施中 |

配置错误抛出异常，第三方验证码不可达抛出异常；宿主返回 503 并停止业务。拒绝后不能在 catch 中继续登录。攻击者能直接改写共享安全存储时，防护不再成立。

SoSecurity 不自动覆盖业务授权入口或定义宿主权限规则，也不替代参数化 SQL、HTTPS、基础设施防护或运行时更新。PHP 7.2 等停止维护的版本仅做代码兼容；组件不能补上运行时本身的全部漏洞。本次内部代码审查和测试不是独立安全审计。

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

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)、[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)：有界HTTP签名配置档与请求体摘要，不宣称通用协议/所有算法互操作。
