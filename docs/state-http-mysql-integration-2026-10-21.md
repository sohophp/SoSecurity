# G5 MySQL HTTP 与持续时钟下的请求中到期

日期：2026-10-21（Asia/Shanghai）。继续原 P1／G5，不新增预算。沿用同一受管认证示例，补真实 MySQL HTTP／TLS，并把测试宿主的按请求快照时钟替换为持续读取的 `SystemClock`。生产库 src 和示例不变；这不是全部业务宿主、事务组合或完整安全恢复验收。

## 实际后端与权限边界

`tests/mysql_check.py --state-http/--state-http-tls <runtime>` 分别创建独立 MySQL 实例，禁 TCP、仅私有 Unix socket；HTTP 重建在连接前再次核对 `/tmp/sosecurity-mysql-*`、socket 名称及 `account-test-owner`。专用测试用户的 TRIGGER 可见性仅用于这个自建实例，既有业务 MySQL 不参与。

认证 SQL 的备份只包括固定七张已声明测试表，以类型标签保留整数／null，以 Base64 保存原始字节；恢复只清空并逐行写回这些测试表，不改 DDL、见证、围栏或当前可信摘要。MySQL 使用实际准备语句及 LOB 绑定，SQLite 保留原生 backup。用于拒绝路径比较的快照仍读取真实表／文件，没有替换 Repository 或身份提供方。

私有测试控制器增加快照／恢复能力，设置和控制脚本强制仅 CLI 执行；受控测试路由实测直接 Web 访问为 404、空响应，且无新目录或认证变化。生产示例没有这些测试路由或维护接口。

## 持续时钟与到期证明

私有引导重建后，原生认证 FileStore、原始 TOTP、SDK 和缓存的会话／因子图使用同一个真实 `SystemClock`。不改系统时钟、不冻结请求时间，也不钳制倒退。

创建八秒有效的实际签名凭证，在一次请求的范围回调中等待 9.1 秒。测试独立记录回调开始、结束和签名 expires_at，必须满足 `start < expires <= end`，且类型确为 `SoSecurity\Support\SystemClock`；不能用请求开始前已过期的令牌凑结果。该请求必须返回 401，完整认证 SQL、原生文件和独立见证不变，并保持 current。SDK 的原生截止时间保持，测试观察文件仅位于独立临时域。

## 固定验收

**已执行并通过：固定 12 条命令全部退出 0，准确输入保持一致；八个临时宿主和四个临时 MySQL 目录／进程已清理。** 每端 SQLite HTTP／TLS 为 329／337 项、MySQL 为 330／338 项；六次 Chromium 和八次真实持续时钟到期观察通过。两端 261 类公开契约、Bash 语法和全库 src 静态分析通过，保留既有可选 turbo GLIBC 启动警告。库 src、产品示例和公开契约与前组逐字节相同，本组只补测试接线及验证。

固定 12 条命令：两端 SQLite HTTP＋Chromium、SQLite TLS＋Chromium和公开接口；四次私有 MySQL 分别执行两端 HTTP、TLS＋Chromium；最后检查主门禁 Bash 语法及库 src 静态分析。准确输入及结果见[执行记录](state-http-mysql-evidence-2026-10-21/execution.json)、[交付核对](state-http-mysql-evidence-2026-10-21/delivery-check.json)。本组完成后停止扩测，不运行历史快照或提前开启九版整轮。

两种后端都实际恢复旧 SQL、认证 JSON 和 PHP 会话，保留新见证；旧 Bearer 和旧 Cookie／CSRF 管理请求均应拒绝，权威不采用回放数据。浏览器沿用已核对的真实跨 Origin 带 Cookie 请求、服务端 403 观察及来源无变化检查。TLS 为受控回环桥接，Python 校验私有 CA，Chromium 仅对该测试证书设置 ignoreHTTPSErrors；不冒充生产证书／源站隔离验证。

MySQL 控制器每条 600 秒，其他命令 240 秒，单次 HTTP 原有 30 秒及 SDK 期限不变。保护图仍使用 16 MiB；PHP7.2 为私有 sodium／posix／原生单调时钟环境，不称系统原版完整门禁通过。浏览器模块是既有测试依赖，没有新增生产 Node／Composer 依赖。

## 未关闭的关口

本组覆盖本地真实 SQLite／MySQL 认证宿主，未覆盖所有实际站点、业务 PDO 事务组合、自定义／带审计委托、其他授权／一次性证明及全部写入者。旧进程交接、最终账号启用和新密码／MFA 登录、见证／审计自身中断与维护、通知／队列、外部 SMTP／OIDC／实体设备／WAF、远端 CI、独立复核及最终同源码九版整轮仍开放。完整 G1／G4／G5／F01／R1—R6 未完成，31 项／80 小时上限保持；未提交、推送或发布。
