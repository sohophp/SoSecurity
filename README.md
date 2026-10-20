# SoSecurity

可选[原生隔离接入](docs/upload-quarantine-native.md)现提供受保护网页和CLI扫描工作进程，使用宿主SQLite示例索引；SDK不依赖该表结构，也不创建默认账号。

上传隔离核心现支持私有待扫、后台有限重试、管理员重扫／拒绝与当前版本内容读取；原同步接口保持。见[持久隔离指南](docs/upload-quarantine.md)，完整接入验收继续。

上传模块现提供本地ClamAV扫描适配器：完整内容、共享总期限和严格响应校验，通过后才私有保存。见[扫描指南](docs/upload-scanning.md)。

可选[ZIP归档只读检查](docs/archive-inspection.md)现可对宿主私有暂存文件限制路径、链接、条目数、解压字节和嵌套归档；需要`ext-zip`，不会自动提取文件。

有界SQL、文件与组合只读快照已并入SDK，提供完整字节摘要和同次数据采集；它们不是权限或独立防回滚证明，见[指南](docs/state-snapshots.md)。

[English](README.en.md) · [功能演示](http://72.rocky.wsl/SoSecurity/) · [文档导航](docs/index.md) · [简单配置](docs/configuration.md) · [旧代码迁移](docs/migration.md)

SoSecurity 是 **框架无关、按需使用的 PHP Web 安全加固组件库**。通过 Composer 安装，可在原生 PHP、自研框架或已有框架项目中逐项替换验证码、CSRF、登录防护等旧代码。包名 `sohophp/sosecurity`，命名空间 `SoSecurity\`，支持 PHP **7.2–8.5**。

当前是**未发布开发候选**，已有功能和验证范围见[功能清单](docs/features.md)与[当前状态](docs/execution-status.md)。自动封禁属于统一的请求限流体系，不接系统 Fail2ban，也不单独创建 AutoBan。

## 安装与最小配置

尚未发布稳定版本，当前在独立测试项目中使用本地路径仓库：

```json
{
  "repositories": [{"type": "path", "url": "/absolute/path/to/soSecurity", "options": {"symlink": false}}],
  "require": {"sohophp/sosecurity": "@dev"}
}
```

执行 `composer install`。公开发布后的安装命令为 `composer require sohophp/sosecurity`。

```php
require 'vendor/autoload.php';
$security = SoSecurity\Security::fromArray(['site' => 'my-site']);
// 只使用需要的组件；宿主先按自己的流程启动并持有 Session 锁。
$csrf = $security->csrf();
$captcha = $security->captcha();
$hasher = $security->passwordHasher();
```

CSRF、验证码默认复用宿主 Session；跨会话限流、密码重置和 API 重放状态需要显式配置共享存储。工厂校验配置，不自动启动 Session、发响应头、连接服务或创建目录。也可以直接实例化各组件，无需工厂或框架。

八种[最小配置预设](examples/configuration-presets.php)覆盖表单、文件/Redis/MySQL登录防护、API签名、无状态CSRF、可选富文本清理和上传隔离；按场景选一份，改站点标识及可信部署值。上传隔离还需宿主提供私有目录、共享状态和扫描器。没有默认管理员、生产密码或签名密钥。

核心仅要求 PHP、JSON 和 hash，没有第三方运行时强制依赖。GD、Redis、PDO MySQL、cURL、intl、DOM/ctype及HTML Purifier仅用于对应能力，见[配置参考](docs/configuration.md)。

## 现有能力

| 能力 | 内容 | 指南 |
| --- | --- | --- |
| 验证码 | 多种算术/图片、滑块/点选、Turnstile/hCaptcha/reCAPTCHA、单次消费 | [验证码指南](docs/captcha.md) |
| CSRF | 有状态令牌、多表单、可选单次消费；绑定登录的签名双重提交 | [CSRF配置](docs/configuration.md)、[无状态方案](docs/signed-csrf.md) |
| 限流与封禁 | 自定义维度、阶梯封禁、手动封禁、到期恢复、查询与解除 | [使用指南](docs/usage.md) |
| 密码与会话 | 原生哈希、旧哈希迁移、重置令牌、Session更新/期限及Cookie | [迁移指南](docs/migration.md) |
| 密码策略精修 | 按算法检查长度、弱密码表、可选泄露范围检查、计算预算和CLI成本校准 | [密码指南](docs/passwords.md) |
| TOTP 与恢复码 | 绑定确认、防重放、共享错误预算、恢复码轮换／撤销及加密因子保存；按需启用 sodium | [MFA 与加密](docs/mfa.md) |
| 认证与会话撤销 | 密码／待 MFA／完整身份、当前版本检查、单个／全部撤销、保持绝对期限的重新认证 | [认证指南](docs/authentication.md) |
| 业务授权 | 默认拒绝、角色／归属／属性、字段与批量检查、租户隔离及版本条件更新示例 | [授权指南](docs/authorization.md) |
| 加权请求预算 | 整数成本、令牌桶／固定／精确秒级滑动窗口、同主体原子组及IP／账号／租户顺序组合 | [预算指南](docs/request-budgets.md)、[示例](examples/request-budgets.php) |
| 并发租约 | 持有者凭据、固定总生命周期、续期／释放／过期恢复、永久隔离序号与SQL条件写入 | [租约指南](docs/leases.md)、[SQL示例](examples/leased-work.php) |
| 记住登录 | 主动选择、固定期限、原子轮换／重放撤销、忘记设备、恢复后敏感操作重新认证 | [持久登录指南](docs/remembered-login.md) |
| 高风险操作 | 准备后重新认证、明确确认、对象／版本／参数绑定、单次消费与SQL执行记录 | [操作授权](docs/operations.md)、[原生页面](examples/operation-authorization.php) |
| 签名链接 | 固定来源／全查询／用途／资源版本绑定、到期、共享撤销和单次消费 | [签名链接](docs/signed-links.md)、[原生页面](examples/signed-links.php) |
| 授权下载 | 当前会话／签名授权、摘要绑定的私有匿名快照、单Range／附件头、全源成本及并发组合 | [下载指南](docs/downloads.md)、[原生页面](examples/authorized-download.php) |
| HTTP与代理 | CSP/Report-Only、HSTS、Permissions-Policy、CORS、可信代理、跳转 | [HTTP策略](docs/http-policy.md) |
| 输出与输入 | 上下文编码、严格类型/Unicode/嵌套验证、可选受限HTML清理 | [验证](docs/validation.md)、[HTML清理](docs/html-cleaning.md) |
| 文件上传 | MIME/内容/大小限制、图片重新编码、私有随机保存、扫描适配 | [上传安全](docs/upload.md) |
| 外部请求 | 固定目标、地址/DNS/逐跳检查、实际IP绑定和资源预算 | [受限请求](docs/outbound.md) |
| API | Bearer摘要与轮换撤销、HMAC签名、时间戳和原子Nonce | [API指南](docs/api.md) |
| 账号API凭据 | 真实会话管理、显式服务账号委派、范围／期限、原子轮换撤销与独立Bearer路由 | [生命周期](docs/api-credentials.md)、[原生页面](examples/api-credentials.php) |
| Webhook | 固定协议验签、业务关联与SQL持久接收；独立CLI事务处理、稳定业务幂等及强认证失败重试 | [接收](docs/webhooks.md)、[处理与恢复](docs/webhook-processing.md)、[原生页面](examples/webhooks.php) |
| 通用写接口幂等 | 同PDO提交业务和结果、当前权限重放、冲突拒绝、到期墓碑／封存维护；原生Bearer订单和私有管理CLI | [核心](docs/idempotency.md)、[原生接入](docs/idempotency-native.md)、[页面](examples/idempotency.php)；完整R4.3验收继续 |
| 事务发件箱候选 | 同事务入队、稳定投递编号、领取确认、聚合顺序、有限重试／维护；原生CLI、独立接收去重／检查点恢复及超期处置核心 | [核心](docs/outbox.md)、[原生接入](docs/outbox-native.md)、[受控恢复](docs/outbox-recovery.md)、[超期对账](docs/outbox-reconciliation.md)；签名终态、持久取消、审计归档及独立权限源已有本地专项，完整阶段验收继续 |
| 审计与存储 | 脱敏事件回调、共享有界预算、固定类别指标与可轮询告警判定、只读诊断、Session/文件/Redis/MySQL原子存储 | [审计接入](docs/audit-budget.md)、[配置](docs/configuration.md)、[MySQL](docs/mysql.md)、[Redis恢复](docs/redis-recovery.md) |

私有 SQL 安全表现拒绝入站／出站外键，覆盖发件箱、幂等、Webhook 接收／处理与 MySqlStore，避免清理级联到业务；关闭执行开关也不能绕过。既有非规范关系须明确迁移，库不自动改表或切换外键设置。结构可见性和迁移互斥见[SQL 依赖契约](docs/sql-transactions.md#私有安全表的依赖边界)。

## 示例与演示

[72.rocky.wsl/SoSecurity](http://72.rocky.wsl/SoSecurity/) 提供实际组件的表单/AJAX操作、正常/拒绝/故障路径及访客隔离。未配置的外部服务会显示实际状态。部署边界见[演示说明](docs/demo.md)。

[examples](examples) 提供独立原生登录、密码重置、上传适配、API请求、签名表单、输入验证和富文本示例。示例供宿主选择接入，不会自动修改其他项目或接管认证、授权、路由、数据库与Session。

## 质量与维护

AI 检查 PHP 网站时可使用 [PHP 网站安全自查技能](skills/php-website-security-audit/SKILL.md)，调用名称为 `$php-website-security-audit`。技能包含可独立使用的通用清单，不强制接入本组件库。将完整技能目录安装到 AI 工具的技能目录后使用；是否需要新会话或重新加载取决于工具。

通用清单仍以 [PHP 网站安全自查规范](docs/php-website-security-checklist.md)为维护源，修改后运行 `python3 scripts/sync-security-audit-skill.py` 更新随包引用，使用 `--check` 只检查一致性。独立副本的修改不表示维护源或其他安装已同步。

本机已执行 PHP7.2–8.5 九版本功能、独立消费者 Composer 安装、真实隔离 Redis/MySQL/HTTP及并发测试。详细证据见[验证记录](docs/verification.md)，开发命令见[贡献指南](CONTRIBUTING.md)。CI定义、作者自检和演示不等同于远端执行或独立安全审计。

项目整理依据见[产品需求](docs/requirements.md)，当前实施顺序见[总体规划](docs/roadmap.md)。本次工作限定在SoSecurity、独立示例和指定演示；已有项目接入及公开发布需明确指令。不再自行使用Windows环境。

库不能替代业务授权、参数化SQL、HTTPS或运行时更新。PHP7.2兼容不代表其上游恢复安全维护。参见[威胁模型](docs/threat-model.md)、[安全政策](SECURITY.md)及[平台限制](docs/platforms.md)。MIT License。
