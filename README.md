# SoSecurity

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

七种[最小配置预设](examples/configuration-presets.php)覆盖表单、文件/Redis/MySQL登录防护、API签名、无状态CSRF和可选富文本清理；按场景选一份，改站点标识及可信部署值。没有默认管理员、生产密码或签名密钥。

核心仅要求 PHP、JSON 和 hash，没有第三方运行时强制依赖。GD、Redis、PDO MySQL、cURL、intl、DOM/ctype及HTML Purifier仅用于对应能力，见[配置参考](docs/configuration.md)。

## 现有能力

| 能力 | 内容 | 指南 |
| --- | --- | --- |
| 验证码 | 算术/图片/Turnstile、场景绑定、过期、错误预算、单次消费 | [使用指南](docs/usage.md) |
| CSRF | 有状态令牌、多表单、可选单次消费；绑定登录的签名双重提交 | [CSRF配置](docs/configuration.md)、[无状态方案](docs/signed-csrf.md) |
| 限流与封禁 | 自定义维度、阶梯封禁、手动封禁、到期恢复、查询与解除 | [使用指南](docs/usage.md) |
| 密码与会话 | 原生哈希、旧哈希迁移、重置令牌、Session更新/期限及Cookie | [迁移指南](docs/migration.md) |
| HTTP与代理 | CSP/Report-Only、HSTS、Permissions-Policy、CORS、可信代理、跳转 | [HTTP策略](docs/http-policy.md) |
| 输出与输入 | 上下文编码、严格类型/Unicode/嵌套验证、可选受限HTML清理 | [验证](docs/validation.md)、[HTML清理](docs/html-cleaning.md) |
| 文件上传 | MIME/内容/大小限制、图片重新编码、私有随机保存、扫描适配 | [上传安全](docs/upload.md) |
| 外部请求 | 固定目标、地址/DNS/逐跳检查、实际IP绑定和资源预算 | [受限请求](docs/outbound.md) |
| API | Bearer摘要与轮换撤销、HMAC签名、时间戳和原子Nonce | [API指南](docs/api.md) |
| 审计与存储 | 脱敏事件回调、只读诊断、Session/文件/Redis/MySQL原子存储 | [配置](docs/configuration.md)、[MySQL](docs/mysql.md)、[Redis恢复](docs/redis-recovery.md) |

## 示例与演示

[72.rocky.wsl/SoSecurity](http://72.rocky.wsl/SoSecurity/) 提供实际组件的表单/AJAX操作、正常/拒绝/故障路径及访客隔离。未配置的外部服务会显示实际状态。部署边界见[演示说明](docs/demo.md)。

[examples](examples) 提供独立原生登录、密码重置、上传适配、API请求、签名表单、输入验证和富文本示例。示例供宿主选择接入，不会自动修改其他项目或接管认证、授权、路由、数据库与Session。

## 质量与维护

本机已执行 PHP7.2–8.5 九版本功能、独立消费者 Composer 安装、真实隔离 Redis/MySQL/HTTP及并发测试。详细证据见[验证记录](docs/verification.md)，开发命令见[贡献指南](CONTRIBUTING.md)。CI定义、作者自检和演示不等同于远端执行或独立安全审计。

项目整理依据见[产品需求](docs/requirements.md)，当前实施顺序见[总体规划](docs/roadmap.md)。本次工作限定在SoSecurity、独立示例和指定演示；已有项目接入及公开发布需明确指令。不再自行使用Windows环境。

库不能替代业务授权、参数化SQL、HTTPS或运行时更新。PHP7.2兼容不代表其上游恢复安全维护。参见[威胁模型](docs/threat-model.md)、[安全政策](SECURITY.md)及[平台限制](docs/platforms.md)。MIT License。
