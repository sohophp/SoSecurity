# SoSecurity

[English introduction](README.en.md) · [功能演示](http://72.rocky.wsl/SoSecurity/) · [简单配置](docs/configuration.md) · [使用指南](docs/usage.md) · [旧站迁移](docs/migration.md) · [路线图](docs/roadmap.md) · [验证记录](docs/verification.md)

框架无关、按需使用的 PHP Web 安全组件。Composer 包名 `sohophp/sosecurity`，命名空间 `SoSecurity\`，核心代码目标 PHP **7.2–8.5**。

当前为 **未发布开发候选版本（已推进到0.5 HTTP/API阶段）**：验证码（算术、PNG 图片、Turnstile）、有状态 CSRF、原子请求预算与封禁、密码哈希/迁移/重置令牌、会话安全辅助、可信代理/CIDR、输出编码、Cookie/基础响应头和脱敏审计回调。Session、本地文件、Redis及PDO MySQL存储可独立选择；新增严格输入验证、可选配置工厂和只读诊断。新增私有文件上传校验/保存；新增安全跳转/CORS/权限头及有界受限外部请求；新增摘要存储的API Key与RFC 9421有界HMAC签名/共享原子Nonce；新增绑定登录的无状态签名CSRF与精确路由策略；完整发布验收继续进行。

## 安装

GitHub/Packagist 尚未发布版本，下面的公开安装命令是发布后的使用方式：

```sh
composer require sohophp/sosecurity
```

本地试用可在宿主的 composer.json 配置路径仓库（不会强制启动任何模块）：

```json
{
  "repositories": [{"type": "path", "url": "/absolute/path/to/soSecurity", "options": {"symlink": false}}],
  "require": {"sohophp/sosecurity": "@dev"}
}
```

然后执行 `composer install`。核心没有第三方运行时依赖；图片需要 ext-gd，Redis 存储需要 ext-redis；Turnstile 的默认 HTTP 传输需要 ext-curl；MySQL需要ext-pdo_mysql；显式NFC规范化需要ext-intl。

## 表单 CSRF

```php
require 'vendor/autoload.php';
// 复用宿主已启动且仍持锁的 PHP Session。
if (!isset($_SESSION['csrf_binding'])) {
    $_SESSION['csrf_binding'] = bin2hex(random_bytes(32));
}
$csrf = new SoSecurity\Csrf\CsrfTokens(new SoSecurity\Storage\SessionStore('my-site'));
$token = $csrf->issue('contact', $_SESSION['csrf_binding']);
// 用 Escaper::html($token) 放入 HTML 隐藏字段；AJAX 可放到 X-CSRF-Token 请求头。
// 提交时：
if (!$csrf->verify('contact', $_SESSION['csrf_binding'], $_POST['_csrf'] ?? null)) {
    http_response_code(403);
    return;
}
// 通过后仍需业务验证和授权。
```

登录示例见 [examples/legacy-login.php](examples/legacy-login.php)。该示例需要显式配置账号哈希和私有存储目录，不会创建默认管理员或替换宿主认证。

## 功能演示

本地入口：[http://72.rocky.wsl/SoSecurity/](http://72.rocky.wsl/SoSecurity/)。现有能力及配置/诊断提供可操作页面、传统表单/AJAX、正常与拒绝结果及核心调用片段。输入验证可直接操作，MySQL使用私有演示数据库展示真实计数与隔离；外部Turnstile和Redis未配置时标记未执行。

部署、隔离和演示测试见 [demo.md](docs/demo.md)，细化后续计划见 [next-steps.md](docs/next-steps.md)。只公开demo/public，源码根目录通过.htaccess拒绝HTTP访问；演示不随Composer运行时压缩包安装。

## 开发验证

```sh
composer install
composer validate --strict
bin/check.sh php
python3 tests/install.py php /path/to/composer
# 独立开发工具在 PHP 8.1+ 环境安装，不影响 PHP 7.2 核心包。
php81 /path/to/composer install --working-dir=tools
php81 tools/vendor/bin/phpstan analyse -c phpstan.neon --no-progress
php81 /path/to/composer audit --working-dir=tools --locked
```

`bin/check.sh` 运行单元/Session/真实 HTTP/文件并发测试；有 redis-server、redis-cli 和 ext-redis 时自动创建独立 UNIX socket Redis 实例测试并关闭，不连接已有站点实例。另有mysqld/mysql/PDO MySQL时创建无TCP独立MySQL并验证事务与并发，用完关闭；不会连接宿主已有MySQL。PHP 7.3、8.0、8.3 本次本地未执行；全版本 CI 已定义但未在 GitHub 运行。

库不能替代业务授权、参数化 SQL、HTTPS、服务器更新或基础设施防护。旧版 PHP 代码兼容不代表运行时重新获得安全维护。内部测试不是独立安全审计。参见 [威胁模型](docs/threat-model.md) 和 [安全报告政策](SECURITY.md)。

MIT License。

完整进一步计划仍在执行中，当前进度与未完成验收见 [execution-status.md](docs/execution-status.md)。

新增指南：[无状态CSRF](docs/signed-csrf.md) · [API凭据与签名](docs/api.md) · [HTTP策略](docs/http-policy.md) · [受限请求](docs/outbound.md) · [上传安全](docs/upload.md) · [MySQL存储](docs/mysql.md) · [输入验证](docs/validation.md) · [Redis初始化与恢复](docs/redis-recovery.md)。
