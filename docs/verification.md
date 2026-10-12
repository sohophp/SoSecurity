# 0.1 基础候选验证记录

日期：2026-10-13。交付性质：**本地 0.1.0-dev 候选里程碑**，不是GitHub/Packagist正式发布，也不是独立安全审计。最初本地目录及公开GitHub仓库为空，本次没有覆盖宿主网站代码或连接生产数据。

## 已执行并通过

| PHP 运行时 | 功能/边界断言 | Session 集成 | 文件24进程并发 | Redis真实驱动及24进程并发 | 真实HTTP登录 |
| --- | --- | --- | --- | --- | --- |
| 7.2.34 | 13组，184断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 7.4.33 | 13组，184断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 8.1.34 | 13组，186断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 8.2.32 | 13组，186断言 | 19断言 | 通过 | **未执行：本机缺ext-redis** | 20断言 |
| 8.4.23 | 13组，186断言 | 19断言 | 通过 | **未执行：本机缺ext-redis** | 20断言 |
| 8.5.9 | 13组，186断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |

每个可用运行时均检查38个PHP文件的语法。Argon2id是否可用影响功能断言数量；不可用时验证明确拒绝该配置，不降级。Redis实例只监听新建私有UNIX socket，TCP关闭，无生产实例连接。文件并发也使用新建0700临时目录。

并发情形每个启动24个独立PHP进程：5次额度只成功5次，单次CSRF只成功1次，验证码只成功1次。不是仅顺序循环模拟并发。

HTTP测试通过隔离PHP内置服务器与真实CookieJar执行：跨Session令牌拒绝、数组字段拒绝、多标签页、正确/错误密码、验证码重放拒绝、登录Session ID变化、请求预算429/Retry-After、非允许方法405、存储权限异常503。没有打开真实浏览器，也没有证明生产PHP-FPM/Nginx/代理的行为。

其他验证：

- PHP7.2及PHP8.5独立消费者通过Composer路径仓库真实安装、PSR-4自动加载和公开API调用。
- 核心composer.json与开发工具composer.json通过严格格式检查。核心没有第三方运行时依赖，依赖审计没有可扫描的运行时包；独立开发工具PHPStan 2.3.1的Composer漏洞公告检查未发现公告。
- PHPStan level5、目标PHP7.2，核心src无错误；无忽略基线。工具实际在PHP8.1运行。早期PHP8.5工具尝试加载Turbo因本机glibc太旧发出警告，随后采用PHP8.1运行并通过；这不是核心运行时问题。
- `composer archive`内容检查通过：排除vendor、tools、tests、CI、缓存、私有配置文件名及lock；保留Composer元数据、源码、许可证和使用文档。
- GitHub工作流YAML语法解析通过；Action使用检查时解析到的固定提交SHA。
- 内部审查检查原子生命周期、代理链、密码截断/降级、会话超时和故障策略；不是独立审计结论。

## 已执行但初次失败，现已修复并复测

- 老版phpredis无前缀时返回null，新版/配置可能返回空字符串；适配器明确接受两种无前缀返回，不接受实际前缀。
- 关闭Redis客户端不总能模拟服务故障，旧扩展会重连；测试改成隔离socket不可达并恢复，验证异常拒绝业务。
- Redis错误数据类型GET失败时不能当缺失记录；检查协议错误并抛StorageException，已有回归测试。
- 发布压缩包最初包含本地vendor；显式Composer/Git导出排除规则修复，压缩包内容检查已通过。

## 未执行与发布前验收

- PHP7.3、8.0、8.3本地没有运行时，**未执行**。完整7.2–8.5 GitHub CI已定义，**未在GitHub实际运行**；CI运行前不宣称完整版本矩阵验证通过。
- PHP8.2/8.4 Redis驱动本地未执行，CI要求扩展齐全且缺失则失败。
- 真实Cloudflare Turnstile网络/widget验证未执行；本次只验证适配器响应绑定和异常路径，不将模拟传输结果当成第三方服务验收。
- 真实浏览器、PHP-FPM/Apache/Nginx、HTTPS及可信代理链、旧站认证业务验收未执行。
- 独立安全审计、ASVS逐项验收、负载/持久性故障测试未执行。24进程正确性测试不替代生产容量评估。
- GitHub推送、标签、Packagist注册及正式Composer公开安装未执行。当前仅本地提交与路径仓库安装。
- Docker安装可见，但守护进程不可连接；本次使用现有原生CLI运行时，没有通过容器补齐缺失版本。

下一里程碑依照roadmap.md推进PDO MySQL存储、输入验证和上传能力；先补齐上述发布前验收，再将候选声明为稳定可公开发布版本。

## 复现

```sh
composer install
bin/check.sh php72
bin/check.sh php74
bin/check.sh php81
bin/check.sh php82
bin/check.sh php84
bin/check.sh php85
python3 tests/install.py php72 /path/to/composer
python3 tests/install.py php85 /path/to/composer
python3 tests/archive.py php72 /path/to/composer
php81 /path/to/composer install --working-dir=tools
php81 tools/vendor/bin/phpstan analyse -c phpstan.neon --no-progress
php81 /path/to/composer audit --working-dir=tools --locked
```
