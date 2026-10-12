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

## 互动演示追加验收（2026-10-13）

基础里程碑后增加demo/public公开入口和源码目录保护。PHP7.2、PHP8.5隔离演示服务器的HTTP验收通过；最终演示测试84项断言，涵盖十类能力、JSON/表单、畸形操作字段、跨访客隔离、过期和重放。

实际 `http://72.rocky.wsl/SoSecurity/` 在Apache/PHP-FPM PHP7.2上HTTP验收通过。真实Chromium验证AJAX生成/正常验证/篡改拒绝、输入不执行脚本、移动宽度无页面横向溢出、无脚本异常；桌面和手机截图已检查。

`.git/HEAD`、composer.json、demo/app.php、src、tests、bin和tools等仓库路径拒绝HTTP访问；演示首页及静态资源正常。私有数据位于Web根之外；只有demo/public映射为大小写明确的入口。原有基础里程碑的“未执行浏览器/PHP-FPM”是此前状态，此次追加不代表真实旧站生产业务已验收。

演示Redis和Turnstile未配置，真实外部服务未执行；页面不宣称通过。上传、MySQL、SSRF等后续功能仍未实现。部署和复现见demo.md。

## 核心加固与配置候选追加验收（2026-10-13）

Policy/Change不可变、稳定异常reason、有界文件锁、分批清理、状态编码预算、Redis原子Lua CAS和网络等待预算已实现。工厂、只读诊断、Session原有Cookie策略保留和宿主重置版本比较已加入源码与演示。

- PHP7.2与PHP8.5功能回归通过；加固29项、配置/诊断33项、Session24项、宿主SQL重置16项；演示现为95项。
- Redis真实冲突、网络暂停、内存耗尽和诊断/配置变更测试已加入；保留原有24进程并发。Redis重启恢复边界尚待完成，不能据此宣称恢复后仍满足全部保护状态保证。
- 两个PHP版本在独立16KiB tmpfs上实际验证ENOSPC写入失败与原记录保留，各4项；测试结束卸载并移除临时挂载点，不填满共享磁盘。
- PHP8.5实际限制独立测试进程文件大小，验证OS部分写失败4项；PHP7.2缺POSIX扩展，此项未执行，不能当作通过。
- CLI只读诊断退出状态及无状态文件写入已验证；PHPStan level5/目标PHP7.2通过。
- 当前Web入口上的配置/诊断与故障页面HTTP测试通过，真实Chromium已验证工厂成功、配置拒绝、隔离锁超时、移动布局且无脚本异常。

完整目标仍进行中，逐项剩余工作见execution-status.md。
