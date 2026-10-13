# 贡献与验证

核心代码保持PHP7.2语法和PHP7.2–8.5运行时兼容，不添加框架强依赖，不用测试通过替代安全审查。安全漏洞走SECURITY.md中的私密路径。

常规修改：先阅读docs/architecture.md和threat-model.md，保持修改范围集中；同时更新相关使用文档及回归测试。AtomicStore回调必须无外部副作用；测试存储失败、边界及并发，不把生产降级成空内存状态。

```sh
composer install
composer validate --strict
bin/check.sh php
python3 tests/install.py php /path/to/composer
# 开发工具与核心依赖隔离
php81 /path/to/composer install --working-dir=tools
php72 /path/to/composer install --working-dir=integrations/htmlpurifier
php81 tools/vendor/bin/phpstan analyse -c phpstan.neon --no-progress
php81 /path/to/composer audit --working-dir=tools --locked
```

测试使用无第三方依赖的断言运行框架（tests/bootstrap.php），检查失败非零退出；警告和弃用也转换为测试错误。tests/run.php是功能/边界测试；session.php与redis.php是真实驱动集成；concurrency.php每种情形启动24个独立PHP进程；test_http.py以隔离PHP服务器检查HTTP/Cookie；install.py验证独立消费者Composer安装。demo.py检查互动演示的表单/JSON、失败和隔离路径。新增功能必须同步补齐演示、示例、限制和测试，见docs/next-steps.md。不能把NOT RUN记成PASS。

Redis测试只对新建UNIX socket实例操作；不连接宿主实例，不FLUSHDB。CI检查缺少必需扩展时应失败，不能以跳过掩盖缺失。本机PHP8.2/8.4原CLI没有Redis扩展；临时测试ini和独立模块补齐后已实际通过。直接执行原CLI仍可能缺扩展，必需标志不能移除，完整运行范围见verification.md。

PHPStan使用PHP7.2目标、level5，不维护忽略基线；开发工具在PHP8.1执行避免本机较旧glibc不支持新Turbo加速扩展。提高分析严格度应同时补齐真正有意义的类型约束，而不是盲目添加忽略。

发布前按docs/release-readiness.md核对当前发行范围和对应verification.md证据，检查composer archive内容并审核公开API和默认策略。提交清楚描述行为和证据；git push、标签、Packagist登记和宿主部署是另外的操作，不由本地测试自动触发。

加固验证包括hardening.php、configuration.php、reset-flow.php、storage-failure.php及bin/full-disk-check.sh。磁盘耗尽测试只能由脚本创建独立小型tmpfs，禁止填满宿主共享磁盘。完整目标状态见docs/execution-status.md。

公开接口提案及类型/默认值比较见docs/public-api.md；`php72 bin/api-contract.php`不构造组件。未经评审不要自动改签名基线。1.0验收工作单见docs/release-readiness.md；完整私有MySQL顺序矩阵可运行 `python3 tests/mysql_check.py --matrix php72 php73 php74 php80 php81 php82 php83 php84 php85`，相关扩展必需条件按实际环境记录。


Windows历史检查入口保留作资料，本次不运行或配置Windows。当前验证使用已有PHP CLI；portable-core.php使用MemoryStore仅验证组件流程，不能代替共享后端或并发验收。

重整后文档导航见docs/index.md；需求与规划各只有一个权威入口。配置预设工作流由tests/configuration-presets.php检查，并加入bin/check.sh，不要求新增框架或外部服务。
