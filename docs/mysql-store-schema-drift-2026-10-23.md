# MySqlStore 复用对象的表结构变化保护

## 已确认问题与修复

对象构造后，原有每次操作只复核外键与索引。自有 MySQL 中将表改为 MyISAM、将 payload 改为 TEXT、将 expires_at 改为有符号整数或增加字段后，既有对象仍调用业务回调并写入，prune 仍删除记录。修复前四种变化 × 两种操作共 8 个场景均未拒绝；规范表的两个对照场景通过。见 [before85.log](mysql-store-schema-drift-evidence-2026-10-23/before85.log)。

现在 `owned()` 在自己的事务内先读取表以获得元数据锁，再调用既有完整 `verifySchema()`，复核引擎、字段、外键和索引后才能执行操作。没有跨事务缓存；构造器原有检查及异常行为保留。发生结构不兼容时不调用业务回调，数据保持不变。没有修改表结构或发行 DDL，没有迁移用户数据。

修改仅针对 MySQL 存储实现；SQLite 未改。公开方法签名和 277 类型清单保持。兼容性收紧为：运行中修改成不支持的表结构，现在会被拒绝；宿主应恢复规范表并重建连接／对象，而非依赖旧对象绕过结构检查。

## 证据和范围

证据目录：[mysql-store-schema-drift-evidence-2026-10-23](mysql-store-schema-drift-evidence-2026-10-23/)。`runtime.patch` 是相对此批开始时源码的差异；`source-hashes.json` 固定最终源码与测试摘要。新增 `tests/mysql-store-schema-drift.php` 以及私有 MySQL 专项参数 `--mysql-store-schema-drift`。

第一版修复把表锁移入构造器共用检查，导致未安装表的异常类型发生变化，原有 `tests/mysql.php` 正确发现失败（`regression.log`）。最终实现仅在操作入口新增锁与完整复核，保留原构造器行为。第一版通过记录不冒充最终结果。测试驱动曾有参数解析拼接错误，保留 `runner-setup-failure.log`，它没有执行数据库测试。

所有数据库、表、进程均属于临时自有测试环境。没有生产访问、外部投递、提交、推送或部署；没有运行暂缓链路。结果只用于定向回归，不代表完整计划或稳定版验收。

另完成[默认原生签发失败定位](native-default-diagnosis-2026-10-23.md)：第二次 actor 校验时触发 API 总预算，仍未解决，pending 未续办。该流程使用的存储路径与本批独立 MySqlStore 修复不同，不能把本批绿色结果当作默认签发问题已关闭。

## 最终源码验证结果

全部已执行并通过：

- PHP 7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5，真实私有 MySQL 8.0.46：结构变化与规范表对照共 90/90。见 `final-matrix.log`。
- PHP 7.2／8.5：完整键索引专项 18/18、错误隐私专项 8/8、有界元数据专项 6/6（含超大默认值，读取进程 8MiB）。
- 两端原有 MySQL 存储回归各 41 项断言；事务归属 12 个场景各 8 项断言，包含 SQL BEGIN／autocommit=0、跨连接可见性和宿主回滚。见 `final-regression.log`。
- 离线 ZIP、全新非软链接消费者安装、vendor 来源核对及源码摘要一致：6/6 步，两端消费者内 MySQL 专项共 20/20。见 `archive.json`。
- 最终 PHPStan、277 类型 API 检查通过；Python 驱动语法及本批差异空白检查通过。

`summary.json` 汇总最终计数；原失败没有删除或覆盖。本批不执行 SQLite（运行时仅涉及 MySQL），不重复执行与本次修改无关的全项目套件。默认原生签发预算问题、既有 PHP 7.2 未解释失败及其余非暂缓候选核对仍开放，goal 保持 active。
