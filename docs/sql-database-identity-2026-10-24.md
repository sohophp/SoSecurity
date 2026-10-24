> 后续[纯构造成本移除](ledger-context-build-2026-10-24.md)只调整原生路径的备用SQL构造位置；下文证据仍属于本批原摘要。后续九版默认结果及失败单独记录，未关闭稳定版预算缺口。

# 数据库标识字节隔离与固定账本上下文语句复用

2026-10-24。本批实际修复两个内部SQL类：`SqlSchema`、`SqlStateAccess`。保留既有未提交改动；未提交、推送、部署或访问生产数据库。goal继续为active，本文仅记录本批定向验证，不是全项目或稳定版验收。

## 已确认问题与修复

在私有MySQL实例将结果字符集设为latin1，两个Unicode数据库名会被普通`SELECT DATABASE()`转换成相同的`sosecurity_??`。修前可复现：切换数据库后复用另一库的合法账本根读取语句、结构证明或通用字段元数据，使读取错误库的检查点或漏拒绝错误字段类型。本批固定上下文池的中间候选还会复用原库的权限观察，第二库已撤销TRIGGER仍未拒绝。这些都是隔离测试结果，不代表已确认生产环境受到攻击。

最终实现对数据库标识使用`CAST(DATABASE() AS BINARY)`，同时用于新鲜数据库探测及原生／通用账本上下文输出。以原始字节隔离预备语句和事务结构上下文；保留256字节上限，不修改宿主字符集。两库的普通查询输出在测试结束时仍然相同，确认修复不是通过更改连接字符集取得通过。四个测试分别验证检查点隔离、结构拒绝、权限拒绝及通用元数据拒绝。见[修前复现](sql-database-bytes-evidence-2026-10-24/probe.json)、[通用元数据复现](sql-database-bytes-evidence-2026-10-24/probe-metadata.json)、[最终源码增量](sql-database-bytes-evidence-2026-10-24/source-change.diff)。

固定账本上下文查询加入已有最多8条的已关闭预备语句池。资格要求严格原生PDO、原生Statement、已注册的受保护账本访问路径，并逐字匹配内部固定SQL和四个固定参数。内部getter只保存固定代码与参数，不保存数据库、结果或授权决定。数值标志显式投影成文本，使固定查询不依赖旧PDO无法读取的STRINGIFY_FETCHES属性；通用元数据的原有获取能力检查保留。

每次仍单独新读数据库名，再执行上下文SQL，检查当前权限、触发器、物理表解析、耐久性及事务归属；不缓存授权结果。关闭失败、执行失败、连接属性漂移、池容量及清理失败传播保持原保护。数据库探测不能进入预备语句池：原型在切库时证明预备语句中的DATABASE()会保留准备时的数据库。MySQL也说明自动重新准备保留原始默认数据库，见[官方说明](https://dev.mysql.com/doc/refman/8.0/en/statement-caching.html)。

## 最终源码与本地验证

[最终源码摘要](sql-database-bytes-evidence-2026-10-24/final-inputs.json)覆盖367份SDK／SQL文件；相对于本批开始仅上述两类变化，其余365份保持。公开清单实际278个类／接口，未修改公开签名、DDL、存储格式及默认预算。ASCII数据库行为保持；内部数据库身份改用原始字节，避免结果字符集有损转换造成混同。`SqlSchema`及`SqlStateAccess`均属内部清单。

| 已执行并通过 | 范围与结果 |
| --- | --- |
| MySQL定向矩阵 | PHP7.2、7.3、7.4、8.0—8.5共36/36程序；数据库字节隔离4场景及上下文池16场景，每版均通过，合计180个新增场景；另覆盖原账本语句18场景和元数据语句82断言 |
| SQLite回归 | 九版共27/27程序 |
| API与静态分析 | 九版公开API检查均为278；静态分析通过，共10/10程序 |
| 归档全新消费者 | 实际ZIP、离线安装且禁止符号链接，367份文件摘要和反射来源一致；PHP7.2／8.5的8个MySQL及6个SQLite程序全部通过，安装流程7/7步骤 |
| 控制器接线 | 新增独立上下文池与数据库字节测试入口；PHP8.5数据库字节入口4场景13断言通过 |

证据：[矩阵](sql-database-bytes-evidence-2026-10-24/matrix.json)、[本地检查](sql-database-bytes-evidence-2026-10-24/local-checks.json)、[计数](sql-database-bytes-evidence-2026-10-24/counts.json)、[消费者](sql-database-bytes-evidence-2026-10-24/consumer/consumer.json)、[独立入口](sql-database-bytes-evidence-2026-10-24/dispatch-85.log)。所有MySQL均由测试框架自建无TCP实例；只清理自建资源。

上下文池测试覆盖：注册与未注册路径、自定义Clock／PDO／Statement／不透明依赖的降级、切库、两张临时表遮蔽、耐久值0／2拒绝与1恢复、直接TRIGGER权限和逐表SELECT撤销、跨事务新增触发器、STRINGIFY_FETCHES变化。复用后的第二事务重新执行上下文SQL，并由第二连接分别ALTER两张表超时，验证元数据锁重新取得；上下文prepare计数仍从两次降为一次。[测试源码](../tests/ledger-context-pool.php)、[数据库字节测试](../tests/sql-database-bytes.php)不进入发行包。

## 中间失败与证据边界

原型首次缓存DATABASE()读取旧库名，两端失败；改为独立新鲜查询后两端各185断言通过。交替4×32次上下文微基准显示复用减少时间，但不作为端到端预算验收。见[原型失败](ledger-context-pool-prototype-evidence-2026-10-24/matrix.json)、[修正原型](ledger-context-pool-prototype-evidence-2026-10-24/fresh-database/matrix.json)。

中间池候选的最初启动器漏写内存参数，功能程序尚未启动即失败；修正后56程序46通过、10失败，包含九版测试闭包漏捕获变量及一项PHP7.2真实时钟倒退拒绝。闭包修复后九版定向补验通过。原元数据测试要求模拟预处理漂移后继续执行，与此前已修复的默认拒绝冲突，现改为明确断言configuration.sql_transaction且不增加prepare次数，保留所有原场景。见[中间矩阵](ledger-context-pool-evidence-2026-10-24/matrix-corrected.json)、[闭包补验](ledger-context-pool-evidence-2026-10-24/statements-supplement.json)。中间源码摘要与最终摘要分开保存；最终通过不覆盖此前时钟失败，也不能将中间ASCII用例通过作为最终安全结论。

## 默认调用与剩余范围

最终源码冻结且其他测试结束后，串行执行一次PHP8.5默认首次签发：真实SystemClock、PDO、纯来源守卫、已知策略提示1、默认3000ms。约3.003121秒返回失败，原因account.completion_unknown，状态pending，未返回可用凭据。堆栈进入签发后的issued／actor认证，随后独立状态见证保留未知完成状态。未重试、续办或执行后续轮换／撤销。见[计时](sql-database-bytes-evidence-2026-10-24/default-85-timing.json)、[运行结果](sql-database-bytes-evidence-2026-10-24/default-85-result.json)、[失败堆栈](sql-database-bytes-evidence-2026-10-24/default-85-run.log)。

默认签发在预算内成功及最终非暂缓候选验收仍未完成；其他八版的默认签发本批未执行。此前真实墙钟回拨及其他历史失败继续保留。本批没有运行完整check.sh或完整恢复／状态边界套件。跨安全代际工作进程交接、未知回执续办、最终账号恢复启用及依赖完整F01均未实现或测试；外部环境验收未执行。当前未知结果只阻止该次操作的后续处理，不应把整个goal标为blocked或宣称稳定版完成。
