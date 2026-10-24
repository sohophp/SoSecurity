# 私有表解析的同批零行检查

2026-10-23。`SqlSchema::tables()`将同批最多两张MySQL私有表的零行解析合入一条语句。每张表仍出现两次，所有别名独立，ON 1=0和LIMIT 0保证零行；表的实际解析与元数据锁在完整结构／权限查询之前完成。SQLite路径及单表公开辅助方法保持原行为。

正常双表解析由2次变为1次：[修前断言失败](table-resolution-batch-evidence-2026-10-23/before.log)明确记录TABLE_RESOLUTION_READS 2；修后为1。这只证明减少一次该类往返，不能据此宣称总体签发速度或稳定版已经达标。

原有引擎、列、主键、索引、额外UNIQUE、触发器、两向外键、当前权限和回滚校验保留。新增两侧同名临时表遮蔽回归均拒绝；准备阶段仍须解析每张表两次，没有借零行谓词跳过解析。

首轮九版PHP7.2—8.5的SQLite及MySQL功能回归通过。构造新语句后，独立预算检查发现合并路径遗漏原MySQL表名64字节上限；[失败](table-resolution-batch-evidence-2026-10-23/budget-before.log)保留。随后把上限移入MySQL查询前校验，超限不准备SQL。最终源码九版预算专项通过，两端完整双表功能及当前数据库主体权限回归再次通过；两端各221项双表断言及20项主体权限断言。初轮源码与最终源码仅差这个MySQL前置长度条件，初轮记录仍按其原摘要解释，不冒充最终源码九版整轮。

最终两端真实ZIP、离线非软链接消费者的SQLite／MySQL四组通过，全部运行时及SQL资源与当前源码匹配，加载类来源为独立vendor。见[最终消费者](table-resolution-batch-evidence-2026-10-23/final-consumer/consumer.json)。首轮消费者作为前置预算修复前的记录单独保留。

公开API278、DDL、持久格式和默认预算保持，静态分析通过。新用例只使用控制器自建且禁TCP的MySQL与自有SQLite资源，不进入工作进程交接、未知续办或最终账号恢复，也没有外部投递、提交、推送或部署。

最终源码下，真实SystemClock／原生PDO、原3000ms预算的首次签发仍失败，约3.3339秒、account.completion_unknown、pending；未续办，输入摘要保持，临时副本清理完成。不能据单次前后计时声称加速或减速。见[测量](table-resolution-batch-evidence-2026-10-23/default-85-timing.json)与[汇总](table-resolution-batch-evidence-2026-10-23/delivery.json)。完整稳定版验收未完成，goal保持active。
