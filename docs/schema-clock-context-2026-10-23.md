# SQL结构校验证明与宿主回调边界

2026-10-23。核对默认签发的重复SQL读取时，确认一处结构证明复用缺陷并修复：自定义Clock可以在同一保存点内切换当前数据库，原证明只绑定保存点，随后接受了另一数据库中含额外UNIQUE的表。

测试只在控制器自建、禁TCP的MySQL内创建两个私有数据库，将已初始化的空账本完整复制到第二库并增加额外UNIQUE；第二次checkpoint由Clock触发USE。修前未拒绝，[实际断言失败](schema-clock-context-evidence-2026-10-23/before-functional.log)为Expected true, got false。未读取业务数据库，没有修改已存在的数据或恢复旧安全代际。

`SqlTransaction::verifySchema()`现在仅在原生PDO／原生PDOStatement、固定SystemClock及无宿主回调的入口下复用保存点内证明。其他路径先清空证书，再完整校验；宿主回调、写入及事务切换原有失效规则保持。自定义Clock、PDO／语句适配器及自定义入口的SQL往返可能增加，不再沿用旧源码下这些配置的优化测量。默认预算、DDL、持久格式及公开API278保持。

最终定向验证：PHP7.2—8.5九版实际MySQL均通过，每版同时核对Clock切库和普通系统时钟路径经宿主回调切库后的具体configuration.sql_schema拒绝；共36项断言。[日志](schema-clock-context-evidence-2026-10-23/accepted-matrix.log)。两端SQLite既有SQL事务上下文回归各191断言通过。静态分析及API278核对通过。

工作进程回归初轮PHP7.2前13个场景通过，下一场景初始化独立栅栏时发生明确的墙钟倒退，后6个未执行；原失败保留，没有重跑取绿。最终源码的PHP8.5独立补验20/20通过。PHP7.2工作进程整组不能记为通过。

两端实际Composer ZIP、离线非软链接消费者的新MySQL专项均通过，安装来源通过Reflection核对，运行时与SQL资源摘要逐文件匹配，消费者目录及测试自建资源已清理。见[最终消费者](schema-clock-context-evidence-2026-10-23/final-consumer/consumer.json)。前序运行器的参数不匹配、PHP7.2测试root账号认证协议错误及补验分别保留，没有放宽产品权限；最终专项使用仅在该私有服务器创建的兼容认证测试账号。

本批是定向安全修复，不是全项目或稳定版验收。原生默认签发、历史时钟失败、暂缓链路和外部验收仍须保留准确状态；goal保持active。未提交、推送、部署或外部投递。

修复后仅执行一次PHP8.5默认3000ms首次签发：约3.4969秒后返回account.completion_unknown，见证pending，未续办；输入摘要保持，临时副本清理完成。该结果证明默认缺口仍开放，不能把本批定向通过视为可发布稳定版。见[计时](schema-clock-context-evidence-2026-10-23/default-85-timing.json)与[汇总](schema-clock-context-evidence-2026-10-23/delivery.json)。
