# SQL事务见证与无效实例检查

本批连续修复两项独立问题，运行时仅修改 `SqlTransaction`。最终候选的输入摘要和结果在 [precheck证据目录](sql-unit-precheck-evidence-2026-10-24/inputs.json)，传输前置实验、旧候选和失败记录在 [transport证据目录](witness-transport-evidence-2026-10-24/protocol-matrix.log)。未修改公开 API、DDL、持久格式或默认预算。

## 保存点见证合发

此前真实原生路径计数包含2011条保存点命令，见[原生计数](native-sql-counts-evidence-2026-10-23/analysis.json)。这些是失败签发前缀中的逻辑命令数，不是完整签发性能结果。

只在原生 PDO／语句、SystemClock、无宿主回调的已知入口守卫及非恢复专用单元中，合发同一随机见证点的 RELEASE／SAVEPOINT。仍执行两条原命令，执行前后各检查入口状态，检查原时钟和预算；没有缓存归属判断。其他配置保留原两条独立命令和原检查位置。

直接观察发现，本机PHP7.2／7.3在第二条命令失败时，PDO::exec可能返回1而不抛异常。该行为与[PHP7.2驱动实现](https://raw.githubusercontent.com/php/php-src/PHP-7.2/ext/pdo_mysql/mysql_driver.c)一致，新驱动的错误处理另见[PHP8.2初版实现](https://raw.githubusercontent.com/php/php-src/php-8.2.0/ext/pdo_mysql/mysql_driver.c)。因此不能只判断返回值不是false。本实现严格要求整数0，其他返回值和不确定错误使单元失效；没有把旧驱动的错误丢失当作成功。

连接禁用多语句时，只有首次精确42000／1064才转回原单发路径；先成功释放原见证，才能重建，不盲目创建新点。不修改连接选项，不重放业务回调。一次确认不支持后，该单元及借用它的只读子单元使用原路径。其他错误以及已成功合发后发生的异常不作这种降级。[PDO文档](https://www.php.net/manual/en/class.pdo-mysql.php)说明该连接选项在构造时指定；本批另以九版实际连接证明禁用状态未被重新启用。

MySQL通用日志会分别记录同一批的命令，初版通过分号计数的测试没有测到真实传输，相关失败保留。最终测试用同一连接Bytes_received、相同长度保存点名，对比原两次发送和SDK刷新：原生成功路径减少3字节协议开销；自定义时钟／适配器／未知入口守卫与原路径相等。禁用多语句时首次探测增加开销，随后与原路径相等。这证明合发及降级路径，不据此推导整个签发提速。

新增直接协议8场景×9版本，共72项通过：正常刷新、第一条／第二条错误、禁用多语句、事务结束、提前回滚、不缓冲连接及保存点顺序对照。见[协议矩阵](witness-transport-evidence-2026-10-24/protocol-matrix.log)。它直接调用PDO，不依赖后续实例前置检查修复。原始矩阵因PHP8.5弃用常量而中止，后来使用其新常量；更早保存点对照初版还受PHP7.2的SQL回滚后PDO本地标志影响，改用测试自己事务的PDO回滚。所有原日志保留。

另在PHP7.2／8.5单独验证RELEASE较早点本身会移除较晚点，见[观察](witness-transport-evidence-2026-10-24/release-only.log)；原文和注释的反向说明已修正。原单发和新合发的结果相同，更早的宿主保存点保持。现有契约已禁止回调管理保存点，本批没有新增任意嵌套保存点保留能力。

## 无效实例先拒绝，守卫后仍复查

原run／enlist先执行入口守卫再检查busy／failed。受控SQLite复现中，重入忙碌单元时，入口守卫被额外调用并执行COMMIT：业务主体0次，守卫副作用1次，父业务行已提交1条，见[原缺陷](sql-unit-precheck-evidence-2026-10-24/before.log)。测试只操作自身数据库，错误守卫用于模拟可能有副作用的宿主依赖。

最终在入口守卫之前增加已知无效状态检查，并保留原守卫之后的检查。有效调用仍执行原入口守卫。开发候选若只移动检查，会漏掉守卫重入并令实例失效的情况，实际复现外层主体1次及提交1条；见[候选失败](sql-unit-precheck-evidence-2026-10-24/admission-transition-before.log)。改为前后双检查后，两个方向都在主体及额外守卫效果0次时拒绝。

新增3状态×3方法×9版本：SQLite81场景、MySQL81场景通过，覆盖run／enlist／inContext以及忙碌、已失效、入口期间失效。见[MySQL](sql-unit-precheck-evidence-2026-10-24/mysql.log)、[SQLite运行记录](sql-unit-precheck-evidence-2026-10-24/sqlite-run.log)。源码前置备份、增量diff和测试运行器均保留。

## 最终候选验证

- 九版MySQL合发SDK135场景通过，覆盖拥有／加入事务、禁用及首次失败、结束／提前回滚、静默错误模式、各种降级、借用及回调失败后的复用，见[当前SDK矩阵](sql-unit-precheck-evidence-2026-10-24/witness-current.log)。
- 九版SQLite还执行原事务上下文和账本18条程序，与新前置检查共27条程序通过，见[结果](sql-unit-precheck-evidence-2026-10-24/sqlite.json)。
- 两端MySQL当前工作进程40场景、锁定结构证明28场景、元数据锁10场景通过，见[工作进程](sql-unit-precheck-evidence-2026-10-24/worker-context.log)、[结构证明](sql-unit-precheck-evidence-2026-10-24/locked-schema.log)、[锁](sql-unit-precheck-evidence-2026-10-24/mdl.log)。早期锁测试在PHP7.2清理自己事务时使用SQL ROLLBACK，令PDO标志滞后，下一阶段未执行；修正为自身PDO回滚后，剩余及最终候选完整矩阵分别保留，未修改产品保护。
- 两端实际ZIP及离线全新Composer消费者14步通过；非符号链接安装、vendor反射来源及全部运行时／SQL资源摘要一致，覆盖两项新行为及直接协议，临时资源清理完成，见[消费者](sql-unit-precheck-evidence-2026-10-24/consumer/consumer.json)。
- PHPStan无错误，原可选turbo扩展的GLIBC警告保留；公开API仍278类型，契约检查通过。开发检查入口已接入专项，仅执行脚本语法检查，未运行含暂缓套件的完整脚本。见[静态分析](sql-unit-precheck-evidence-2026-10-24/static.log)、[API](sql-unit-precheck-evidence-2026-10-24/api.log)。

以上均为专项，不是整项目或稳定版验收。传输阶段的较早SDK矩阵及消费者不替代最终候选；最终SDK和相关回归均已在前后双检查版本重跑。

## 未关闭事项及兼容变化

传输优化后、前置检查修复前，单独执行真实SystemClock／原生PDO默认首次签发，仍约3.074246秒失败，3000ms预算，issued的第三次actor进入时到期，见证pending、外层account.completion_unknown。没有续办，见[时序](witness-transport-evidence-2026-10-24/default-85-timing.json)、[原始日志](witness-transport-evidence-2026-10-24/default-85-run.log)、[输入与清理](witness-transport-evidence-2026-10-24/default-85-result.json)。最终仅增加无效实例拒绝前后检查，未再重复该签发实验；最终版本的真实默认签发本批未执行，不能引用较早结果称其通过，默认预算缺口仍未关闭。

公开签名、DDL、格式和默认时间／资源预算不变。可观察兼容变化包括原生连接合发控制命令、禁用多语句时一次探测后降级，以及无效实例优先返回sql.cleanup而非先执行入口守卫。有效守卫仍须遵守禁止提交／回滚等既有契约。

历史时钟及其他未解释失败、最终非暂缓候选核对仍开放；暂缓跨代交接、未知回执续办、最终恢复启用和完整F01未实现或测试，外部验收未执行。goal保持active；未提交、推送、部署、访问生产数据库或外部投递，既有改动保留。见[汇总](sql-unit-precheck-evidence-2026-10-24/delivery.json)和[Git状态](sql-unit-precheck-evidence-2026-10-24/git-status.final.txt)。
