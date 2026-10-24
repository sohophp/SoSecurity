# 账号账本根记录与首批历史合并读取（2026-10-24）

本批继续同范围的活跃goal。仅处理非暂缓的账本读取成本与相关安全边界，不执行跨代工作进程交接、未知结果续办、恢复账号最终启用或完整F01。默认签发和最终非暂缓候选核对仍是独立关口，不以查询数量减少认定完成。

## 实际变更

修复前，每次原生MySQL账本检查分别读取根记录、首批历史元数据；[原始复现](ledger-root-batch-evidence-2026-10-24/before.log)记录实际2次、预期1次的失败。此前默认首次签发预算失败的证据保持，本批没有提高预算。

`Ledger`在受限原生路径中通过LEFT JOIN一次读取根记录及最多64条历史元数据。根记录仍先认证，全部历史仍逐条认证并重新计算数量／摘要，后续分页保持；正文仍在原来的独立读取阶段验证。空历史使用明确的存在标记，缺根和孤立历史保持拒绝。没有缓存根、历史、账号或授权结论，没有移除会话更新及权限回调。

仅MySQL、原生PDO／PDOStatement、原生SystemClock、异常模式、原生预备语句、自然字段名和可信入口守卫允许合并；带恢复回调的单元、自定义时钟、PDO／语句适配器或不透明入口守卫保持原读取路径。SQLite账本读取保持原路径。`SqlSchema`为内部投影增加受限表别名／输出前缀，原默认SQL及类型、长度约束保持。

本批三个运行时文件的准确改动见[Ledger](ledger-root-batch-evidence-2026-10-24/Ledger.diff)、[SqlSchema](ledger-root-batch-evidence-2026-10-24/SqlSchema.diff)、[SqlTransaction](ledger-root-batch-evidence-2026-10-24/SqlTransaction.diff)。修复前源码分别保存，不覆盖已有Git改动。

## 已执行并通过

- [九版MySQL矩阵](ledger-root-batch-evidence-2026-10-24/mysql-matrix.json)：PHP7.2、7.3、7.4、8.0—8.5各20场景，合计180场景通过。覆盖普通／空／格式2初始账本、65条分页、缺失目标／根、孤立记录、根及其他历史篡改、删除历史、同长度正文篡改、8MiB异常正文、回调期间变化、四类自定义依赖，以及第二连接对根／记录行和空历史范围的竞争。进程内存限制8MiB；不读取异常大正文到PHP。
- [九版SQLite矩阵](ledger-root-batch-evidence-2026-10-24/sqlite-matrix.json)：81条程序通过，覆盖别名输入、原默认SQL、旧驱动整数字符串、类型及长度拒绝、原账本和七类检查点读取行为。
- [两端相关MySQL](ledger-root-batch-evidence-2026-10-24/related-mysql.json)：PHP7.2／8.5共118场景通过，包括因子首次读取、读取期间账号变化、历史认证、撤权、临时表遮蔽、数据库切换、事务边界及当前独立登记工作进程。这里只借用同一SQL事务执行当前读取，不是跨安全代际交接。
- 原生首屏数据读取由2条变1条，65条历史由3条变2条；四类自定义依赖仍为原路径。以上是实际服务器日志计数，不代表完整签发耗时结论。
- [修正后真实ZIP／离线新消费者](ledger-root-batch-evidence-2026-10-24/consumer-corrected/consumer.json)：两端共10步骤全部通过。核对全部运行时及SQL资源摘要、实际vendor反射来源、非符号链接安装、归档排除及自身清理；两端新增MySQL20场景均实际执行。
- [PHPStan](ledger-root-batch-evidence-2026-10-24/phpstan.log)无错误，既有可选turbo扩展GLIBC警告保留；[公开API](ledger-root-batch-evidence-2026-10-24/api.log)实际278类／接口通过，本批不修改候选清单。完整检查脚本只检查Shell语法，不执行其中暂缓套件。

这些是同一运行时／SQL摘要下的定向回归，不是全项目九版验收。输入见[371文件摘要](ledger-root-batch-evidence-2026-10-24/inputs.json)，交付核对见[汇总](ledger-root-batch-evidence-2026-10-24/delivery.json)。

## 保留的测试失败

新别名测试首轮在四个旧版PDO上错误地要求返回PHP整数，实际为整数字符串，见[初轮](ledger-root-batch-evidence-2026-10-24/projection-matrix.json)及相应日志；修正测试取值后纳入上述81条最终程序。运行时没有为测试改动解码约束。

消费者首轮10步骤中8通过／2失败，原因是启动器遗漏允许的`-d memory_limit=8M`参数，新增MySQL程序未进入，见[原结果](ledger-root-batch-evidence-2026-10-24/consumer/consumer.json)。修正启动器后重建归档并完整执行上述10步骤。两次源码／SQL摘要相同，原失败、原启动器及修正后记录分别保留，不覆盖成一次全绿。

## 兼容与剩余事项

公开契约、签名数据格式、默认预算及错误拒绝保护保持。原生MySQL更早读取并锁定首批历史元数据；这是执行顺序的变化，不应依赖损坏根与历史锁冲突同时出现时的拒绝先后。自定义依赖保持旧路径，不增加授权缓存。

所有相关测试结束后，仅执行一次PHP8.5原生SystemClock／PDO默认首次签发：3000ms预算不变，约3.441983秒后返回`account.completion_unknown`，见[时序](ledger-root-batch-evidence-2026-10-24/default-85-timing.json)、[调用栈](ledger-root-batch-evidence-2026-10-24/default-85-run.log)及[输入／清理](ledger-root-batch-evidence-2026-10-24/default-85-result.json)。调用栈落在`issued()`返回阶段的`actor()`复核；状态为pending，没有续办。其余八版默认首次签发本批未执行，不使用旧九版失败作为当前候选结果。一次失败耗时不能用于宣称性能提升或退化，查询次数减少也未解决默认签发缺口。历史PHP7.2时钟倒退及其他未解释失败保持；最终非暂缓候选核对尚未完成。暂缓流程、真实IdP／设备／宿主、生产数据库、外部投递、远端CI及独立人员审查未执行。goal保持active，不能标记完整稳定版或发行通过。未提交、推送、部署；测试只清理自行创建的进程和临时资源。
