# 账本预备语句有界复用（2026-10-24）

继续同范围活跃goal，仅处理非暂缓的原生账本读取开销。默认首次签发仍失败，最终非暂缓候选核对未完成；本批不是全项目验收或稳定版结论。

## 确认与修复

[原始复现](ledger-statement-evidence-2026-10-24/before.log)使用原生PDO／SystemClock、覆盖根表和记录表的真实SqlStateSnapshot、初始格式2见证及原生StateBoundary守卫：连续两次账本读取准备2次、执行2次，减少准备次数的断言失败。既有默认签发失败及全部未提交源码保留。

`Ledger`通过私有`checkedRoot`在原结构／权限复核完成后，将刚读取的数据库名直接作为局部参数传给紧接着的私有根读取。不增加保存数据库名的属性，不从旧的结构证明中提取该值，不跨调用保存或复用权限结论。直接调用公开内部`verifySchema():void`仍不返回该值；正文前的复核保持原样。没有修改账号权限回调、会话更新或凭据返回检查。

`SqlStateAccess`仅在既有受限原生路径、已登记PDO及完整匹配的有界账本元数据SELECT中使用这个参数。SQL、参数名称、数据库及获取格式共同区分语句；每次重新绑定namespace、执行、完整读取并关闭游标。语句取出时先从池中移除，失败或清理不确定的语句不放回。继续使用既有每连接8条已关闭语句的池上限，不缓存行、正文或授权结果。其他元数据读取仍独立查询DATABASE()，未放宽既有规则。

本机支持相应属性读取的PHP8.2—8.5，两次读取准备1次、执行2次；PHP7.2—8.1仍准备2次、执行2次。实际按驱动能力判断，不硬编码PHP版本启用缓存。未登记连接、自定义时钟、PDO／语句适配器、不透明守卫及既有恢复单元保持降级路径。

修改仅限三个内部运行时类型：[Ledger差异](ledger-statement-evidence-2026-10-24/Ledger.diff)、[SqlTransaction差异](ledger-statement-evidence-2026-10-24/SqlTransaction.diff)、[SqlStateAccess差异](ledger-statement-evidence-2026-10-24/SqlStateAccess.diff)。公开278类型清单、数据格式、默认预算和SQL资源保持，没有数据迁移或新增公开配置。

MySQL8.0.46的官方实现也表明，执行已准备的SELECT时仍重新打开表并检查权限及锁定子句；见[执行器源码](https://github.com/mysql/mysql-server/blob/mysql-8.0.46/sql/sql_select.cc)。本批仍保留SDK自己的每次权限／结构复核，不以服务器机制代替SDK检查。

## 已执行的验证

- [九版144场景覆盖](ledger-statement-evidence-2026-10-24/mysql-coverage.json)：首轮PHP8.2—8.5各16场景通过，修正测试的旧驱动能力预期后，PHP7.2—8.1各16场景通过。两阶段运行时及SQL摘要完全一致，不能写成一次完整重跑全绿。
- 新场景覆盖真实原生受保护读取、namespace变化、有效写入后读取、历史及正文篡改、撤权、临时表遮蔽、合法同结构数据库切换、获取格式变化、语句类型切换、未登记连接、自定义时钟、不透明守卫、8条淘汰、非法上下文参数及事务边界。原生复用期间新增独立DATABASE()查询为0；完整日志还包含其他既有元数据查询，不能把它们误记为0。测试进程限制8MiB并检查池大小。
- [九版SQLite126条程序](ledger-statement-evidence-2026-10-24/sqlite-matrix.json)全部通过：原账本、初始读取六类及检查点读取七类行为。该路径不启用新语句池规则。
- [两端相关MySQL](ledger-statement-evidence-2026-10-24/related-mysql.json)：10条控制器命令9通过、1失败。根／历史合并读取两端各20场景、既有元数据语句程序、耐久语句两端各10场景、锁定结构两端各14场景均通过。PHP8.5因子首次读取组19/19通过；PHP7.2该组18/19通过，分页预设构建第37条记录时，Deadline检测持续时间时钟倒退而失败，见[原日志](ledger-statement-evidence-2026-10-24/related-factor-initial-read-72.log)。该路径是自定义时钟／PDO适配器，未启用新缓存；失败保留，没有重跑覆盖或修改时钟保护，也不声称宿主时钟根因已修复。
- [原归档与新消费者](ledger-statement-evidence-2026-10-24/consumer/consumer.json)10步骤9通过／1个旧驱动预期失败，PHP8.5新场景16项实际通过；[补充重建](ledger-statement-evidence-2026-10-24/consumer-supplement/consumer.json)4步骤全部通过，PHP7.2最终测试16项完整执行。运行时／SQL摘要相同，补充测试文件摘要单独记录。核对真实ZIP、离线非符号链接安装、vendor反射来源、全量运行时／SQL字节及自身临时资源清理；不能合称一次全新消费者完整重跑通过。
- [静态分析](ledger-statement-evidence-2026-10-24/phpstan.log)无错误，既有可选turbo扩展GLIBC警告保留；[API278](ledger-statement-evidence-2026-10-24/api.log)通过。完整检查脚本只检查Shell语法，不执行其暂缓套件。

当前输入见[370文件摘要](ledger-statement-evidence-2026-10-24/inputs.json)，最终核对见[交付记录](ledger-statement-evidence-2026-10-24/delivery.json)。这些是准确运行时摘要下的专项，不是全项目九版验收。

## 测试修正及未关闭事项

反射池大小的补强检查最初在PHP8.5调用已弃用的setAccessible，见[失败](ledger-statement-evidence-2026-10-24/native-counter.log)。已仅在PHP8.1以前调用它；原测试保存，没有压制弃用错误。首轮旧驱动能力预期只检查ORACLE_NULLS，遗漏STRINGIFY_FETCHES，错误地要求缓存，五版均在第一个场景断言失败，见[初轮矩阵](ledger-statement-evidence-2026-10-24/mysql-matrix.json)。修正为核对所有相关获取属性，再补跑五版；运行时没有为测试改动保护。PHP8.2—8.5的实际缓存能力及预期不变，未重复已通过的64场景。原失败、两个测试修正版本和补充结果分别保留。

所有相关测试终止后，只执行一次当前PHP8.5原生SystemClock／PDO默认首次签发：预算3000ms，约3.231712秒失败，原因account.completion_unknown、状态pending；调用栈位于issued返回阶段actor复核，未续办。见[时序](ledger-statement-evidence-2026-10-24/default-85-timing.json)、[日志](ledger-statement-evidence-2026-10-24/default-85-run.log)、[输入及清理](ledger-statement-evidence-2026-10-24/default-85-result.json)。其余八版默认签发本批未执行。只确认准备次数减少，不以两次不同源码的单轮耗时宣称完整性能提升或退化。

默认首次签发、时钟倒退及其他历史未解释失败、最终非暂缓候选核对仍未关闭，goal保持active。本批不实现或测试跨安全代际交接、未知回执续办、恢复账号最终启用及完整F01，已有源码、审批和限制保留；真实宿主／IdP／设备、生产数据库、外部投递、远端CI及独立审查未执行。未提交、推送或部署；仅清理测试自行创建的资源和进程。
