# 账本读取重复查询修复（2026-10-23）

本批只调整普通 Ledger::read 的同一事务读取，不涉及恢复激活、跨代工作进程交接、未知回执续办或完整 F01。

## 复现与修改

原实现先扫描完整历史并认证元数据，随后再查询一次目标元数据。`before.log` 在正常正文断言通过后以“预期0次、实际1次目标元数据查询”失败。现在完整历史扫描只保留一个目标的已认证元数据，待根记录、条数和历史摘要全部验证成功后再读取并校验正文。不存在跨调用缓存，历史扫描预算、签名、正文长度和摘要校验保持。未更改权限检查、事务提交和默认时间预算。

公开方法签名和277类／接口清单保持。非法ID在结构查询前拒绝；正常返回结构不变。新增选择参数仅用于私有方法。

## 已执行的专项验证

- PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3、8.4、8.5，SQLite矩阵46/46通过；PHP8.5初次六场景也通过。矩阵覆盖正常、不存在、非目标签名损坏、删除非目标历史和正文损坏；分页65条在7.2与8.5验证。8MiB内存限制，各场景均核对数据库未改变及事务已结束。
- 私有无TCP MySQL8.0.46，PHP7.2／8.5六场景各通过，合计12/12。仅操作自行创建的测试表与实例。
- Composer离线归档及全新消费者安装六步骤通过，消费者两端共12个MySQL场景通过；归档排除tests和证据目录，反射确认加载vendor实现，Ledger／SqlTransaction／SqlSchema摘要一致。消费者临时目录已清理。消费者7.2使用既有sodium运行包装器。
- PHPStan通过；既有可选turbo扩展GLIBC加载警告保留。API检查通过，277个类／接口。

## 未关闭事项

当前默认预算诊断约3.38秒，仍返回account.completion_unknown、acceptance=false、witness=pending。脚本退出0只表示诊断完成，不是验收通过。诊断期间有其他隔离测试运行，耗时不能作为严格前后性能比较。没有续办pending，也没有放宽预算。此批仅证明消除一条重复查询及保护性专项测试通过，不证明默认预算问题、PHP7.2时钟问题或完整候选已解决。

其余非暂缓产品核对仍需继续；暂缓项和外部验收不计完成，goal保持active。

## 本地证据

[证据汇总](ledger-read-capture-evidence-2026-10-23/summary.json)、[本批源码差异](ledger-read-capture-evidence-2026-10-23/ledger.patch)、[复现](ledger-read-capture-evidence-2026-10-23/before.log)、[九版矩阵](ledger-read-capture-evidence-2026-10-23/matrix.json)、[MySQL](ledger-read-capture-evidence-2026-10-23/mysql.log)、[归档](ledger-read-capture-evidence-2026-10-23/archive.json)、[默认预算诊断](ledger-read-capture-evidence-2026-10-23/default-profile.log)。
