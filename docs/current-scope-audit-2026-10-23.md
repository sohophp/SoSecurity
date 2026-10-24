# 当前源码与历史失败复核（2026-10-23）

本轮没有更改运行时源码，也没有把历史阶段记录当作当前验收。上一批为实际出站行为修复，本轮按收口要求核对准确内容、兼容说明和仍失败的项目。

## 源码身份

以普通组件828项矩阵的inputs.json为对照，当前src／resources有九份已有文件变化，没有新增运行时或资源文件。九份变化为AuthenticationFlow、RememberedLogin、MySqlStore、SqlSchema、Ledger、ArchiveInspector、Transfer、Client、DohResolver；每份当前SHA-256均能在对应专项证据清单中找到。范围见ordinary-baseline-delta.json及evidence-bindings.json。该核对只证明这些证据所对应的源码身份，不把多批通过汇总为一次完整候选门禁。

本轮固定src、resources、integrations、examples及tests的代码／SQL／JSON输入摘要；测试结束全部仍匹配。原有未提交改动保持。当前中英文兼容说明已补齐，并接入migration与CHANGELOG，见[中文](current-compatibility-2026-10-23.md)／[English](current-compatibility-2026-10-23.en.md)。

## 历史失败的有限复核

公共SQL／账本及认证源码已变化，故对七个受影响的历史PHP7.2失败场景分别执行一次当前源码检查。使用现有sodium包装器、默认时长时钟、全新SQLite／文件数据及新账号，没有覆盖旧日志、续办旧pending或替换单调时钟。

| 场景 | 当前结果 |
| --- | --- |
| custom-plain | 通过 |
| policy-business-denied | 通过 |
| business-normal | 通过 |
| operation-return-consume-guard | 通过 |
| auth-return-cancel-guard | 通过 |
| remember-return-resume-risk-step_up | 通过 |
| normal（普通凭据委托流程） | 失败：replace返回复核中的SessionRegistry验证触发依赖异常，最终保留未知完成结果。底层原因仍未确定。 |

这六个通过不能证明历史失败根因已修好；当前记录与原记录并列。未重跑无关的已通过矩阵。另进行一次隔离诊断，在临时Deadline与CredentialRegistry副本上只输出倒退量及固定错误分类；该次通过77项，未再次复现失败，也未输出诊断事件。因此诊断不构成失败已解决或其由墙钟造成的证据。临时副本已清理，运行时源码未改。

## 尚未关闭的明确关口

1. 当前MySQL默认凭据预算仍失败，最新正常源码诊断见ledger-read-capture证据的default-profile.log。未增大预算、缓存当前权限或续办pending。
2. PHP7.2已独立观测到墙钟倒退；本轮普通凭据委托依赖失败仍未解释，不能把所有失败统一归因于时钟。
3. 最终候选的非暂缓SQL／文件维护、可选包与当前核心组合、实际消费者及文档一致性仍需要按31项要求逐项核对。当前源码身份清单和既有专项不代替这项验收。
4. 跨代工作进程交接、未知回执续办、最终账号恢复启用及完整F01仍暂缓；真实宿主、外部投递、实体设备、独立复核和远端CI不计本地完成。

本轮是证据及兼容性收口进展，不是goal完成。goal保持active，没有提交、推送、部署、生产数据库访问或外部投递。

## 本地证据

[汇总](current-scope-audit-evidence-2026-10-23/summary.json)、[固定输入](current-scope-audit-evidence-2026-10-23/inputs.json)、[源码证据绑定](current-scope-audit-evidence-2026-10-23/evidence-bindings.json)、[七场景逐项命令及结果](current-scope-audit-evidence-2026-10-23/php72-review.json)、[普通流程失败](current-scope-audit-evidence-2026-10-23/php72-normal.log)、[隔离诊断结果](current-scope-audit-evidence-2026-10-23/diagnostic.json)。
