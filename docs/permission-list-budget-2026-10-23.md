# 状态权限与凭据解码分配前限量

延续凭据列表预算修复，检查同类普通输入路径，确认两处独立遗漏：StatePermission认证方式先array_values再检查最多4项；CredentialState::fields在确认字段数量前array_keys并排序。三个低内存场景均复现进程耗尽，分别保留于before.log、before-state-root.log和before-state-record.log。输入数组已存在时，复制约4MiB键／值超过1MiB剩余空间。

修复只提前既有数量判断：StatePermission先拒绝超过4项；CredentialState字段数不一致立即返回false，数量相等仍执行原精确键集合校验。普通状态权限不构成授权本身；损坏凭据仍由read抛出storage.corrupt。没有改变权限判断、字段格式、合法排序、原因码或公开签名，不触及恢复启用和工作进程交接。

已执行并通过：权限构造器PHP7.2—8.5九版9条命令（每条11项）；状态根／子记录低内存拒绝及原credentials、credential-management-scope九版36条命令（两新增程序各6项，原程序各5400／1932项）。权限新增测试也覆盖合法空列表／4项列表、重复值、稀疏键、未知类型、稳定binding、输入数组修改与令牌不导出。新测试均接入bin/check.sh，但没有执行包含暂缓链路的完整脚本。

第一阶段权限修复有单独归档记录；最终两处修改后的归档、离线全新消费者安装、来源定位及PHP7.2／8.5五类消费者测试共14步骤通过。vendor两份运行时摘要与仓库一致，临时消费者已清理。最终PHPStan及公开API277类／接口通过，保留既有可选turbo扩展GLIBC警告。仅PHP内存校验逻辑变化，没有SQL改动，本批不宣称真实SQL后端或完整产品验收。

[本批收口及准确摘要](permission-list-budget-evidence-2026-10-23/closeout.json)、[权限九版结果](permission-list-budget-evidence-2026-10-23/summary.json)、[最终状态／凭据结果](permission-list-budget-evidence-2026-10-23/final/summary.json)、[最终归档消费者](permission-list-budget-evidence-2026-10-23/final/archive.json)均保留。

同类核对中，TotpFactorState在规范化前已有10项恢复码上限；配置／签名策略顶层键有数量预检；HTTP权限策略／出站列表有前置上限，未仅凭搜索命中改动这些实现。MailboxRecovery属于恢复相关路径且其记录正文另有预算，本轮不改动或执行其流程。这不是全源码所有内存路径的审计完成声明。

兼容性：仅异常超大输入由内存耗尽改为既定拒绝，合法行为和状态格式保持。旧855项普通组件矩阵按原快照解释，不因本批专项改写为当前全项目通过。默认受保护MySQL签发总预算失败、PHP7.2时钟倒退及其他未关闭事项保持；goal为active。没有提交、推送、部署、外部投递或操作生产数据库。
