# 当前原生通知队列已知结果复验

本批验证Codec／Change等近期存储层改动后的原生队列，运行时代码与[Change隐私修复](storage-change-privacy-2026-10-23.md)的完整src摘要一致，测试前后输入未改变。仅新增测试运行器--outbox-known-current，固定三个模式defaults、ack、reject，逐条保留返回码，不因第一条失败覆盖后续结果。

已执行并通过：PHP7.2—8.5九版SQLite共27条命令。首次领取使用Outbox原默认10000毫秒预算，覆盖角色／守卫拒绝、异常隐私、作用域／主体／令牌不匹配、顺序阻塞、重入、首次次数和独立消息；已知成功确认验证sent终态及正文清除；已知拒绝验证dead终态、固定错误码和其他消息保持。各模式分别64、98、127项断言。对已确认终态的再次检查不产生新尝试，不是未知回执续办。首次领取末尾故意撤权只检查保持pending，不进行恢复。

真实私有MySQL：PHP8.5三条通过；PHP7.2首次领取和已知成功确认通过，已知拒绝场景在权限前置快照期间触发明确持续时间时钟倒退，退出255。合计5/6通过。失败未重跑、未改时钟或预算；它不因SQLite或其他MySQL场景通过而关闭。

[本批汇总](native-outbox-current-evidence-2026-10-23/summary.json)、[SQLite逐条结果](native-outbox-current-evidence-2026-10-23/results.json)、[PHP7.2 MySQL失败](native-outbox-current-evidence-2026-10-23/mysql72.log)、[PHP8.5 MySQL](native-outbox-current-evidence-2026-10-23/mysql85.log)、[源码输入](native-outbox-current-evidence-2026-10-23/inputs.json)已保留。自有进程、数据库和临时目录均由运行器清理。

本批没有外部投递、租约接管、未知回执续办、跨代交接或最终账号恢复启用。已知结果由本地测试显式提供，不当作真实SMTP／提供器回执证据。不修改产品代码、公开契约或兼容行为，也不因这些专项通过宣称整个R4.3／R4.6或稳定版完成。

默认受保护MySQL凭据签发超时、PHP7.2时钟倒退、其他未齐门禁及暂缓／外部范围保持；goal为active。没有提交、推送、部署或生产访问。
