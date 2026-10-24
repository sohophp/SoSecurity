# 存储变更对象隐私与默认调试环境复验

上一批Codec预算测试在PHP8.2默认Xdebug develop环境仍有一项大键输入失败。本批确认Change对象直接保留原始状态与结果，var_export和var_dump均泄露测试标记，且native serialize成功导出内容；三个修复前失败日志保留。状态可包含凭据材料，普通诊断不应隐式展开。

Change改用私有闭包保留内容，显式value／expiresAt／result方法及对象身份保持；__debugInfo返回固定占位，var_export不展开闭包捕获内容；__sleep及__wakeup以configuration.storage_serialization拒绝序列化／反序列化。没有修改Codec预算、测试内存、Xdebug配置或原子提交逻辑。

同一4MiB键、同一1MiB附加内存测试在PHP8.2默认Xdebug develop下现已通过。此前单纯把大字符串参数换为长度、在encode统一抛错仍失败，本次保护Change诊断内容后通过；原失败与诊断日志保留于上一批，不覆盖。结论只覆盖此已复现路径，不宣称修复Xdebug全部内存行为。

API审查仅发现SoSecurity\Storage\Change新增__debugInfo、__sleep、__wakeup三个无参数实例方法，原有方法和其他所有类条目逐项一致，类型数仍277。先生成独立候选并断言上述差异，再更新候选契约；[审查记录](storage-change-privacy-evidence-2026-10-23/api-review.json)含前后条目与摘要，未盲目刷新清单。

已执行并通过：PHP7.2—8.5九版99条命令（每版5种隐私／序列化、3种编码预算、文件写入失败、加固及凭据回归）；PHP7.2和8.5实际归档、离线全新消费者安装、来源及同组验证共26步骤通过，vendor源码摘要一致，临时目录已清理；两端真实MySQL每端41项驱动断言及合计12个事务所有权场景通过。最终PHPStan、API契约和shell语法通过，保留既有可选turbo扩展GLIBC警告。

[最终汇总及源码](storage-change-privacy-evidence-2026-10-23/closeout.json)、[九版结果](storage-change-privacy-evidence-2026-10-23/summary.json)、[PHP8.2默认环境](storage-change-privacy-evidence-2026-10-23/php82-runtime.json)、[归档消费者](storage-change-privacy-evidence-2026-10-23/archive.json)均保存。本批不是全项目验收，没有执行暂缓交接、未知续办或最终账号恢复。

兼容变化：原生序列化Change的宿主代码现在会被拒绝；它是回调返回的瞬时存储操作描述，应从可信数据重新构造，不作为持久化对象。显式读取与正常存储行为保持。此前PHP8.2大键低内存失败已由本批当前专项覆盖；默认受保护MySQL签发超时、PHP7.2墙钟倒退和其他缺口仍开放。goal保持active，没有提交、推送、部署、外部投递或生产访问。
