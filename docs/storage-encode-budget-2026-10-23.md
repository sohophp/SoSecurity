> 后续[Change诊断隐私修复](storage-change-privacy-2026-10-23.md)在原默认PHP8.2 Xdebug环境通过了大键低内存测试；下文失败作为原阶段证据保留。

# 普通状态编码前字符串预算

检查重复会话写入路径时发现独立缺口：Codec::encode虽限制8192节点、30层深度和最终65536字节JSON，却在json_encode前没有限制字符串值与数组键累计字节。大值、大键及多个共享字符串组成的大状态，均复现编码阶段内存耗尽。原始三个before-*日志保留。本批没有采用跳过FileStore写入的优化，不改变存储原子提交语义。

修复在原遍历中累计字符串值和字符串键的原始字节，超过65536立即结束预检，再由encode抛出既定storage.encoding。原始字节是JSON大小的下界，合法可编码状态不会因此被提前拒绝；转义、数字及结构开销仍由最终精确JSON长度检查处理。节点／深度／对象拒绝保留，容器格式和TTL不变。新增测试覆盖三个低内存拒绝场景、恰好65536字节有效状态、Unicode／转义及转义后超限，已接入bin/check.sh，未执行包含暂缓流程的完整脚本。

最终PHP7.2—8.5九版54条命令：53通过、1失败。失败为PHP8.2默认Xdebug develop环境下的4MiB键测试：产品已到达storage.encoding拒绝，但调试扩展生成异常诊断时申请约16MiB而耗尽内存。将辅助函数参数改为长度、在encode统一抛错仍未消除此环境开销，各阶段失败都保留。仅一次XDEBUG_MODE=off的对照通过，不替代默认环境失败，也未修改系统配置。

最终PHP7.2／8.5归档、离线全新消费者安装、来源定位及6类消费者回归合计16步骤通过，vendor Codec摘要匹配并清理临时目录。两端真实MySQL每端41项驱动断言、共12个事务所有权场景通过。最终PHPStan、公开API277类／接口及shell语法通过；初轮静态分析发现一个重复is_string分支，已去除，初轮日志保留。既有可选PHPStan turbo扩展GLIBC警告不影响其最终通过。

[汇总与准确源码摘要](storage-encode-budget-evidence-2026-10-23/closeout.json)、[最终矩阵](storage-encode-budget-evidence-2026-10-23/final/summary.json)、[默认环境失败](storage-encode-budget-evidence-2026-10-23/final/82-001-storage-encode-budget-key.log)、[关闭调试模式的对照](storage-encode-budget-evidence-2026-10-23/no-xdebug82.log)、[归档消费者](storage-encode-budget-evidence-2026-10-23/final/archive.json)均保存。

本批兼容变化仅为超大状态在编码前按既定原因拒绝，合法格式、公开签名和原预算保持。由于默认PHP8.2仍有上述失败，不宣称本批全绿或完整稳定版通过。默认受保护MySQL签发超时、PHP7.2墙钟倒退、其他未关闭事项及暂缓／外部范围保留；goal保持active。没有提交、推送、部署、外部投递或访问生产数据库。
