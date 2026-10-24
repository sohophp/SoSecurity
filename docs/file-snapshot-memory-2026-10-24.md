# 小目录完整文件快照减少临时排序I/O

> 后续[FileStore异常节点修复](file-store-nodes-2026-10-24.md)改变了完整运行时输入；本页保留文件快照阶段的准确绑定，不能替代后续候选结果。后续消费者PHP7.2的4097文件容量复核另有持续时间时钟倒退失败，旧通过不覆盖该失败。

本批继续处理非暂缓本地可用性缺口，只修改 `FileStateSnapshot`。小目录的完整摘要在原分块内直接计算，避免把相同记录写出再重读；不减少物理文件扫描，不缓存摘要或权限，不修改默认预算。源码及差异见[修前备份](file-snapshot-memory-evidence-2026-10-24/FileStateSnapshot.php.before)、[运行时差异](file-snapshot-memory-evidence-2026-10-24/runtime.diff)。

## 确认与实现

先在无其他本次测试并行时检查上一候选的真实默认首次签发：仍约3.298144秒失败，pending／account.completion_unknown，未续办。见[独立时序](native-default-isolated-evidence-2026-10-24/default-85-timing.json)和[输入及清理](native-default-isolated-evidence-2026-10-24/default-85-result.json)。它说明先前并行测试负载不能解释整个默认预算缺口，不把该结果绑定到本批后续源码。

源码确认：即使目录只有1个状态文件，也先建立排序文件、写出96字节记录，再打开并读取同一记录。修前测试观察到该排序文件创建1次，预期0次的断言失败，见[原始失败](file-snapshot-memory-evidence-2026-10-24/before.log)和[当时测试](file-snapshot-memory-evidence-2026-10-24/test.initial.php)。

实现只在尚未触发原256条分块落盘时，直接按原字符串排序顺序哈希完整块；0—255个状态文件使用此路径，256个及以上继续原外部排序与归并。每个文件仍完整读取并校验描述符／路径、权限、所有者、链接数和字节数；完整目录、文件容量、选定字节、逐记录期限及最终目录复核保持。私有临时工作目录仍创建、校验和确认清理，排序目录仍是必需配置。

保留原摘要字节协议和FileSnapshot.Profile.3指纹，不需要状态迁移。测试用旧源码仅重命名类的[对照实现](file-snapshot-memory-evidence-2026-10-24/LegacyFileSnapshot.php)，并独立按固定格式计算完整摘要；测试中的文件打开观察函数仍调用实际文件系统，不替换文件内容或哈希结果。

## 已执行并通过

- PHP7.3—8.5共80个新旧实现对照样例：0、1、2、255、256、257、511、512、4096、4097个实际文件，逆序创建、64KiB／NUL字节、选定／缺失文件、物理容量和8MiB内存限额。摘要一致；1／2／255文件的排序文件创建从1降为0，256以上与旧实现相同。见[后续结果](file-snapshot-memory-evidence-2026-10-24/sqlite-continuation.json)。
- PHP7.2安装后的实际消费者通过相同10个样例的独立格式向量，不依赖旧类；与上述八版合计覆盖当前候选九版90个样例。不能据此称旧实现对照程序通过，见下方失败记录。
- 共55条后续程序通过，包含八版新对照程序、九版原文件完整性／不可变采集／容量准入／暂存槽／组合来源检查，以及两端10000文件外部排序回归。保留权限、符号／硬链接、未选文件损坏、目录替换和跨源变更拒绝。见[准确命令及结果](file-snapshot-memory-evidence-2026-10-24/sqlite-continuation.json)。
- 两端私有MySQL组合来源及非权威暂存槽4条程序通过，见[日志](file-snapshot-memory-evidence-2026-10-24/mysql-context.log)。没有运行跨代交接、未知续办或最终恢复启用。
- 两端实际ZIP及离线全新Composer消费者10步通过，含20个新样例及6条既有文件／MySQL组合程序。vendor来源、完整运行时／SQL资源摘要、非符号链接安装及自身清理均核对通过，见[消费者](file-snapshot-memory-evidence-2026-10-24/consumer/consumer.json)。
- PHPStan无错误，已有可选turbo扩展GLIBC警告保留；API278契约检查通过。见[静态分析](file-snapshot-memory-evidence-2026-10-24/static.log)、[API](file-snapshot-memory-evidence-2026-10-24/api.log)。完整检查脚本仅检查语法，不运行含暂缓项的整轮。

这些是同一运行时输入下的专项证据，不是整项目验收。377项[输入摘要](file-snapshot-memory-evidence-2026-10-24/inputs.json)在验证结束后保持一致。

## 已执行但失败、未执行及兼容性

最初PHP7.2对照程序在最后4097文件样例的旧实现内发生持续时间时钟倒退，见[失败日志](file-snapshot-memory-evidence-2026-10-24/72-memory.log)、[首轮结果](file-snapshot-memory-evidence-2026-10-24/sqlite.json)。未重复该失败程序、未放宽保护或变更时钟；继续未执行版本和检查。该失败仍保留，不能以当前消费者通过覆盖它，也不能声称本批解决了历史时钟问题。

所有相关测试结束后，准确本批候选的独立默认首次签发仍约3.027312秒失败，预算仍3000ms；在issued阶段第三次actor的会话复核后检查到期，保留pending，外层account.completion_unknown，未续办。见[时序](file-snapshot-memory-evidence-2026-10-24/default-85-timing.json)、[日志](file-snapshot-memory-evidence-2026-10-24/default-85-run.log)、[输入及清理](file-snapshot-memory-evidence-2026-10-24/default-85-result.json)。不把两次单独观测当作稳定性能提升或完整签发成功，默认缺口继续开放。

公开API、DDL、持久格式、来源指纹、内存／文件容量及时间预算不变。可观察变化仅为小目录不创建排序记录文件；实际来源仍逐次完整观测，临时工作目录及其安全要求保持。历史失败、最终非暂缓候选核对仍开放；暂缓功能和外部验收未执行，不宣称稳定版通过，goal保持active。

本批未提交、推送、部署、访问生产数据库或外部投递，既有改动保留。见[汇总](file-snapshot-memory-evidence-2026-10-24/delivery.json)、[精确命令](file-snapshot-memory-evidence-2026-10-24/commands.json)。
