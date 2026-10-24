# 原生授权入口的物理文件容量准入

日期：2026-10-22。继续既定 F01／G1、R1.4 的正常拒绝与容量契约；31 项、80 个有效工作小时上限保持。本批修复 FileStateSnapshot.maximumFiles 的新增账本文件准入，不新增服务、公开接口或配置项。

## 已复现的问题

[修前探针](state-admission-capacity-evidence-2026-10-22/preflight-reproduction.log)在 PHP8.5／SQLite 的真实账号、密码／TOTP 会话、完整 SQL／文件／HMAC 配置来源上逐一执行四个入口。目录物理上已占满声明的 8 个 JSON 文件，包含逻辑过期但尚未删除的记录。

| 入口 | 修前实际结果 | 修后预期结果 |
| --- | --- | --- |
| Links.issueFor | 文件 8→9，持久化 pending 一次，最终 account.completion_unknown | link.capacity；文件、SQL、见证均保持，不持久 pending |
| ResetTokens.issueFor | 同上 | reset.capacity；同上 |
| Grants.begin | 同上 | operation.capacity；同上 |
| CredentialRegistry.issue | 同上 | api_credentials.capacity；同上 |

缺少的不是单个账本的 entries 数量限制：这些检查已有。问题是新账本文件会超过完整物理来源的文件数量上限；它在 pending 之后才发生，导致最终采集不能完成。修前探针四项均实际失败，原日志和[库文件身份](state-admission-capacity-evidence-2026-10-22/before-library.json)保留，不把它们改称通过。

## 改动与边界

四个原生新增账本入口在实际身份／对象／字段／请求授权及已有条目限额检查后，调用已有 StateAccountPolicy::credentialCapacity。它从准确声明的 FileStore 导出文件坐标，在同一独立见证排他锁内读取完整来源，检查真实物理余量并复核来源摘要；不能按逻辑过期数或某个 namespace 的条目数猜测全目录余量。

只在新账本会占用物理文件时拒绝；已有文件即使逻辑过期，也仍是可覆盖的物理位置。已有账本内的合法新增不要求额外文件空位，不会把整个满额目录冻结为只读。拒绝后保持 current，无见证修订推进、令牌消费、SQL／文件效果；按原有受控维护释放一份记录后，同一服务、同一会话可以重试成功。

链接／操作／API 继续使用原 capacity 原因码；重置原语使用 reset.capacity。没有改变令牌格式、默认容量、公开参数或权限条件，也没有把满额检查移到授权之前。底层已发生效果或真正未知的 I/O 结果仍应保留 pending；本补丁不能作为清除已存在 pending、删除第九份文件或重新 initialize 见证的理由。

## 固定验收

[冻结清单](state-admission-capacity-evidence-2026-10-22/execution.json)固定八条命令：PHP7.2／8.5 × SQLite／私有 MySQL 各执行修后四入口探针、136 项容量检查、四组既有原生入口及 HMAC 拒绝兼容，再执行两组真实最后空位竞争。SQLite 另执行原普通 Links／Reset SQL／Grants／API 和物理余量专项。其余四条为两端公开契约、PHP7.2 目标静态分析和 PHP7.2 语法。保护图 16 MiB，普通专项 8 MiB；PHP7.2 是既有私有 sodium／posix／CLOCK_MONOTONIC 环境，不代表系统原版整轮通过。

验收固定包括：

- 满额且未创建目标账本时，四入口均在 pending 前拒绝；文件、SQL、Root、持久化次数均不变。
- 无权限时先拒绝权限；已过期的实际文件继续占容量，不隐式删除。
- 精确释放一个测试记录后，用原服务／会话成功重试，不重新初始化或替换服务图。
- 已有账本在满额目录继续合法更新，物理文件数不增加，过期测试记录原字节保持。
- Links→Reset 与 API→Grants 两组不同账本争用最后一个空位。先行进程持有见证锁并在真实 pending 后 SIGSTOP，竞争者确认仍在等待；SIGCONT 后先行请求完成 current，竞争者重新检查实际完整来源并在 pending 前拒绝。根保留先行请求的动作及唯一一次修订，没有第二次 pending。

这是成功提交后的配额竞争测试，不是 SIGKILL 恢复测试，不能与之前十二次强杀混算。测试读取器只在明确测试元数据中携带原 files_cap，以准确重建同一个来源指纹；其他历史测试仍保持默认容量。

[预检记录](state-admission-capacity-evidence-2026-10-22/preflight-notes.md)保留测试辅助函数重复导入失败、修前四个实际产品失败及修后预检。最终结果以冻结清单和交付核对为准。

**已执行并通过：固定八条命令全部退出 0，冻结输入前后哈希一致。** 四种组合的四入口探针共 16 次拒绝均保持 current、文件数 8、持久化 0 且完整状态不变；容量专项每组 136 项通过。四组既有原生链接／重置／操作／API 分别 108／108／112／71 项，HMAC 拒绝 91 项保持。SQLite 两端的原普通 Links／重置 SQL／操作／API 分别 1575／21／953／200 项，物理余量 6 项通过。

两组竞争在四种组合中共 8 次真实 SIGSTOP／CONT，8 个等待者均在先行提交后以容量拒绝结束，根保持先行动作和唯一修订；本批 SIGKILL 为 0。两端 264 类公开契约、PHP7.2 目标静态分析和 859 个 PHP 文件语法通过，保留可选 turbo GLIBC 加载警告。

[交付核对](state-admission-capacity-evidence-2026-10-22/delivery-check.json)确认四个测试根、八个竞争子目录和两次私有 MySQL 全部清理，无在途任务。[库增量](state-admission-capacity-evidence-2026-10-22/library-delta.json)仅四个准入源码文件；原普通测试、原生兼容测试和受管 HTTP 示例字节保持。[公开清单](state-admission-capacity-evidence-2026-10-22/api-unchanged.json)三个文件与上一批字节完全一致，没有新类型、方法、参数或默认值。本批达到停止条件。

## 停止条件

本批通过后停止扩测。这里只处理物理文件数量准入；序列化字节、SQL／队列容量、系统磁盘／权限故障、其余写入者／维护、配置迁移、最终恢复启用及当前九版本完整门禁仍按原计划逐项验收。原 HTTP 503 保持开放，不在本批重复诊断。完整 F01／R1—R6 未完成；无提交、推送或发布。
