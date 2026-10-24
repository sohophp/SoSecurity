# Outbox 首次认领及只读结构校验

现有 claim／claimMessage 会同时考虑到期租约，不能用于本次排除续办的保护模式接入。本批新增 claimInitialMessage，仅选择指定的、从未尝试且没有手动重试的 pending 消息；检查可用时间、正文完整性、消息期限和聚合顺序。成功时第一次创建租约，重复调用或租约到期后调用均拒绝，不重新排队、不接管、不发送、不处置回执。

保护模式通过 initialClaimTarget／claimInitialFor 接入实际 StateAccountConnection 和当前账号权限。目标绑定准确来源、策略、密钥配置、scope、生产者、工作进程和消息 ID，动作是 outbox.claim_initial。准入在只读 SQL 观察单元内检查候选；authority 的 admission／admitted 回调在观察事务之外执行，只收到局部参数和有限元数据。账号角色失效、权限错配、嵌套调用和旧原始入口均拒绝。提交后权限失效保留 pending，不返回可用认领令牌，不尝试续办。

完整入口使用现有策略的时间预算，返回前再次检查消息与租约期限。超时保持默认拒绝。本批没有增加预算。普通入口事务前后权限检查、签名及账本完整性保护保留。

初测复现：原 SqlSchema 使用 PRAGMA table_info，观察单元不允许该命令，导致合法只读结构检查失败。修复为带参数和结果预算的 SQLite 表值元数据 SELECT。观察单元仍拒绝写入、原 PRAGMA 命令和宿主回调；没有扩大 SQL 放行规则。新增损坏索引、部分索引、额外列、触发器、main／temp 元数据同名对象及资源边界测试。

兼容变化：公开类型保持272，新增 StateAccountConnection 两个方法和 SqlOutbox 三个方法，无既有签名替换。候选差异见 api-review.json。SQLite 私有表的索引元数据最多128项、索引名最多256字节，元数据模块同名对象被拒绝；标准发布结构通过。MySQL结构检查逻辑未改。

证据位于 [本批证据目录](outbox-initial-claim-evidence-2026-10-22/)。普通测试不执行发送或租约接管；四进程竞争验证只有一个首次认领成功。原生测试使用真实新账号、会话、角色和完整来源。schema 专项验证观察单元限制。matrix.json 记录九版逐命令退出码；archive.json 记录离线非链接 Composer 全新消费者、实际 vendor 来源及四个修改运行时文件摘要。初始观察拒绝保留在 native-initial.log／expiry-initial.log，未删改失败证据。

已知未关闭问题：隔离 MySQL PHP7.2／8.5 普通专项均通过，但两端原生 normal 在效果回调中触发 outbox.timeout；mysql.log／mysql85.log 保留完整失败，不扩大预算、不重试覆盖。其他运行时或消费者通过不能关闭该失败。首次认领不代表完整 Dispatcher 接入或完整产品验收；发送与处置链、历史未解释超时、暂缓能力和外部验收继续保留。无提交、推送、部署、外部投递和生产数据库访问。

最终本批结果：九版 SQLite 专项72/72通过（含普通23、原生正常63、过期29、预算28、只读结构31、四进程竞争17断言及既有通知/API检查）；归档消费者10/10通过；两端语法及入口检查22/22通过；PHPStan无错误，可选 turbo 的 GLIBC 加载警告保留。MySQL 两端普通／过期／预算拒绝共6套通过，正常原生2套失败。两次正常失败均未重复执行；仅补执行控制器提前退出而未运行的过期／预算场景。精确结果见 result.json；goal 保持 active。

后续澄清与修复：[写入前预算复核](native-operation-deadline-2026-10-22.md)记录原1秒测试配置和产品既有10秒默认值的区别，并在写 pending 前检查已耗尽的同一预算。两端 MySQL 默认配置已另行通过；原1秒失败仍保留，不由默认配置通过覆盖。
