# 原生操作授权和签名链接的捕获权限策略

本批继续非暂缓产品接入。修复前，与准确身份及完整 SQL 来源匹配的 `SnapshotPolicy`，仍被公开 `operations($stateAccountPolicy)`、`signedLinks($stateAccountPolicy)` 工厂以 `configuration.state_permission` 拒绝；两个反例日志保留在[证据目录](native-captured-permissions-evidence-2026-10-23/)。不将历史完成记录当作当前通过。

## 行为与边界

两个工厂现在接受准确身份提供器、同一个 `SqlStateSnapshot` 对象和无审计回调的 `SnapshotPolicy`，原有纯 `RolePolicy` 保持。准入、效果开始前及最终返回前重新捕获当前权限事实并检查对象／字段。执行结果面对提交后的权限；合法业务造成失权时，拒绝交付结果，保留已提交业务与证明消费，不自动退款、回滚或重放。效果阶段拒绝仍保留未知结果及 pending，不续办。

沿用已有 `SnapshotEvaluator` 和捕获事实契约：最多8行，每行16列／64KiB，合计256KiB；准确主键，不接受分页或计数选择器。策略实现及静态配置摘要必须真实绑定部署配置。回调只能做有界纯计算，不得自行查库或访问外部服务；这不是 PHP 沙箱。执行前后检查同一个30000ms整体期限，不能中断任意PHP回调，也不延长原期限。原始回调错误脱敏后拒绝。

不同身份源、不同 SQL 来源对象、普通自定义 `PolicyProvider` 和带审计回调的授权器继续构造拒绝。构造及新匹配方法均不执行权限回调、不读取会话或授予权限。匿名链接验证／执行继续使用准确签名目标持有者能力；自己的操作取消仍保持原身份与请求保护语义。地址变更内部使用的普通 Grants 仍有单独的 RolePolicy 准入限制，本批没有将其标为支持。

只修改四个运行时文件：`Auth/IdentityState.php`、`Auth/SessionRegistry.php`、`Operation/Grants.php`、`Link/Links.php`。类／接口清单仍为277；公开 `SessionRegistry::operationSnapshotPolicy(Authorizer, StateAccountPolicy): ?SnapshotPolicy` 是有意的单个新增方法，其余公开签名不变。[API逐项审阅](native-captured-permissions-evidence-2026-10-23/api-review.json)记录差异，候选没有用反射输出整体覆盖。历史268清单不改写为当前值。默认配置、持久格式、SQL DDL、强认证要求和事务边界保持。

## 当前验证状态

冻结检查已执行：116项外层检查115通过、1失败；其中MySQL控制器运行17个独立PHP场景全部通过，展开后共132个检查程序131通过、1失败，已通过场景合计28016项断言。九版普通 operations／links／authorization／snapshot-policy、两个新工厂正常及默认拒绝；两端字段／异常／重入／效果与返回拒绝、原RolePolicy正反例；PHP8.5六项真实31秒回调超时及MySQL8.0.46十七场景均执行。两端API277和PHPStan通过（保留既有可选turbo扩展GLIBC加载告警）。唯一失败为PHP7.2 changed场景，认证预设阶段发生计时钟倒退，尚未进入本批工厂；没有重试覆盖。归档消费者结果另列，未纳入上述计数。

冻结矩阵之后只删除bin/check.sh中误重复插入MySQL分支的一组SQLite调用；shell语法通过，完整门禁未执行。原输入不改写，[最终输入](native-captured-permissions-evidence-2026-10-23/final-inputs.json)及[单独脚本差异](native-captured-permissions-evidence-2026-10-23/gate-delta.json)保留；运行时源码与矩阵一致；PHP测试的后续摘要断言另列，不改写原冻结输入。检查命令、逐项退出码和日志写入[verification.json](native-captured-permissions-evidence-2026-10-23/verification.json)，冻结输入为[inputs.json](native-captured-permissions-evidence-2026-10-23/inputs.json)。初步日志与冻结验证分开，不将其累计为最终通过。

## 实际发行消费者

Composer ZIP、无网络全新path包安装、PHP7.2／8.5实际vendor加载来源、四个运行时文件的源码摘要及15个包内SQL资源摘要一致。消费者使用包内resources／examples运行SQLite与控制器自建MySQL，未读取源码树DDL。[归档记录](native-captured-permissions-evidence-2026-10-23/archive.json)保留ZIP摘要及实际依赖锁定清单。

18个外层步骤16通过、2失败；将两组MySQL控制器各自四个PHP程序展开后，24个检查22通过、2失败，已通过场景合计5779项断言。PHP8.5全部通过。PHP7.2 SQLite grants-changed在捕获到sql.timeout后因期望authorization.denied而失败，原始超时消息未记录，原因未定；PHP7.2 MySQL links-normal则明确保留计时钟倒退的原始StorageException。PHP7.2 MySQL grants-normal及grants-changed通过，不能覆盖两个失败或当作原失败修复。没有等价重跑／时钟替换／预算放宽。与冻结矩阵中的预设时钟失败分开保留。

消费者临时目录及控制器自建资源已清理，运行时源码保持；消费者使用原冻结测试输入，后续摘要断言另列；[最终核对](native-captured-permissions-evidence-2026-10-23/final-verification.json)和[消费者计数](native-captured-permissions-evidence-2026-10-23/consumer-summary.json)保留。完整门禁、暂缓恢复链路、真实宿主HTTP和外部投递未执行。

## 收尾的测试补充

复核发现只断言pending不足以证明尚未写入证明，因此仅在测试中新增完整来源摘要断言：效果拒绝／超时时摘要不变，返回前拒绝时已有证明写入导致摘要改变。[补充差异](native-captured-permissions-evidence-2026-10-23/supplement-input-delta.json)与原测试输入分开。PHP8.5 SQLite按两组件各effect-deny／budget-effect／return-deny共6项全部通过、304项断言，包括两次真实31秒回调超时。没有改运行时源码或重跑失败场景，不把补充绿色结果替换为整套通过。

## 仍然开放

本批不是完整候选验收。旧 PHP7.2 墙钟倒退证据、原生默认3000ms签发失败及 pending 均保留；本次不重复不相关的默认签发，也不改预算／时间源来得到绿色。地址内部自定义策略及其余非暂缓入口仍须独立核对。完整 F01、跨安全代际工作进程交接、回执未知续办和最终恢复启用继续暂缓；真实宿主、OIDC／SMTP、实体设备、远端 CI 和独立审查未执行。

未提交、推送、部署或对外投递。保留已有环境、数据及未提交改动，仅清理测试自行创建的资源。已有相同范围 goal 继续为 active，未标记完整计划或稳定版完成。
