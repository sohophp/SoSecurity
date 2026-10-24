# SQL 账号识别与权限证明查询合并（2026-10-23）

默认 MySQL 凭据签发仍有3000ms预算缺口。本批减少 SqlSchema 权限证明中的重复往返，不缓存权限、不减少结构校验、不提高预算。

原实现先读取 CURRENT_USER，再把 PHP 拼出的 GRANTEE 绑定到权限查询。现由同一查询中的单行派生结果提供有界账号标识，以 CONCAT／SUBSTRING_INDEX 构造权限匹配值，并把原始标识一并返回。PHP 仍执行原有严格格式校验：合法标识恰有一个 @，SQL 两段切分与原 PHP 捕获一致；不合法标识在使用权限结果之前拒绝。SQL 不拼入外部字符串；表名仍分别绑定参数。全局 partial_revokes 限制、触发器存在检查、后续完整结构检查及事务边界保持。

## 修改前对照

PHP8.5／私有MySQL8.0.46，分别在无触发器和真实触发器场景交替执行原方案与候选方案，每方案每轮100次、三轮。结果完全一致，3600项断言通过。每100次身份与权限证明的SQL数由200降为100；无触发器场景三轮累计耗时下降约10.11%，有触发器约15.66%。无触发器场景的第二轮候选耗时约高3.97%，并非每轮都更快。这是特定查询对照，不是整体签发吞吐量或稳定预算承诺。原始数据见 [performance.json](sql-visibility-query-evidence-2026-10-23/performance.json)，原源码、查询和探针均保留。探针回放改为读取同内容的 SqlSchema.before.php，不依赖后续已修改的工作树。

## 回归范围与兼容

新增 tests/sql-schema-principal.php，覆盖含点／连字符的合法账号、加号和额外 @ 的拒绝、32字节合法账号边界；账号均由私有MySQL控制器创建和删除。既有权限专项继续覆盖直接表／库／全局权限、缺权限、有／无触发器、角色、撤权和检查间隙。

已执行并通过：九版SQLite27项／3150断言；九版MySQL结构与复用18项／144断言；两端MySQL依赖2项／720断言；九版权限与账号格式18项／747断言；两端SQL审计和独立账本4项／194断言。合计69项定向程序、4955项断言，另有查询对照3600项断言。归档消费者6步、静态分析、API277及差异检查通过。静态分析可选turbo扩展的GLIBC加载警告保留，普通分析完成。

实际结果以 [verification.json](sql-visibility-query-evidence-2026-10-23/verification.json) 为准，inputs.json 绑定源码；两端审计和账本见 components.json；新消费者见 [archive-fixed.json](sql-visibility-query-evidence-2026-10-23/archive-fixed.json)。精确运行时变更见 runtime.patch。

权限要求、规范DDL、存储格式、公开API277和预算保持。错误提示的措辞整理不改变异常类别或原因码。其他MySQL／MariaDB版本未验证。暂缓交接、未知回执续办、最终恢复和完整F01没有执行，不以本批专项替代全项目验收。

随后在无本批并行测试负载时，用全新测试账号复验默认签发。3000ms预算保持，调用耗时3.048930487秒，PHP用户态／内核态CPU约0.333555／0.447671秒；首次actor的CredentialRegistry第109行期限检查失败，最终account.completion_unknown。后续列表、轮换、替换和撤销没有执行，也未续办未知结果。时间包含错误传播和清理，不能推断只差49ms即可完成整个流程，更不能据两次独立失败测量声明整体加速。默认签发缺口继续开放。见default-result.json／default-timing.json／default-run.log。历史失败、未齐门禁和外部验收继续保留，goal保持active；未提交、推送或部署。
