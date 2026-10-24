# Webhook 请求权限与引用参数边界修复

本批检查原计划中的 Webhook 保护模式余项时，独立复现并修复两项现有 Verifier 缺陷。运行时只修改 `src/Webhook/Verifier.php`，未将保护模式完整接入或稳定版验收标为完成。

## 实际修复

1. 请求权限只在密钥查询前检查；查询期间撤权后仍返回有效证明。现在成功路径返回前再次执行请求权限检查，并在检查后重新检查时钟、I/O预算和签名期限。最初拒绝仍不查询密钥；后期拒绝抛 `webhook.denied`，回调异常固定为 `webhook.request_unavailable` 且不保留原始异常。
2. 密钥及请求回调的引用参数可以替换内部固定 Endpoint。现在向回调传递局部变量；请求检查也使用局部 Request 参数，不能替换当前待验证请求。测试验证固定端点对象、证明端点和正文摘要均保持原始输入。

第一项原始失败为 `Withdrawn request authority accepted: first-key`；第二项原始失败为固定端点对象不一致。没有通过删除断言或放宽拒绝逻辑取得通过结果。

**证据更正（原日志保留）：** 本批旧测试在第二轮验签中撤权，实际发生在事务开始前，只证明提前拒绝及无接收行，不能证明 INSERT 后回滚。后续已把撤权移至第三轮验签，并断言 INSERT 确实发生且最终回滚，见[原生接收专项](webhook-native-receive-2026-10-22.md)。没有改动SQL结构或事务实现。未知提交、旧安全代际交接、最终账号恢复不在本批测试范围。

## 验证及证据

证据目录：[webhook-request-evidence-2026-10-22](webhook-request-evidence-2026-10-22/)。

- `before.log`、`reference-before.log`：修复前实际失败。
- `matrix.json`：PHP7.2、7.3、7.4、8.0—8.5九版共36条命令退出0。每版包括请求权限43断言、时钟异常42断言、既有SQL接收191断言，以及900条Python独立原始协议向量。新增最后一次时钟检查也已纳入异常测试。
- `mysql.log`：私有无TCP MySQL，PHP7.2原生单调时钟运行时／PHP8.5分别通过请求43、时钟42、原有接收191、并发25及事务所有权16断言。该并发测试的强杀仅针对Webhook接收提交，不涉及暂缓的安全代际或恢复工作。
- `archive.json`：实际ZIP归档、离线全新Composer安装、消费者反射确认代码来自vendor副本，两端各运行权限／时钟／既有接收测试，10条命令退出0。归档未包含本地测试和证据目录。消费者中的Verifier摘要与本地运行时一致；这是本批运行时代码的归档检查，不是整个发布候选冻结。
- `static.log`：PHPStan按项目配置分析退出0，保留现有turbo扩展GLIBC加载警告。
- `final-checks.json`：两端公开API检查通过，仍为268类／接口；没有重写契约。新测试最后增加私有MySQL所有权前置校验，两端SQLite重新通过；缺少自建socket／标记时在构造PDO前拒绝，原始拒绝日志保留。该最后修改只涉及测试入口，不影响已验证的运行时代码和SQL断言。

新增测试接入 `bin/check.sh` 的SQLite及MySQL路径，以及 `tests/mysql_check.py --webhook-inbox`。脚本语法检查通过。没有运行包含暂缓流程的完整检查脚本；上述定向检查不能称为全项目验收。

## 兼容变化与未完成项

公开方法签名保持。成功验签时 `requestGuard(Endpoint, Request)` 从一次变为两次调用；SqlInbox本身会重复验签，因此普通 SqlInbox 一次成功接收执行三轮验签，通常有六次请求检查（原文“四次”为计数错误）。宿主回调须重复安全且读取当前权限；一次性入口预算放在外层，不能在该回调中重复消费不可重用证明。无效签名等提前拒绝路径不保证第二次调用。回调通过引用修改参数不再替换组件上下文。已有提供器密钥重复读取行为保持。

这些修复不提供外部权限系统的原子性。完整受保护Webhook仍需显式同PDO来源覆盖、密钥配置权威、原生准入、接收及处理写入者边界；不能把现有工厂独立构造Verifier／SqlInbox／SqlProcessor当作已经接入StateBoundary。旧ApiKeys、维护等计划余项、PHP7.2历史维护超时、暂缓项及外部验收继续保留。goal保持active；没有提交、推送、部署、生产访问或撤销原有改动。

English compatibility: successful verification now invokes the request guard both before key lookup and before returning a proof. Guards must be repeatable and read current authority. Charge one-shot transport budgets outside this callback. Reference parameters can no longer replace the verifier endpoint or the request being verified. Public signatures remain unchanged; protected-state integration and full release qualification remain incomplete.
