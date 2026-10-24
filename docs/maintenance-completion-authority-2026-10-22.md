# 注册／地址变更维护的完成权限（2026-10-22）

本批从当前维护源码确认并复现一个产品缺陷：Registration::maintain 在 SQL COMMIT 后管理权限已经撤销，仍返回成功。原始反例见 [before.log](maintenance-authority-evidence-2026-10-22/before.log)。相同缺口存在于两个服务的 maintain／rotate 四个入口；本次统一补齐完成时权限复核，没有实现未知结果续办。

## 修改

Registration 与 AddressChange 现在使用既有 SqlTransaction::run 的 afterCommit 回调，在实际提交和连接设置清理结束后执行 authorize(action, complete)。提交前仍使用原 commit 阶段授权及正文／checkpoint 校验；原 SQL、分页／容量预算、密钥、账号及 Outbox 生命周期不变。

完成阶段失权或授权依赖抛出异常时，固定返回 StorageException / account.completion_unknown，不返回成功计数，不包含原异常消息及 previous 链。事务已经提交，不能将此异常理解成回滚确认，不自动重试或恢复旧数据。本次没有增加继续未知操作、跨代际工作进程交接或最终恢复启用。

这是可见的回调契约收紧：管理回调须允许并实际检查 complete 阶段，保持只读、可重复。四个公开方法签名保持，候选契约不变。它不保证外部在线权限服务原子性，也不能代替全写入者保护覆盖或原生维护接入。

## 测试范围

新增 tests/maintenance-completion-authority.php 使用自行创建的普通注册及地址变更环境；注册新账号只是测试准备，不恢复已有隔离账号。两个服务、两个操作分别覆盖：提交时撤权、连接清理时撤权、提交前拒绝、正常授权、完成权限回调异常。共124项断言，核对完成状态未知／提交前回滚区别，已提交清理保留，宿主账号及 Outbox 数据不变。没有外部邮件投递。

证据目录：[maintenance-authority-evidence-2026-10-22](maintenance-authority-evidence-2026-10-22/)。矩阵同时运行原注册维护、地址变更维护及注册账本维护套件；MySQL仅通过自建无TCP实例。发行检查使用离线ZIP、全新非链接Composer安装，实际修改类的vendor来源另见 maintenance-origins.json；source.json记录当前源码与271类型API清单摘要。

实际结果（completion.json）：

- 已执行并通过：九版PHP7.2—8.5的36条SQLite专项命令（每版四套，8MiB预算）。新增完成权限测试每版124项断言。
- 已执行并通过：私有MySQL控制器退出0，两端各四套；容量11、注册维护105、地址变更维护95、新完成权限124项断言。
- 已执行并通过：九版271类型API反射、PHPStan、两端六份PHP语法、shell／Python语法与相关差异空白检查；公开候选未变。静态分析保留环境现有可选turbo扩展GLIBC警告。
- 归档检查11条命令中10条通过、1条失败；另两条实际修改类vendor来源检查通过，两个运行时文件摘要与安装副本一致。首次PHP7.2归档消费者的新测试在准备注册账号阶段触发sql.timeout，未执行完124项断言；原日志与非零退出码保留，未提升预算或重跑该失败命令。随后仅继续尚未运行的七条消费者专项，均通过，包括PHP8.5新测试。不能将该消费者验收写成全部通过。
- 最终核对 source.json 所列源码、测试及候选摘要未变化。本轮未执行全项目门禁，也未重跑暂缓套件。

## 未关闭项

本批不关闭既有PHP7.2维护／共享边界超时，也不解释上一批PHP8.5 MySQL并发超时。它们属于尚未定位的稳定性证据缺口。受保护原生维护、全用途写入者、通知／队列对账等仍需逐项核对。暂缓能力、未定义OIDC迁移及外部验收保持原边界；不宣称完整稳定版、全项目门禁或完整F01通过。

没有提交、推送、部署、生产数据库访问或删除既有数据，goal保持active。

## 后续有界诊断与时钟异常隐私修复

对首次失败的同一已安装消费者执行了一次有界诊断，32MiB和操作预算保持，命名空间观察函数原样返回真实 microtime。`consumer72-clock-diagnostic.json`／`consumer72-clock-detail.json` 记录退出0、新测试124断言通过；149658次观测，约13.86秒总测试历时，最大相邻间隔约0.297秒、未发现倒退。事件最多16条，栈不包含参数；临时观察器随执行清理。整个套件历时不等于单次SQL操作时间，这次通过不能解释或抵销首次超时。停止等价重复诊断。

检查相关错误路径时另复现 Deadline 在原生时钟异常时通过 previous 链暴露原异常详情；`clock-privacy-before.log` 是失败断言，含合成标记。现在只返回固定 storage.clock，删除该异常链，期限、回退时钟、数值验证和超时拒绝均不变。tests/deadline-clock.php 增强断言原异常链及详情不外泄，原有实际计时故障注入保持。

- `clock-matrix.json`：九版PHP各37项断言通过，包含无效数值、原生／墙钟异常、正常耗时及倒退拒绝。测试已在既有 bin/check.sh 中，无需重复新增入口。
- `clock-static.log`：PHPStan退出0，原环境扩展警告保留。
- `clock-consumer/archive.json`：最新源码ZIP、离线非链接全新消费者、两端Deadline的vendor来源与故障测试共6条命令通过，记录Deadline和两个维护服务源码与安装副本一致。该时钟专项通过不将前一维护消费者失败改为通过。
- `clock-source.json` 保留修复源码及测试摘要，公开API未改变；未再次运行无关SQL／Redis套件。

原生维护仍有独立实现缺口：StateLifecycleRequests目前只接受request／confirm／cancel，不能把管理维护当作普通请求接入；maintain仍要求已有激活边界。下一步须明确绑定管理调用者、准确页游标与操作、完整来源和只读准入，不能扩大现有动作白名单就宣称接入完成。
