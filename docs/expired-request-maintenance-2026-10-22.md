# 过期恢复请求的原生维护（2026-10-22）

本批仅补齐密码恢复和邮箱恢复的请求历史清理／密钥重封装。当前源码原有maintain／rotate依赖外部已有激活边界，缺少独立的原生管理准入；普通维护也缺少提交清理后的权限检查。未实现或测试恢复确认、最终账号启用、跨代际工作进程交接或未知回执续办。

## 实际修改

- Recovery、MailboxRecovery各增加maintainFor／rotateFor，复用准确StateAccountConnection、账号表／字段匹配、当前会话／角色StateAccountPolicy及参数绑定的StatePermission。
- maintenanceTarget及原生意图白名单只增加这两个用途的maintain／rotate四项，不增加confirm、approve、resume或账号启用动作。
- 正常无权限或管理admission拒绝返回null且不写pending。原分页、正文认证、容量与保留期限、SQL事务及账号／Outbox用途隔离保持。
- 四个普通维护方法增加SQL提交及连接清理后的complete管理权限复核。失权或回调异常报告account.completion_unknown，不声称回滚已提交清理；原生入口同时复核当前会话／角色并保留pending。没有实现继续未知操作。

## 测试范围

扩展现有私有原生维护测试，使用Security公开工厂、真实RequestBudgets、SQL账号和当前会话：

1. 在测试中创建全新账号；只调用Recovery::request和MailboxRecovery::request生成请求历史，随后让请求过期。
2. 请求授权仅允许request和outbox.enqueue；恢复确认／取消不获授权。邮箱强审批回调一旦被调用就让测试失败。没有调用confirm、审批、启用或外部投递。
3. 四个用途的维护入口一起验证默认拒绝、错误页参数、回调引用参数隔离、嵌套拒绝、准确意图及真实过期记录清理。账号所有字段和Outbox记录在正常维护前后保持。
4. 分别在密码恢复和邮箱恢复的完成回调中撤销当前管理角色，确认返回未知并保留pending，不尝试续办。每个完整变体127项断言。

两端运行时、SQL与发行证据目录：[expired-request-maintenance-evidence-2026-10-22](expired-request-maintenance-evidence-2026-10-22/)。最终结果见completion.json：

- matrix.json：PHP7.2—8.5九版36条命令，35通过、1失败。密码恢复及邮箱恢复两种维护场景共17套完成各127断言，当前影子账号表拒绝回归九版各77断言通过，API反射九版271类型通过；PHP7.2密码恢复请求维护触发sql.timeout，未完成。新增逐命令父进程单调耗时；该失败进程约4.63秒，但没有失败当次时钟值，不据此断言根因。
- mysql.log：自建无TCP实例控制器退出0，PHP7.2原生单调时钟运行时／PHP8.5各两个场景，共四套各127断言通过。
- archive.json：最新ZIP、离线全新非链接Composer安装、两端vendor来源与两个运行时场景共8条命令，7通过、1失败；PHP7.2密码恢复请求消费者在持久化预算检查时拒绝。保留原日志，仅继续尚未执行的消费者命令，没有重跑失败项。
- static.log：PHPStan退出0，原可选turbo扩展GLIBC警告保留。
- completion.json：两端12份PHP语法、shell／Python入口及相关空白检查通过；五份运行时源码与安装副本摘要一致，测试摘要留存。

另一次[有界时钟诊断](php72-clock-diagnosis-2026-10-22.md)未复现之前的超时，不能抵销本批或历史失败。当前不是全绿稳定版或全项目验收。

## 兼容与未完成

类型清单仍为271；只增加两个服务的四个方法，原有公开签名保持，候选差异经api-before／api-proposal／api-review核对。新的For方法使用admission阶段；普通maintain／rotate的管理回调现在还须支持complete阶段，并保持只读、可重复和当前授权检查。这是可见契约收紧。

本批不关闭完整恢复链路、因子历史维护、全写入者覆盖、通知／队列对账、PHP7.2未解释超时或任何外部验收。全量脚本含暂缓范围，本轮仅运行明确选中的隔离测试。没有提交、推送、部署或生产访问，goal保持active。
