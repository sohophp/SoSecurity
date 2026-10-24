# 原生维护工厂与准确账号映射（2026-10-22）

复核上一批新增原生维护入口，发现权限策略与实际账号连接的绑定仍不完整。本批实际修复这项新入口缺陷，并验证Security公开工厂接线；不是仅补充文档。

## 反例与修复

在同一完整SqlStateSnapshot中声明真实账号表和一份影子账号表。先使用真实密码登录取得管理会话，再将账号复制到影子表，并通过当前边界撤销真实账号的管理角色。真实账号策略拒绝维护，影子表策略却仍能通过会话／角色检查，并被维护连接接受。

`mapping-before.log`保留实际失败：Different account mapping accepted for native maintenance。这不是恢复备份或恢复被隔离账号；只是自行创建的两张测试表展示身份来源错配。

现在StateAccountConnection保留已验证的SQL来源对象、账号表及字段映射，调用maintenance前使用StateAccountPolicy::maintenanceContext作纯配置匹配。SQL来源对象或账号表不一致、八个认证字段映射不一致时，返回configuration.state_connection；发生在权限查询、回调和pending之前。原本的同见证、同会话登记器、作用域、时钟与准确动作／分页参数检查全部保持。新辅助方法先检查映射数量，避免无界遍历；没有新增类型。

## 工厂与边界测试

扩展tests/state-boundary/native-maintenance.php，三条路径共享真实服务图：

- direct：原直接构造路径；
- factory：先通过同一Security实例建立StateAccountPolicy与stateAccountConnection，再调用registration／addressChange公开工厂；使用真实RequestBudgets和独立文件预算目录；
- factory mapping：在上述工厂图中加入影子账号表反例，确认正确策略拒绝、错配策略抛配置错误，见证不变。

管理回调声明引用参数并修改局部action／phase／scope，成功后的准确意图仍保持；回调还尝试嵌套同一原生入口，必须被拒绝。正常路径继续覆盖真实过期记录清理、普通拒绝不写pending、提交后撤权保留pending，不执行续办。最终每条完整套件75项断言。

首轮工厂接线错误地向request_budget提供普通闭包，被现有类型校验拒绝（first85.log）；随后改用正式RequestBudgets，未放宽工厂保护。普通直接构造支持回调的契约保持，工厂仍要求正式预算对象。

## 本地证据

目录：[native-maintenance-factory-evidence-2026-10-22](native-maintenance-factory-evidence-2026-10-22/)。

最终结果见completion.json：

- matrix.json：九版PHP共36条命令，35通过、1失败。直接／工厂／错配三条运行时路径中26条完成各75断言，九版API反射通过；PHP7.2源码目录的mapping套件触发sql.timeout，未完成。
- mysql.log：私有无TCP MySQL控制器退出0，两端各工厂及错配两套，共四套各75断言通过。
- archive.json：ZIP归档、离线全新非链接Composer安装、两端vendor来源和三套测试，共10条命令，9通过、1失败。PHP7.2的mapping消费者触发sql.timeout，原日志保留；只继续原先尚未执行的PHP8.5检查，未重跑失败命令。
- static.log：PHPStan退出0，保留既有可选turbo扩展GLIBC警告。
- delivery.json：两端六份PHP语法、shell／Python入口及相关空白检查通过；当前运行时与已安装归档的五文件摘要一致，修复源码／测试／API摘要留存。

两次PHP7.2错配套件超时均保留非零退出码，没有增加操作预算或重跑以获取绿色结果。其余通过不能抵销这些失败，当前不是全绿稳定版验收。

API仍为271类型，只新增StateAccountPolicy::maintenanceContext；api-before／api-proposal／api-review保留逐项审查，其他已有签名保持。新原生测试入口使用与专项一致的32MiB测试运行预算；原普通账号8MiB套件保持，产品操作预算未改。bin/check.sh分别接入直接、工厂、错配三个变体；本轮不运行含暂缓功能的完整脚本。

## 范围与剩余项

本批不实现恢复／因子历史维护，不改跨代际工作进程、未知回执续办或最终恢复启用。全部写入者、通知／队列对账、其他原生工厂、未解释超时和外部验收仍未关闭。旧专项不包含本次影子账号表反例，不能作为当前修复的完整替代证据。没有提交、推送、部署或生产访问，goal保持active。
