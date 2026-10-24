# 因子通知的完成权限与原生维护

本批复现 FactorNotices::maintain 在真实 COMMIT 后管理权限失效仍返回成功，失败保留在 [before.log](factor-notice-maintenance-evidence-2026-10-22/before.log)。相同提交边界存在于轮换与通知读取。它们不依赖工作进程跨代交接、未知回执续办或最终账号恢复启用。

## 修改

1. maintain／rotate 在 COMMIT 和连接超时设置清理完成之后调用管理 guard 的 complete 阶段；失败为固定 account.completion_unknown StorageException，无原始异常链，不撤销已提交清理、不自动重试。
2. notificationForDispatch 在完成阶段重新检查读取权限、当前真实账号指纹及通知期限；完成期间角色／账号字段变化或到期时不返回私密通知。账本读取可能更新观察状态，因此失败也保留明确的完成不确定语义。
3. Outbox 初始化／入队的权限适配器改传局部字符串副本，兼容按引用接收参数的 guard，同时不让 guard 改写后续调用的 scope。原生测试触发了旧实现将字符串字面量传给引用参数的异常。
4. 构造函数增加可选 StateAccountConnection，新增 maintainFor／rotateFor。准确账号表与字段、PDO、仓储、站点、scope、代际、时钟、策略、会话和完整来源沿用现有连接校验。StateAccountConnection::maintenanceTarget 的 purpose 增加 factor_notices；见证只新增 account.factor_notices.maintain／rotate 两个准确动作。

## 原生调用

使用与实际认证策略相同的 StateAccountConnection 作为 FactorNotices 构造函数最后一个参数。调用者从实际当前会话构造 StatePermission，动作使用 account.factor_notices.maintain 或 account.factor_notices.rotate，目标必须来自：

```php
$target = $connection->maintenanceTarget('factor_notices', 'maintain', $limit, $after);
$result = $notices->maintainFor($policy, $permission, $limit, $after);
```

permission 必须绑定相同动作、scope、target、实际会话及非空维护角色，不能用自助权限代替管理权限。管理回调增加只读 admission 阶段；拒绝在 pending 之前完成。完成期间失权时见证保持 pending，不提供续办。受保护 PDO 的普通入口仍要求已有准确活动上下文，未移除 SqlStateAccess 门槛。

publish 仍必须参加宿主已经开启的同 PDO 事务，返回的通知 ID 在宿主 COMMIT 前只是暂定值。本批测试一度遗漏宿主事务，原有保护正确拒绝；[native-after.log](factor-notice-maintenance-evidence-2026-10-22/native-after.log) 保留该失败，随后仅修正测试的事务用法，没有放宽生产边界。

## 兼容及范围

公开类型保持 272；候选变更仅 FactorNotices 的末尾可选参数和两个 For 方法，已逐项核对。原通知数据、轮换格式、Outbox 身份及限额保持。权限回调需要处理新增 complete 阶段；原来依赖底层异常或只允许提交前阶段的宿主需适配，不能把该变化当作透明行为。

普通通知读取得到末端权限复核，但本批没有补齐独立原生 Dispatcher／Outbox 认领、外部发送或结果对账。没有进行任何实际 SMTP 投递，既有通知测试使用进程内模拟传输。完整恢复链、先前超时和外部验收继续开放。

## 验证证据

证据位于 [factor-notice-maintenance-evidence-2026-10-22](factor-notice-maintenance-evidence-2026-10-22/)。matrix.json 记录九版各命令的实际退出码与持续时间；普通专项覆盖完成时失权、连接清理时失权、异常、账号变化、通知到期、引用参数及成功路径；原生专项覆盖角色拒绝、管理拒绝、参数绑定、嵌套拒绝、真实通知清理、准确意图、账号／Outbox 不变及完成时失权保留 pending。已有通知／轮换／模拟传输用例和原生注册／地址维护作为相关回归检查。

首轮私有 MySQL 中，普通专项遗留了自己创建的表，导致随后全新原生测试的建表拒绝；mysql.log 保留失败。新专项现在清理自己的五张表，修后证据单独写入 mysql-owned-cleanup.log；不修改旧测试公共环境，不访问业务库。

最终结果：九版矩阵45/45命令通过；普通专项每版95断言，原生因子通知维护每版102断言。修后私有 MySQL 控制器退出0，两端各普通／原生两套通过。archive.json 记录归档、全新离线非链接 Composer 消费者、两端实际 vendor 来源和三套场景，共10/10通过；安装的三个运行时文件与最终源码摘要一致。static-final.log 的 PHPStan 退出0，保留既有可选 turbo 扩展 GLIBC 警告。completion.json 的两端PHP语法、shell／Python入口及相关空白检查13/13通过。原生注册／地址维护回归和272类型反射均在本批九版矩阵内通过。

本批是局部产品实现及验证，不是完整稳定版验收。没有提交、推送、部署或生产数据库访问，goal 保持 active。
