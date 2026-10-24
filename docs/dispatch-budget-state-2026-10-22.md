# 受保护通知工厂与发送预算的完整边界

## 已复现缺陷

受保护账号通知工厂原先仅验证SendBudgets的站点、时钟和共享存储类型，可以接受不在见证来源内的独立文件库。队列和账号账本受保护，而发送额度及每通知发送状态可以写到来源之外，不能作为完整保护图使用。[before.log](dispatch-budget-state-evidence-2026-10-22/before.log)保留修复前的拒绝断言失败。

首个测试另有自建空目录未被旧测试清理器递归处理的错误；已改用测试本来拥有的预算目录，并仅删除该次失败遗留的两个确认为空的自建目录，没有清理其他任务资源。该清理错误不替代前面的产品反例。

## 修复与兼容

SendBudgets新增validateState：保护模式要求准确站点、同一个Clock实例以及同一StateBoundary的WitnessedStore；允许有界NamespacedStore外层包装。StateAccountConnection提供validateSendBudgets，SqlOutbox提供validateDispatchBudgets。内部SqlStateAccess::isProtected只查询已有PDO注册，不授予执行权限。

Dispatcher在构造和每次sendNext开始时检查预算声明，尚未调用工作进程、通知或传输回调。已注册为受保护PDO的队列若缺少准确StateAccountConnection，会拒绝；较早构造的普通Dispatcher不能在PDO后来变成受保护连接后继续沿用旧组合。

注册、地址变更、密码恢复、邮箱恢复及因子通知的五类dispatcher工厂，将自身已有的StateAccountConnection传给工作队列。它们使用相同预算校验，原始状态执行限制保留。未受保护的普通模式仍使用既有共享存储规则，不要求新增声明。

```php
// 包装原有存储，保留目录、命名空间、密钥及额度数据。
$protectedBudgetStore = $boundary->protect($existingBudgetStore);
$budgets = new SendBudgets($protectedBudgetStore, $site, $pseudonymKey, $policies, $clock);
$sender = $service->dispatcher($worker, $budgets, $templates, $transport, $workerAuthority);
```

保护模式行为收紧：独立存储、不同边界及未明确包装的原始FileStore不能作为发送预算声明；即使原始FileStore已绑定物理边界，也应通过同一boundary的protect保留其原始映射，不要为了接入而新建命名空间或清空计数。普通方法签名和既有参数不变。公开类型保持272，公开候选增加三个方法；SqlStateAccess内部辅助方法不属于公开类型清单，见 [API复核](dispatch-budget-state-evidence-2026-10-22/api-review.json)。

## 验证范围

新原生组合测试使用实际账号／会话及完整SQL、文件、密钥和见证来源：五类工厂都拒绝独立预算库、接受同边界包装及命名空间包装；构造不执行授权／传输回调，不改变来源或见证。另检查错误边界、缺少连接声明的直接Dispatcher，以及PDO注册前创建的旧Dispatcher在注册后拒绝。

之后只发布一条新因子通知，在同一个明确外层StateBoundary内执行首次发送，使用进程内模拟传输，验证预算文件、通知账本和队列最终与见证摘要一致。没有网络调用、重投、未知回执续办或跨代交接。恢复与邮箱恢复仅构造工厂，其执行回调设置为抛错桩实现，未调用恢复、审批或最终账号启用。

这证明的是完整来源内的一次本地首次发送组合；外层权限仍由宿主明确提供，不等于自动完成原生Dispatcher的当前账号权限入口，也不替代真实SMTP验收。

[证据目录](dispatch-budget-state-evidence-2026-10-22/)记录九版定向矩阵、隔离MySQL、离线非链接Composer消费者、API和静态检查。旧的自定义1秒配置失败、PHP7.2未解释时限失败继续保留，不由本批通过覆盖。

完整原生发送授权、可重试拒绝流程、其他剩余产品项和外部验收仍开放；暂缓功能保持隔离，goal保持active。无提交、推送、部署、真实投递或生产数据库访问。

最终本批结果：九版定向矩阵36/36通过（新组合每版55断言，另含普通工厂、普通因子通知及API检查）；两端私有MySQL四套通过；归档／安装／来源及两端三个消费者场景10/10通过；语法与入口检查29/29通过。PHPStan无错误，可选turbo扩展GLIBC警告保留。十个修改运行时文件的最终源码与归档消费者SHA256逐项一致。精确命令与退出码见matrix.json、archive.json、completion.json、result.json；不是完整项目验收。
