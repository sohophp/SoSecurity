# 显式完整来源的自定义凭据委托策略

## 本次产品行为

新增 `Authorization\SnapshotPolicy`，接收专用 `SnapshotEvaluator`，将可信、纯计算、可重复调用的策略显式关联到受保护账号图正在使用的同一个 `SqlStateSnapshot` 对象，以及64位小写十六进制的实现／静态配置摘要。它不是把所有普通自定义策略自动视为受保护策略；普通 PolicyProvider、不同的SQL来源对象、不同身份提供器或未准确覆盖的审计日志继续拒绝。

策略使用的持久权限数据必须属于这个完整SQL来源，更新者必须共享原生状态边界。配置摘要必须包含实现版本和影响决策的静态配置，不能以固定占位字符串替代实际配置绑定。声明不是PHP沙箱，不允许回调依赖未覆盖数据库、外部服务或执行外部效果。评估器不得自行查库：selectors声明需要的准确行，SDK从完整摘要中捕获这些行并核对当前见证；decide只接收这些事实、已捕获的账号与资源及静态配置。最多8行、每行16列且64KiB、合计256KiB，沿用SQL来源的预算；本入口拒绝分页和计数选择器。空选择器仅用于纯静态／已捕获账号策略，也复核完整图。外层期限在回调边界复核，不能中断任意PHP代码。需要其他来源的提供器仍须先建立对应的准确来源契约。

凭据原生委托支持不带审计和准确SQL审计两种组合。入口在准入、效果前和最终返回阶段重新判断策略，并在策略返回决策后重新观察完整状态图；回调原始SQL写入被检测时，不采用其为新基线。原始违规写入不会被伪装成已经回滚，测试只记录并清理其自建环境。

不带审计的策略拒绝在pending前结束。带审计的明确策略拒绝仍采用已有流程：只写拒绝审计、完成见证，再抛出拒绝。已经完成业务后的最终撤权不返回凭据，不恢复已完成状态，也不继续未知结果。回调异常及重入错误脱敏后默认拒绝。

## 接入契约

```php
$declaredPolicy = new \SoSecurity\Authorization\SnapshotPolicy(
    $capturedFactsEvaluator,
    $sameCompleteSqlSnapshot,
    hash('sha256', $reviewedImplementationAndConfiguration)
);
$authorizer = new \SoSecurity\Authorization\Authorizer(
    $sameIdentityProvider,
    $declaredPolicy,
    $optionalExactlyCoveredSqlAuditLogger
);
```

可执行接入样例见 [native-maintenance.php](../tests/state-boundary/native-maintenance.php)：selectors选择目标账号角色，decide只读取facts中的角色及已捕获账号。样例故障注入故意违反纯计算约定，仅用于证明拒绝，不作为生产实现。

通过已有 `management_authorization` 服务注入此Authorizer，再用准确StateAccountPolicy构造原生凭据服务；没有新配置开关。无审计的显式策略增加请求守卫操作 `management_current`，metadata提供原始 `operation`、`phase=admission|before|return` 及原请求元数据。带审计继续使用 `audit_current`。这些复核必须只读且可重复，不得再次消费CSRF或请求预算。

公开类型从275增加至277，新增 SnapshotPolicy、SnapshotEvaluator；原有275个类型的签名保持。临时的276类型包装方案未作为最终接入交付，其构造参数已改为专用评估器；普通decide明确拒绝，仅原生捕获路径可求值。具体清单复核见[api-review.json](captured-policy-evidence-2026-10-23/api-review.json)。本次接入限定凭据委托，不能据此宣称所有业务授权接口已支持任意自定义提供器。

## 证据与未关闭事项

[原型证据](native-custom-policy-evidence-2026-10-23/)仅属于已被替代的普通策略包装方案；即使阶段测试通过，也不能证明它使用了被捕获的数据。所有原型失败和源码摘要保留。修订版见[当前证据目录](captured-policy-evidence-2026-10-23/)，九版定向矩阵57条命令中55条通过、2条PHP7.2失败（一次明确时钟倒退，一次脱敏后的认证不可用，根因未定）；静态分析通过并保留可选turbo扩展GLIBC警告。私有MySQL两端14/14、离线ZIP与全新消费者14/14通过，实际vendor源码摘要一致且自建资源已清理；汇总见 [summary.json](captured-policy-evidence-2026-10-23/summary.json)。MySQL的PHP7.2使用既有真实单调时钟测试运行时，消费者使用默认PHP7.2运行时；一次通过不抵销矩阵失败。这些都是定向验证，不作为完整候选通过。功能测试沿用原生专项的凭据30秒／审计10秒配置；没有改变生产默认预算，也不声称默认预算问题已解决。

原型中匿名类名引入部署路径差异的问题已修正；指纹只使用明确的实现／配置摘要与来源指纹。测试样例的无效写入、PDO异常模式、未知结果原因链及普通提供器负例也均保留修正记录，未删除保护。

MySQL默认预算、PHP7.2时钟倒退、其他原生业务入口／提供器和最终候选核对仍开放。暂缓的跨代际工作进程交接、未知回执续办、最终账号恢复以及依赖它们的F01不在本次执行范围。没有提交、推送、部署或外部投递。
