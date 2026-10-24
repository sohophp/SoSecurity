> 后续发现与修复：原生维护策略还需精确匹配实际账号表／字段，影子账号表反例及公开工厂验证见[后续专项](native-maintenance-factory-2026-10-22.md)。下文为首批实现证据，不包含该反例。

# 注册／地址变更的原生维护入口（2026-10-22）

当前源码确认：StateLifecycleRequests仅接收公开的request／confirm／cancel；Registration与AddressChange的maintain／rotate要求外层已有边界，缺少可直接调用、在pending前完成管理权限判断的原生入口。本批新增四个For入口，不将管理维护伪装成公开账号请求，不扩大恢复或工作进程交接权限。

## 原生调用及约束

已声明准确StateAccountConnection的服务现在支持：

```php
$target = $connection->maintenanceTarget('registration', 'maintain', 20, $after);
$permission = new StatePermission(
    'account.registration.maintain', $scope, $actor, $target, $sessionToken,
    ['account-maintainer'], 2, 300, true, false, ['totp', 'webauthn']
);
$result = $registration->maintainFor($accountPolicy, $permission, 20, $after);
```

这是接线示例，不是默认角色或自动审批。角色、当前会话和要求的方法由宿主明确指定；示例要求当前强认证，不能为迁就现有会话而降低宿主策略。地址变更使用address_change，轮换使用rotate／rotateFor。target绑定准确边界、站点、作用域、代际、账号策略、服务用途、动作、页大小和游标；更改页参数需要重新构造匹配权限。每页仍最多50条，旧方法继续保持原边界要求。

- 必须使用同一完整声明、会话登记器、时钟和绑定见证的StateAccountPolicy；必须显式提供非self权限及非空角色。没有推断管理身份，没有布尔回调代替实际会话／角色检查。
- 锁内从完整来源重建当前账号、密码身份指纹、因子状态和会话要求。缺少角色、当前会话无效或管理准入拒绝返回null，pending及原来源保持。旧角色会话在角色变化后不会被重新接受，需实际重新认证。
- 管理回调新增admission阶段。该阶段在见证锁内、SQL观察事务之外执行，必须只读且可重复；参数为局部副本，异常脱敏。其后再次校验权限和完整来源。SqlTransaction观察事务禁止宿主回调的规则保持，未放宽SQL准入。
- pending意图使用实际StatePermission及策略绑定，动作只增加account.registration／address_change的maintain／rotate四项。原SQL事务执行前及完成后均复核当前会话／角色，整个原生调用共享有界时间预算。
- 原有before／commit／complete管理回调、正文／checkpoint核对及清理语义保持。提交后失权返回account.completion_unknown并保留pending，不续办、不清除、不回滚已提交结果。连接拒绝嵌套的原生维护调用。
- StateAccountConnection::maintenance和StateAccountPolicy::maintenancePermission属于SDK接线辅助方法，不是可授予不可信回调的执行能力；宿主仍不得将任意业务闭包或外部权限依赖冒充完整声明。

## 证据与当前结果

证据目录：[native-maintenance-evidence-2026-10-22](native-maintenance-evidence-2026-10-22/)。新增tests/state-boundary/native-maintenance.php创建自己的SQLite或无TCP MySQL数据，建立全新账号和当前代际权限，不启用既有隔离账号、不交接旧工作进程。

新测试覆盖四个入口的无角色拒绝、当前管理拒绝、错误页参数、准确意图、成功检查；通过实际Registration请求生成待验证账号及私有记录，过期后原生清理；最后在完成回调中撤销真实账号角色，核对pending与完成未知。测试不尝试续办。普通维护完成权限的124断言同时回归。

初期测试编写的语法错误、错误的Grants接线、角色变化后误用旧会话及在SQL观察事务中调用宿主回调分别保留于first85至fifth85日志；它们未被算作通过。按现有保护约束修正接线和测试，未放宽会话指纹或SQL观察限制。static-first.log的纯函数误判通过给实际读取当前来源的方法标注phpstan-impure修正。

最终结果见completion.json：

- matrix.json：九版PHP共27条命令，26条通过、1条失败。八版SQLite原生维护各67断言通过；九版普通维护完成权限各124断言及271类型API反射通过。PHP7.2 SQLite原生测试在完整SQL来源检查时触发sql.timeout，未完成套件，native-72.log保留完整可得日志；未重跑该失败命令。
- mysql.log：自建无TCP MySQL控制器退出0，PHP7.2原生单调时钟运行时／PHP8.5各67断言通过。
- archive.json：最新ZIP、离线全新Composer非链接安装、两端vendor来源与原生／普通维护专项共8条命令通过。PHP7.2安装消费者通过不能抵销源码目录执行的失败。
- static.log：PHPStan退出0，已有可选turbo扩展GLIBC加载警告保留；没有删除检查或放宽类型。
- delivery.json：两端12份PHP语法检查通过，shell／Python入口及相关空白检查通过；五份运行时源码与安装副本摘要一致。测试摘要同时留存。

本批是专项验证，非九版全项目验收；PHP7.2此次超时及此前其他未解释超时继续保留。

## 兼容及范围

公开类型仍为271；只增加Registration／AddressChange各两个For方法、StateAccountConnection两个方法、StateAccountPolicy一个方法。api-before／api-proposal／api-diff／api-review记录逐项审查，既有签名全部保持。原方法调用不增加admission阶段；新阶段只适用于显式For入口。

本批只接入普通注册和地址变更维护。恢复、因子历史维护、跨代际工作进程、未知回执续办、最终恢复启用和完整F01仍未验收；不将它们写成已完成。未确定语义的OIDC迁移继续跳过。全写入者、通知／队列对账、其他原生工厂、稳定性失败及外部验收仍按计划保留。没有提交、推送、部署或生产访问，goal保持active。
