# 并发租约、持有者与恢复

`Concurrency\LeaseManager` 为同一作用域和资源提供1—64个并发名额。每次获取返回不可缓存的持有者凭据，凭据绑定服务器指定的owner、资源和scope；续期、验证、释放均检查绑定及秘密摘要。租约仅在期限内有效，进程活着不代表仍持有租约。

## 显式初始化与状态

由授权部署／资源创建流程调用 `initialize(scope, resource)`，将返回的epoch与业务资源一起保存。正常请求调用acquire时如果账本缺失，抛 `lease.uninitialized`，不能自动初始化、切换内存或假定空闲。重复初始化现有同策略账本保持原epoch和序号。

账本v1永久保存epoch、策略指纹和递增序号，存储TTL为0；各持有者具有独立期限，到期自动释放逻辑名额。这样不会因为所有租约自然过期而重置隔离序号（fencing token）。过期持有者在后续变更时清理；单条账本最多64项，永久账本总数及资源归属由宿主管理。

`LeasePolicy(maximum=1, ttl=30, maximumLifetime=300)`：maximum为1—64，ttl为1—3600秒，总生命周期不小于ttl且最多86400秒。所有字段严格整数；使用秒级一致时钟，后端和服务共享时间源。策略指纹变化、状态损坏或时钟回退拒绝操作，不静默重建。

```php
$manager = new SoSecurity\Concurrency\LeaseManager($sharedStore,
    new SoSecurity\Concurrency\LeasePolicy(1, 30, 300), $clock);
// 只在授权的资源创建／部署流程：$epoch = $manager->initialize('exports', $resourceId);
$lease = $manager->acquire('exports', $resourceId, $serverWorkerId);
if ($lease === null) { return; } // 繁忙，不能开始业务
try {
    // 先由宿主检查epoch、建立业务隔离；任务分块，每步前复核／续期。
} finally {
    // 如果业务存储也授予了写权限，应先撤销并提交该权限，再释放共享租约。
    // 不能完成业务撤销时，停止工作并等待期限，不盲目提前释放。
}
```

owner应为当前已授权任务的唯一稳定标识，不接受客户端自报持有者。相同owner已有有效租约时重复acquire返回null，不重复占位也不暗中续期；正常重试保留现有凭据并调用verify／renew。无法取得原凭据时等待原期限，不恢复明文秘密。

## 凭据、期限与故障

凭据为256位随机秘密与独立随机ID，账本只保存摘要。`Lease`提供token、epoch、fence、expiresAt及absoluteExpiresAt；var_dump通过__debugInfo隐藏秘密、JSON不输出属性、禁止序列化。不要记录或导出凭据对象，也不要把token放在URL、日志或页面状态中，它属于持有者进程。epoch和序号不是认证凭据。

`verify`检查当前真实状态但不续期；它和inspect／重复initialize会持久化观察时间并清理已过期持有者，避免观察到期后时钟回拨令旧凭据重新有效。`renew`仅允许仍有效的同一凭据，将期限推进到 `min(now+ttl, absoluteExpiresAt)`，不改变隔离序号或固定总生命周期。期限为排他边界，到期verify／renew返回null，release返回false。释放后的旧凭据不能续期、重放释放或删除后来者，即使owner相同。

时间、随机数在可重试事务回调之外取得。获取／续期／验证在存储返回后检查期限，慢I/O导致过期抛 `lease.expired`，时钟回退抛 `lease.clock`；不得开始或继续任务。异常可能发生在已提交之后，不能据此认为名额没占用；等待期限或持原凭据复核，不盲目创建新任务。网络故障不降级为成功。

返回后发现凭据已过期或时钟回退时，组件再做一次精确凭据清理并保存观察时间；清理不删除并发替代的新凭据／新epoch，不回退序号。如果该清理也因存储故障失败，资源状态仍不可信，宿主须停止相关任务并按恢复流程核对，不能以重试或自动初始化掩盖异常。观察时间检查不替代部署时钟同步、存储持久性或旧备份恢复审查。

进程崩溃不需要执行析构或finally才能恢复名额，后续获取会清理已过期持有者。组件不杀死暂停进程、取消外部请求或回滚业务副作用；旧进程必须在每一步前验证并处理失去持有权。长时间队列等待后必须重新验证。租约不是任务幂等或恰好一次交付。

## 业务隔离与维护

隔离序号在同epoch账本中单调递增，释放、过期和续期均不回退。业务数据库／对象存储须核对固定epoch并拒绝落后的序号，才能防止暂停后的旧任务覆盖新任务；只在PHP里检查一次租约不能原子保护另一个数据库写入。多名额信号量不等同于同资源独占，不能把较小序号的仍有效名额一律当过期；严格单资源写入隔离示例使用maximum=1。

`inspect`仅返回initialized、epoch、active、maximum、available、sequence、retryAfter，不返回持有者ID／秘密；它不是获取操作。retry仅代表当时最早空位时间，不承诺未来竞争结果。查询／管理也由宿主授权，不自动暴露HTTP路由。

授权运维可在资源停用并排空后调用 `remove(scope, resource, expectedEpoch)`，仅epoch匹配且无有效持有者才删除。旧epoch不能删除重新创建的账本。缺失状态恢复、策略迁移或后端切换须停旧工作进程、排查状态损失并协调宿主固定epoch／业务序号；不能请求内自动remove／initialize来消除错误，也不能把业务epoch验证写成允许任意新epoch。

后端必须保证单键原子性、持久性、禁止驱逐并限制总资源数量。异步副本切换／旧备份恢复可能返回旧账本，即使记录存在也不能仅凭组件检测全部历史；强一致需求由权威业务存储约束，恢复前停止敏感任务。File只保证同主机同私有目录，不能当多机共识锁。

## SQL接入示例与时序

[leased-work.php](../examples/leased-work.php)支持SQLite及MySQL原生预处理，示例表由宿主创建：jobs包含tenant、id、lease_epoch、fence、lease_digest、lease_until、revision、output；tenant＋id为联合主键。新资源在受控创建流程固定epoch，初始fence=0，lease_digest为空、lease_until=0、revision=1。MySQL使用InnoDB和足以容纳输出预算的字段；示例不自动建表、读取请求或提交事务。

1. 宿主验证身份、CSRF／协议和对象授权，生成服务器任务owner，acquire得到租约。
2. 在宿主事务中调用 `claim($pdo,$manager,$tenant,$id,$owner,$token)`：重新验证凭据，要求固定epoch、严格更大序号和仍在未来的期限，然后写入当前序号／摘要／数据库期限；由宿主提交。
3. 每一步先调用manager.verify获取当前Lease，再在宿主事务中调用 `write($pdo,$verified,$tenant,$id,$expectedRevision,$output)`。即使验证之后进程暂停，UPDATE也会用数据库当前时间、epoch／fence／digest和revision阻挡过期或被替代的旧快照。输出预算65536字节，字段固定，不接受任意列。
4. 需要续期时，在宿主事务中调用示例 `renew`，同时延长共享租约与仍有效的SQL期限，再提交。SQL拒绝或回滚时共享租约可能已续期，但业务没有获得新期限，必须停止；同秒续期兼容MySQL按变更行数返回0的行为。
5. 完成／提前停止后，先在宿主事务中调用 `retire` 将当前SQL权限期限置0并提交，再调用manager.release。旧序号／旧摘要的retire不能撤销新持有者。若数据库不可用，不能将未提交的撤销当成功，应停止工作、等待期限并按宿主流程恢复。

所有示例操作要求宿主已开启事务，任何失败由宿主回滚；SQL副作用不放进可重试的AtomicStore回调。示例支持同数据库的条件更新，不保证发送邮件、支付、对象存储等外部副作用的原子性。租约存储／工作节点与数据库时间必须协调，独立的数据库期限会保守拒绝偏差，不能用客户端提供的now替代数据库时间。完整任务发布、重试与幂等继续由宿主编排。

## 工厂、诊断与演示

数据库条件检查的是语句执行期间的时间，某些时间函数固定在语句开始；MySQL的行为见[官方时间函数说明](https://dev.mysql.com/doc/refman/8.0/en/date-and-time-functions.html)。示例在claim／write／renew返回前用新SQL语句和工作节点时间再次检查，触发器／锁等待导致过期即抛错，宿主必须回滚。该检查不是COMMIT时的钩子：保持短事务、每一步立即提交，不支持检查后长时间暂停再提交，也不承诺自动终止任意旧事务。

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/my-site/security'],
    'leases' => ['maximum' => 1, 'ttl' => 30, 'maximum_lifetime' => 300],
]);
$manager = $security->leases();
```

默认不启用leases，工厂不会初始化资源。Memory／Session不能作为工厂共享后端；直接构造允许测试。诊断提示固定账本／恢复、宿主隔离和时钟仍需验收，不执行清理或初始化。网页 `?module=leases` 使用访客Session、两位测试工作者和隔离时钟，支持初始化／获取／检查／续期／释放／旧凭据／到期／排空清理／故障；token只保存在服务器，不展示或返还浏览器。共享后端、SIGKILL崩溃恢复和真实数据库隔离证据单独记录，页面不证明跨Session全局互斥。

设计参考：[Symfony Lock的持有者与期限](https://symfony.com/doc/current/lock.html#reliability)、[Redis锁的一致性与隔离序号](https://redis.io/docs/latest/develop/clients/patterns/distributed-locks/#disclaimer-about-consistency)。本组件使用现有AtomicStore单账本契约，未实现或宣称Redlock、多副本共识或任意基础设施故障容错；本批验证与剩余边界见[验证记录](verification.md)，整体规划继续。
