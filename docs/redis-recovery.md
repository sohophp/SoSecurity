# Redis 初始化与重启恢复

Redis存储不在HTTP请求中自动初始化。专用连接仍需无serializer/prefix，不混入宿主MULTI/WATCH，配置noeviction和持久化/内存告警。仅允许本库使用独立实例或受控数据库/命名空间。

## 第一次部署

```php
// 独立的可信部署脚本，不是Web路由：
require 'vendor/autoload.php';
$redis = new Redis();
$redis->connect($privateSocket, 0, 2.0);
$store = new SoSecurity\Storage\RedisStore($redis, 'shop-prod');
$store->initialize();
```

请求阶段连接后直接使用store；没有ready标记时事务抛 `storage.uninitialized`。相同进程已初始化时initialize()返回false且不重置数据。工厂的命名空间为 `site:shared` 和 `site:tokens`，不要误用直接组件的另一命名空间进行初始化。

```php
// 仍只在可信部署脚本内执行：
$security = SoSecurity\Security::fromArray($config, ['security_redis' => $redis]);
$security->initializeStorage();
```

也可以执行 `php bin/initialize-storage.php /private/config.php`；私有PHP文件返回config和services，连接认证/TLS由文件中的宿主代码建立。CLI不打印秘密、路径或底层异常全文。Redis账号需要读取INFO server与ready键、执行EVAL以及操作该namespace的数据键；Lua内部也检查INFO server。缺权限会拒绝，不降级为不检查。

## 检测与恢复

ready记录绑定Redis进程run_id及随机epoch。每次操作先校验标记，原子Lua提交时再次核对进程身份、ready和旧状态。进程重启即使载入旧RDB/AOF，也不允许旧的一次性令牌直接复活；标记删除、损坏或epoch被其他维护任务更换时拒绝操作。

1. 停止使用相关敏感操作，确认服务端故障、持久化恢复点和记录丢失范围。
2. 决定账号会话/重置令牌失效策略，并恢复必要的永久封禁、计数或其他人工保护。库无法从旧快照还原真实最新状态。
3. 重建专用连接，在可信维护脚本中显式调用 `initialize(true)`，或 `Security::initializeStorage(true)` / CLI `--recover`。
4. 新epoch隔离旧数据；检查诊断及受控操作后恢复业务。不在请求里捕获故障后调用recover。

正常initialize()遇到旧进程标记会报storage.restart，要求显式recover。标记完全缺失时库不能区分第一次部署和标记被删，运营者必须根据部署历史按上述恢复流程审核；不要把“能够创建标记”当作没有丢过数据。

重新初始化会使旧epoch的验证码、CSRF和重置令牌失效；旧封禁/计数也不再参与新epoch计算，需要运营者明确处理。旧键按原TTL自然过期，永久记录需要受控运维处理；库不FLUSHDB，不自动清整个命名空间。不能把恢复描述为无损或自动保持全部封禁。

传输失败可能发生在服务端提交后、响应到达前，因此不重试为成功；失败实例关闭连接，宿主重连并构建新实例。默认1000ms/最多32次CAS；仅当旧状态竞争导致明确未提交时才重试纯回调。响应丢失意味着调用者得到故障，也可能已经消耗令牌，重新发令牌比复用更安全。

## 仍需运营者管理的边界

标记不能检测所有单键误删、同一运行进程被不受信任客户端修改、备份数据在未变更进程身份时被直接导入等情况。禁止其他业务直接操作安全键，限制运维权限并使用noeviction。该方案按单实例Redis设计，Redis Cluster多键槽/拓扑/故障切换未验收；不能宣称透明支持。

只读diagnose(..., true)检查连接、Lua权限、淘汰策略及当前ready；不会初始化标记。ready缺失或与当前进程不一致显示fail。CONFIG权限不足的淘汰检查为manual，不冒充pass。

测试 `tests/redis_restart.py php72` / php85创建无TCP的独立Redis，保存消费前快照、消费一次、NOSAVE关闭并载入旧快照；确认重启拒绝、未审核初始化拒绝、显式恢复后旧令牌仍拒绝、新令牌正常、删除ready后拒绝。它不重启已有网站Redis。当前本地Redis5.0.3，PHP7.2/7.4/8.1/8.5已执行，包含PHP7.2旧版phpredis4.3客户端；不据此宣称其他服务端版本或Cluster已验收。
