# PDO MySQL 原子存储

`MySqlStore` 为限流、验证码、CSRF 和重置令牌提供跨进程状态。只要求可选 `ext-pdo_mysql`，不依赖 ORM 或框架。使用独立 InnoDB 表与固定 SQL，不接管业务账号表。

## 最小接入

连接的 DSN、认证、TLS 和网络超时由宿主配置，秘密从私有配置读取。使用独立 PDO 连接，避免与宿主事务或其他并发任务共用。

```php
require 'vendor/autoload.php';
$pdo = new PDO($privateDsn, $privateUser, $privatePassword, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_TIMEOUT => 2, // 驱动相关的连接超时，不等于所有查询的总预算
]);
// 仅在部署阶段，用有建表权限的独立连接执行：
SoSecurity\Storage\MySqlStore::install($deploymentPdo);
// 请求阶段只需要 SELECT/INSERT/UPDATE/DELETE，禁止在请求里自动建表。
$store = new SoSecurity\Storage\MySqlStore($pdo, 'shop-prod', null, 1);
$limiter = new SoSecurity\RateLimit\RateLimiter($store);
$decision = $limiter->consume('login', $serverSideIpAccountKey);
if (!$decision->allowed) { /* 宿主拒绝业务并提供 Retry-After */ return; }
```

部署 SQL 位于 [resources/sql/mysql.sql](../resources/sql/mysql.sql)，随 Composer 包交付。`install()` 只在表不存在时创建，并验证已有结构；不改表、不清数据。缺表、MyISAM、错误列/主键/清理索引会拒绝使用。建表是 MySQL 隐式提交操作，因此宿主已有事务时直接拒绝。

## 工厂配置与诊断

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'shop-prod',
    'storage' => ['driver' => 'mysql', 'connection' => 'security_db', 'lock_wait_seconds' => 1],
], ['security_db' => $pdo]);
$login = $security->rateLimiter();
// token_storage 默认仍是 Session；需要共享验证码/CSRF时显式配置为 mysql。
$checks = $security->diagnose($documentRoot, true);
```

`lock_wait_seconds` 默认 1，整数 1–30，单位秒。等待行锁超时会抛出 `StorageException`，不会当作新状态放行。高竞争且磁盘较慢时，宿主可以显式选用较长等待；本地24进程验收使用5秒，同时另有真实持锁测试验证默认1秒拒绝。API管理凭据的24并发轮换在慢盘下可触发明确1205锁等待拒绝；测试分别统计成功/拒绝，确认至少一次成功后原凭据失效、后续串行轮换可用且撤销后不能复活，不承诺所有管理请求都会成功。

工厂创建不连接数据库、不建表、不启动事务。首次调用模块才检查注入连接和表。默认诊断不探测数据库；显式 probe 只读检查结构。网络超时无法从 PDO 配置可靠证明，会标记人工确认；不能把行锁等待上限描述成整个数据库操作的总超时。

运维 CLI `bin/initialize-storage.php /private/config.php` 可显式执行配置中的 MySQL 建表/验证；CLI配置格式见configuration.md。安装后请求账号收回DDL权限，使用正确schema的专用连接。

## 原子性、事务与故障

每次操作先用 `(namespace_hash,state_key)` 唯一主键占据目标行，再 `SELECT ... FOR UPDATE` 读取，最后提交后返回结果。命名空间与逻辑键使用 SHA-256；不把账号/IP原文保存为索引。载荷仍是JSON原语，受统一Codec的64KiB/深度/节点限制。

逻辑删除保留60秒的空载荷记录，防止并发插入/删除产生间隙锁竞争；读取仍返回空状态。永久封禁的expires_at为0，不会被过期清理删除。

- 宿主已有事务时，`transact()`/`prune()`/`install()`直接拒绝；不提交或回滚宿主事务。
- 只拥有自己创建的事务。异常时回滚该事务，并恢复临时设置的 `innodb_lock_wait_timeout`；不修改 PDO 错误模式或模拟预处理设置。
- 不能确认提交、连接断开或清理失败时抛异常；不自动重试可能已经提交的操作。清理失败的实例不能继续使用，宿主重新连接并构建存储。
- 回调属于原子状态计算，可能由其他驱动重试，因此仍必须没有业务I/O、副作用或额外SQL，不要在回调里发邮件或更新业务账号。

密码重置的业务示例见 [password-reset.php](../examples/password-reset.php)。宿主账号更新仍使用版本比较；若宿主要保留业务事务，安全存储必须使用另一个 PDO 连接。令牌消费与业务SQL不构成分布式事务，SQL失败应重新发令牌，不能恢复已消费令牌。

这些边界依据 [MySQL InnoDB 锁说明](https://dev.mysql.com/doc/refman/8.0/en/innodb-locks-set.html) 和 [死锁处理说明](https://dev.mysql.com/doc/refman/8.0/en/innodb-deadlocks.html)。死锁或超时都是拒绝敏感操作的故障路径，业务是否重试由宿主明确处理。

## 有界清理与版本证据

```php
$removed = $store->prune(1000); // 默认1000，每批1–10000；按同一namespace清理
```

清理索引限制候选数；按单条载荷检查Codec和JSON过期时间与索引字段一致性后删除。损坏元数据不会被当成“普通过期”悄悄删除。应定期运行独立维护任务，HTTP热点请求不运行无限清理循环。数据备份、数据库恢复、数据库账号权限和服务器磁盘容量仍由运营者管理；数据库恢复到旧快照可能恢复旧安全状态，不能宣称有Redis同等的进程标识检测。

本地实际验证：MySQL8.0.46、PHP7.2/7.4/8.1/8.2/8.4/8.5及本机PDO客户端；24进程限流/单次令牌/验证码和业务密码版本比较；事务冲突、损坏记录、锁超时与断连接提交失败。MySQL5.7/8.4、MariaDB及其他客户端版本尚未验收，不根据SQL语法看似兼容宣称通过。旧PHP客户端对MySQL现代认证的支持需要单独确认；隔离测试账号使用mysql_native_password，仅用于私有测试实例，没有改现有网站账号或服务策略。
