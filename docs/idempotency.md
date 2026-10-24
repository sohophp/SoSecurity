# 通用 SQL 幂等

`Request`和`Response`可能持有幂等键、URL参数及业务正文；当前对象导出不会展开这些值，显式getter仍返回原始字节。旧序列化对象拒绝恢复，宿主应从当前认证请求或可信结果存储重建，不能把对象转储作为业务回放凭据。

R4.3实施中的可选组件。`Idempotency\SqlExecutor` 将同一 PDO 上的业务写入与可重放结果放入一个事务，适合订单创建等具有稳定业务唯一约束的写接口。它不创建结构、不接管已有事务、不自动重试业务回调，也不向客户端输出内容。显式工厂、只读诊断及原生Bearer／CLI接入已通过本地专项；出站消息箱（Transactional Outbox）和完整阶段验收继续实施。

内部另增加[加入宿主事务的基础单元](sql-transactions.md)，供同事务出站入队使用；不会改变本公开执行器仍自行拥有事务、拒绝外层调用方事务的契约。完整Outbox仍在实现。

## 部署与身份边界

根、执行记录、历史分页及维护查询的元数据均在 SQL 返回 PHP 前校验类型与字节上限；异常／超限值返回空值并由严格状态读取器拒绝，不截断成合法数据。正文独立核对真实 BLOB 长度、声明长度和摘要，保留空正文、NUL 及非 UTF-8 二进制重放。该保护限制 PHP 读取缓冲，不承诺数据库引擎总内存上限；不需要修改现有表结构。专项结果见[2026-10-21 修复记录](idempotency-bounds-fix-2026-10-21.md)。

部署使用64位PHP，显式执行 [SQLite](../resources/sql/idempotency-sqlite.sql) 或 [MySQL](../resources/sql/idempotency-mysql.sql) 结构，使用私有持久 SQLite 文件及 FULL／EXTRA 同步，或 InnoDB 与 `innodb_flush_log_at_trx_commit=1`。MySQL 使用原生预处理、异常模式和自动提交的空闲连接；SQLite 支持旧 PDO，但同样拒绝已有的原生或 SQL 手动事务。构造只检查连接属性，不查询 SQL、调用宿主回调或初始化数据。

`site`、租户、主体及固定操作名由宿主可信上下文提供，`epoch` 为数据库外保存的64个小写十六进制字符组成的部署代际，不能从请求或待恢复数据库自证。封存密钥与业务／API密钥分离，使用 `Support\HmacKeys` 注入。部署管理程序经当前管理权限显式 `initialize(scope, subject, operation)`；请求缺少根记录时拒绝执行，不能在请求中自动重新初始化。

客户端幂等键由16—128个受限 ASCII 字符组成，只负责区分意图。`Request` 中的 scope、subject、operation 也只是描述，不证明身份。宿主必须先认证并提供当前权限回调，逐阶段核验租户、主体、目标对象、资源版本及操作权限；对 Cookie 接口另行执行 CSRF、防重放和请求预算。授权不能只看第一次成功或旧结果中的用户编号。

## 事务调用

工厂可选配置 `idempotency => ['connection'=>'orders_db', 'epoch'=>$epoch, 'integrity_keys'=>'idempotency_keys', 'authority'=>'current_authority', 'management_guard'=>'current_manager', 'policy'=>[]]`，分别注入 PDO、HmacKeys 与两个权限回调后调用 `Security::idempotency()`。未配置时抛配置异常；管理服务可省略，此时禁止初始化／维护，正常请求仍需预先部署的命名空间。配置／工厂构造与 `diagnose(null, true)` 都不执行 SQL 或权限回调；诊断中的 manual 需要宿主核实，不能当作结构、权限或恢复安全已验收。

```php
use SoSecurity\Idempotency\Request;
use SoSecurity\Idempotency\Response;
use SoSecurity\Idempotency\SqlExecutor;

// $authority、$management、$keys 等由宿主明确注入；没有默认放行回调。
$executor = new SqlExecutor($pdo, $site, $epoch, $keys, $authority, null, null, $management);
$request = new Request(
    $authenticatedTenant, $authenticatedSubject, 'orders.create', $clientKey,
    'POST', $actualTarget, $rawBody, ['content_type' => 'application/json']
);
$outcome = $executor->execute($request, function (PDO $connection, Request $request, string $executionId): Response {
    // 从同一 Request 正文解析输入，白名单验证，并使用当前身份和数据库业务唯一约束。
    // 所有 INSERT/UPDATE 均使用传入 connection，不自行 COMMIT、DDL 或调用外部系统。
    return createOrderInCurrentTransaction($connection, $request, $executionId);
});
// null 表示前置权限拒绝；宿主自行映射通用 HTTP 拒绝，绝不能继续执行订单。
// 非空结果通过当前权限复核后才返回；宿主自行设置固定响应头、禁止共享缓存并输出允许的结果字节。
```

`authority(phase, Request, metadata)` 只有严格 `true` 才允许。阶段为事务前 `request`、新任务 `execute`／`commit`、已有结果 `replay`、无结果查询 `lookup`，以及提交后 `return`；阶段可能多次调用。元数据提供稳定 execution_id、已认证存储fingerprint、created_at、expires_at 和 replayed，不包含缓存正文。`management(operation, scope, subject, action)` 保护 initialize／maintain，同样在执行前、提交前及提交后核验。管理回调未提供时管理拒绝。回调必须有界、无网络副作用，不创建或结束事务；回调异常转换为固定原因，不附带原异常或秘密。

执行键绑定 site／scope／subject／operation；指纹另绑定实际 HTTP 方法、完整目标（含查询）、原始正文摘要及最多16项宿主绑定字段。相同键且指纹一致时返回保存的状态码和原始二进制正文，`Outcome::replayed()` 为 true，业务回调不再执行；不同内容拒绝 `idempotency.conflict`。不要在宿主通过另一份可变对象或未绑定正文执行业务。

`Response` 支持200—599和有界正文，不缓存响应头、Cookie、HTTP输出或会话副作用。只保存允许当前调用者重复查看的业务结果；一次展示凭据、密码、恢复码等秘密不能作为可重放正文。HMAC防篡改不提供数据库加密，私有结果的数据保护和日志脱敏仍由宿主负责。默认响应上限64KiB，最大1MiB；请求正文最大1MiB。

## 失败、到期与恢复

默认有效期86400秒、每命名空间1000个键、总 SQL 调用预算10000毫秒。同步 SQL／宿主回调在返回后检查期限，不能中断任意驱动或任意阻塞代码；生产仍需连接／语句／进程层超时。可信 Clock 必须同步且可靠，组件保存根记录观察时间并拒绝回退，但不替代跨机器可信时间源。

业务异常、当前权限拒绝、保存结果失败或提交前超时，回滚已知属于组件的整个事务。MySQL状态、计数与正文统一采用当前读取，避免等待另一事务提交后混用旧快照；宿主授权回调及业务查询仍需使用适当的当前读取、版本条件或锁，不能用旧快照当作当前权限。COMMIT确认丢失、回滚失败或回调自行提交／替换事务时，实例失效，要求重建连接并核对业务记录；不自动重跑回调，也不回滚后来由宿主创建的事务。非法自行提交的业务副作用可能已持久化，不能声称已回滚；发现持久 `running` 记录拒绝自动继续，要求人工对账。

提交成功后权限变化、超时或响应丢失仍可能使调用失败，此时业务可能已经完成。合法客户端可在当前授权下用原键查询／重试，不能自动改键。宿主应以 execution_id 和业务自然唯一键维护独立约束或执行账本，处理备份恢复及跨记录重建。

提交后的权限检查失败或拖过结果期限时，组件在原 SQL 总预算内尝试独立短事务：复核已提交记录、保存观察时间并清空已过期结果，不再执行业务或延长期限。这样已观察到的到期不会因随后重建服务和时钟回退而直接复活；补记故障仍拒绝返回，并要求核对状态，不承诺在存储不可写或不可信时间源下完成持久化。

到期结果变为永久键墓碑：不再返回旧正文，也不把同一键作为新业务。`maintain(scope, subject, operation, limit, afterKey)` 每批1—50条，校验实际正文与封存，清空到期正文并轮换封存密钥；返回 scanned、compacted、rekeyed、next_cursor、complete。刚好满批时 complete 为 false，需继续一批确认结束。维护不释放键名或容量，不重置生命周期；业务应提前规划命名空间生命周期与总量配额，不能为了释放容量删除已完成历史后复用键。

根记录除计数外，还封存有序的键摘要／执行ID集合摘要；每次核验以最多512行一批读取元数据，避免只校验条数时“删除旧键再塞入其他记录”绕过。删除、替换或改变执行ID都会拒绝，缺少根记录或留下孤儿记录也拒绝执行；单批读取有界，但一次完整核验的工作量随命名空间历史数增长，策略最大容量及总预算共同限制它。HMAC不能识别“根记录与全部数据一起恢复到一份旧的有效备份”，也不能抵御已取得封存密钥的攻击者。恢复后需外部代际、业务唯一账本和人工对账，禁止通过重新初始化宣称恢复安全。密钥轮换须保留所有尚未重封存记录的旧键，逐批维护确认后再移除。

当前未发布根格式为2，增加 `history_digest` 并使用独立版本的根封存域；记录格式仍为1。早期仅计数的开发原型结构不兼容，不自动补字段、重签或清空旧历史，必须先依据可信业务记录对账，再在停写条件下实施受控迁移；没有把开发期SQL改动当成生产在线迁移验收。

原生Bearer接口、当前SQL账号、独立业务唯一账本、私有CLI和移动页面已实现，接入要求与复验边界见[原生幂等订单](idempotency-native.md)。完整R4.3及出站消息箱继续。

## 验证边界与参考

最新原生接入的PHP7.2—8.5九版SQLite每版409项（核心135／安全190／工厂48／受限内存5／并发31）、真实MySQL每版356项（135／190／31）、HTTP／TLS各433项、161类API和九个全新Composer消费者通过。两后端含24进程与真实SIGKILL，原生接口另验证丢失确认后的服务器重启；两版TLS移动Chromium通过，451个源码／测试／配置文件在整轮未变。此前两版513条历史跨批次验证的各517项仍为单独补充证据。出站消息箱、完整R4.3及整库最终验收继续，阶段快照、原始失败和验证边界见[验证记录](verification.md)。本批不作生产或独立审查结论。

参考 [Stripe幂等请求](https://docs.stripe.com/api/idempotent_requests) 的键与参数比较及结果重放语义；本组件永久保留键墓碑，不能套用其他产品删除到期键后重新执行的规则。外部副作用需要另行实现 [事务消息箱与接收方去重](https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html)，本组件只保证同一 SQL 事务内的结果和业务一致性。

> 幂等／Outbox工厂已补受保护模式默认拒绝，见[工厂边界修复](idempotency-factory-boundary-2026-10-22.md)。幂等原生准入仍未实现，不能用拒绝配置替代功能完成。

> 幂等原生初始化／维护已继续接入，见[当前实现](native-idempotency-maintenance-2026-10-22.md)。此前“幂等原生全部未实现”为历史状态；首次执行与结果查询仍开放，不能据此关闭整个缺口。

> 幂等原生首次执行及已知结果查询已继续接入，见[本批实现与定向证据](native-idempotency-request-2026-10-22.md)。此前“首次执行／查询待接入”为历史状态；默认PHP7.2时钟失败、暂缓功能和外部验收保持开放。
