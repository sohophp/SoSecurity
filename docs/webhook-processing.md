# Webhook持久处理、重试与恢复

状态：R4.3实施中。SQL核心包含领取、事务完成、错误重试、人工重试、状态和有界候选扫描；追加显式处理工厂、只读诊断、独立CLI工作端及强认证管理页。工厂九版专项、两版真实TLS／CLI／移动浏览器及全新消费者已有本地证据；共享事务保护379文件完整矩阵及本批388文件九版接入专项均已通过，二者按各自快照分别记录。通用接口幂等／出站消息契约及完整R4.3验收继续，不能将接收ACK当作业务完成或将子阶段描述为整个规划完成。

同事务出站入队的[内部事务基础](sql-transactions.md)已实现，具体队列与发送契约继续实施；处理器本身的事务所有权与禁止回调自行提交的要求不变。

## 接收与处理的关系

SqlInbox确认消息已经持久接收；SqlProcessor从同一私有数据库读取真实接收记录，先验证独立HMAC封存、命名空间与实际原始正文摘要，再重建Message并检查接收时封存的描述指纹。只拥有Receipt对象、候选ID或客户端提交的“已验证”标志不能执行工作。

处理不要求提供器重新签署已经接收的旧消息，也不把过去的签名时间窗口当作当前业务授权。原始接收来源由独立封存证明；当前业务关联及工作端权限仍逐次核验。被撤销的提供器密钥可能涉及历史消息处置，宿主须按可信接收时间／签名来源制定停止处理或人工核实策略，不将重新验签失败当作自动删除历史记录的理由。

## 显式部署

先安装[接收结构](../resources/sql/webhook-sqlite.sql)或[MySQL接收结构](../resources/sql/webhook-mysql.sql)，再通过宿主受控迁移安装[SQLite处理结构](../resources/sql/webhook-processing-sqlite.sql)或[MySQL处理结构](../resources/sql/webhook-processing-mysql.sql)。新增接收编号索引与独立处理表，保留已有接收列、正文和封存。原始DDL供明确部署使用，宿主迁移负责互斥、已有结构核实、幂等与恢复，不在Web请求中自动安装。

SQLite必须为私有真实文件、日志开启且同步等级FULL／EXTRA；MySQL接收与处理均要求InnoDB及提交刷盘。业务处理表和幂等执行记录也必须在同一连接、同一事务数据库及支持事务的引擎中；组件验证自己的表，宿主负责其他业务表。连接使用异常模式，MySQL要求自动提交开启、原生预处理和当前锁定读取；启动事务前通过服务器保存点识别旧PDO漏报的手工事务，不切换自动提交或隔离级别；宿主配置传输／语句超时、容量与保留策略。

处理表对端点＋接收编号建立主键，并对端点＋稳定事件键建立唯一索引。即使接收历史丢失后合法重投形成了新接收编号，保留的处理历史仍阻止同事件被当作新任务执行；这类不一致需人工核实，不能靠删除处理行“修复”。若安全状态和业务历史均被删除或恢复到旧备份，组件无法证明所有历史副作用，必须停工作进程并执行恢复／对账流程。

## 显式构造与宿主接口

```php
$processor = new SoSecurity\Webhook\SqlProcessor(
    $privatePdo, $site, $fixedEndpoint, $independentIntegrityKeys,
    $receivedBodyMapper, $currentBusinessAssociation, $currentWorkerGuard,
    new SoSecurity\Webhook\ProcessingPolicy(),
    null, // 默认系统时钟
    $currentOperatorGuard // 不配置则人工重试拒绝
);
```

构造只检查已有连接能力，不查询业务、执行回调、建表、启动Session或联网。

也可以显式配置仅处理历史接收记录的工厂：

```php
$security = SoSecurity\Security::fromArray([
    'site' => $site,
    'webhooks' => ['events' => [
        'scope' => $tenant, 'account' => $publisher,
        'url' => $fixedReceivingUrl, 'protocol' => 'standard-hmac',
        'processing' => [
            'connection' => 'business_db', 'integrity_keys' => 'receipt_keys',
            'mapper' => 'received_mapper', 'association_guard' => 'current_business',
            'worker_guard' => 'current_worker',
            // 'management_guard' => 'current_operator', // 仅在需要人工重试时配置
            'policy' => ['maximum_attempts' => 5],
        ],
    ]],
], $services);
$processor = $security->webhookProcessor('events');
```

services注入已有PDO、独立HmacKeys以及上述回调。processing只配置服务名，不把秘密放入配置数组。历史工作端可省略接收侧key_provider／request_guard，也不配置inbox；它不获取提供器密钥、调用Verifier或因历史Ed25519消息而要求sodium。实际接收Ed25519仍必须使用sodium，不能降级验签算法。完整接收服务须成对配置key_provider／request_guard，启用inbox时也不能省略。接收与处理都配置时使用同一固定命名空间和真实接收数据库。

`diagnose()`和`diagnose(null, true)`的processing相关检查均不执行处理回调或SQL；PDO与回调存在仅标记manual，不能据此证明业务授权、持久化、结构、超时或恢复契约已满足。其他存储的显式探测仍按其原有契约执行。缺失管理回调显示人工重试未配置，错误服务类型显示fail。ProcessingPolicy.options()和Config.webhooks()返回独立数组，不能通过外部引用改写已校验的策略。

- mapper接收真实已封存正文、固定Endpoint、接收编号及已封存描述元数据，返回Message；必须与接收时的消息ID、类型、资源及完整描述指纹一致。原始上下文若来自正文之外的数据，宿主须保留可稳定重建的可信依据；不能重新查到不同版本后悄悄替换历史描述。第四参数包含message_id、type、resource、received_at、source_key和source_time，可用已封存的message_id处理Standard消息ID仅出现在签名头、正文没有id字段的情况；前三个参数的既有回调继续兼容。type／resource是接收时已经核验并封存的映射描述，不代表协议一定签署了同名投递头，不能将GitHub未签名头重新提升为来源声明。
- associationGuard接收Endpoint、Message、phase及已验证来源元数据。元数据包含receipt_id、received_at、source_key和source_time；无签名时间的协议为null，不能伪造新鲜度。phase包含claim、execute、commit、retry和status，严格true才允许。回调只读，MySQL事务内读取当前权威关联应使用锁定读取，不能依赖历史一致性快照。
- workerGuard接收operation、Endpoint、receiptId和workerLabel，严格true才允许。operation包含claim、execute、fail、pending、status；pending的receiptId为空。工作端标签是服务器定义的有界ASCII标识，不能替代实际进程／服务身份验证。
- managementGuard签名同workerGuard，仅用于retry；必须执行实际操作者身份、近期强认证、CSRF、对象权限及管理请求预算检查。传入字符串operatorLabel不构成身份认证。

回调收到内部对象／上下文的局部副本；即使使用PHP引用参数，也不能替换组件保存的PDO、固定端点、原始正文或来源上下文。Message等对象本身不可变。回调不得重入同一处理实例。

## 状态与预算

状态为ready、leased、retry、succeeded和dead。尚未领取的合法接收记录可以没有处理行；首次领取才创建经过封存的处理状态。成功行保留，接口不提供将succeeded重置为可执行状态的操作。

默认每轮最多5次尝试、最多3次人工重试、领取期限60秒、重试延迟1／5／30／120秒、单次总I/O预算10000毫秒。可配置每轮1—20次、人工0—8轮、领取期限1—900秒、有界不递减延迟和最多30000毫秒操作预算；所有轮次累计最多100次，人工重试不清零累计次数。策略指纹绑定已有状态，策略变化需要显式迁移，不自动清空历史或恢复额度。

领取凭据绑定命名空间、接收编号、递增修订和工作端摘要，秘密只返回一次。数据库仅存摘要。领取过期不能复活旧凭据，新持有者领取后旧凭据不能执行或报告失败。租约到期本身不能停止旧进程；SQL完成路径在持有处理行锁时复核期限并回滚过期工作。

## 候选扫描与工作执行

```php
$page = $processor->pending('receiver-worker', 20, $cursor);
foreach ($page['receipt_ids'] as $receiptId) {
    $claim = $processor->claim($receiptId, 'receiver-worker');
    if ($claim === null) { continue; }
    $status = $processor->execute('receiver-worker', $claim->token(), $transactionalHandler);
}
$cursor = $page['next_cursor'];
// complete=true时本次扫描结束；下一轮从空游标开始。
```

pending每次最多扫描50条有索引的接收记录，再筛选未领取、到期重试或领取已过期的候选。即使receipt_ids为空，也必须在complete=false时推进游标；不能因前面都是已完成记录而遗漏后面的消息。候选编号是惰性提示，真正领取时重新核验来源、业务关联与当前状态。并发新消息可能位于游标之前，由下一轮重新扫描发现；不保证一次扫描是全队列快照。

handler签名为`function(PDO, Message, string $rawBody, ProcessingStatus): bool`。只能在传入的同一PDO事务内执行经过授权、带租户／资源条件及业务版本的参数化SQL；严格true表示完成。组件在提交前再次核对来源记录／实际正文、业务关联、工作端权限和领取期限，并将业务写入与succeeded状态一起提交。commit阶段的业务关联必须识别本次事务合法的新资源版本，仍保留租户、归属、禁用及身份权限检查。

handler禁止自行提交／回滚／开启事务、执行DDL或改变连接状态；持有组件事务期间，采用随机保存点（Savepoint）在登记的权限、映射和业务回调返回或抛错后确认原事务仍存在；识别回调提交、回滚或隐式结束事务后停止该实例。若宿主已另开事务，不接管或回滚后来事务。非法提交可能已经产生真实业务副作用，检测不能撤销已经提交的写入；必须停用错误回调并按稳定业务执行记录核对，不能自动重做或声称已回滚。自定义Clock必须可靠只读，不管理事务。不能在该回调中发邮件、支付、HTTP请求、扫描文件或提交其他连接；这些副作用无法随本事务回滚。使用同库出站消息表记录意图，再由有独立幂等契约的发送端处理，完整接入示例仍在实施。

业务执行记录应以可信提供器／租户／稳定事件身份建立唯一约束，并在同一事务记录／校验原始请求内容。不要仅依赖随机接收编号、Redis中的已处理标志、回调执行次数或响应是否到达。该业务不变量还能在局部状态丢失时阻止重复执行。

## 失败、重试与不确定结果

handler失败或返回非true时，本事务回滚业务写入，领取仍保留，调用方可按已知业务错误调用`fail(worker, token, fixedErrorCode, retryable)`。只使用服务器固定的有界错误码，不存异常文本／正文／密码；retryable=false直接终止，达到尝试上限也转dead。重复fail或旧凭据不重复安排重试。

`retry(receiptId, operatorLabel)`只对dead生效，要求独立管理回调及当前业务关联；每轮尝试归零，但累计次数和人工轮次保留。成功消息不能通过此接口重做。查询状态需通过当前工作端权限和业务关联，不返回正文、秘密或任意业务结果。

若提交返回过晚、清理失败或进程在响应前退出，数据库可能已经同时提交业务和succeeded；组件不会自动重复handler。用新连接核对持久状态，成功则结束，未完成则按真实领取期限／重试状态恢复。连接清理失败后拒绝复用该实例。业务与外部系统、其他数据库或旧备份之间不提供跨资源恰好一次保证。

## 当前验证边界

SQLite／MySQL原型已验证真实SQL写入与状态提交、回调失败完整回滚、期限和旧凭据、错误退避／人工上限／累计100次、源正文损坏、接收历史丢失后稳定事件唯一性、状态篡改、宿主事务保护及有界游标。两后端24进程领取／完成／重放和真实SIGKILL提交前后恢复已有原型证据；引用隔离首轮根目录九版专项已通过；新增头部独有消息ID与回调事务结束检测的两版两后端专项通过，新共享事务保护的379文件基线九版完整门禁及388文件新接入九版专项均已通过；完整R4.3仍保留通用幂等／出站消息契约与最终阶段验收。当前状态见[精修跟踪](security-refinement.md)和[验证记录](verification.md)。

## 原生CLI处理与管理恢复

[webhook-worker.php](../examples/webhook-worker.php)为与[接收页面](../examples/webhooks.php)配套的显式CLI示例，[webhook-business.php](../examples/webhook-business.php)共享固定消息映射及当前业务关联。导入不运行工作端；HTTP访问CLI脚本返回404，不执行任务。示例仅使用SQLite，库本身仍支持SQLite／MySQL。

先通过受控部署安装接收与处理结构，再安装[业务示例结构](../resources/sql/webhook-example-processing-sqlite.sql)。该结构增加独立稳定事件执行记录及资源投影，须和接收／处理表位于同一私有事务数据库；不会修改权威资源版本。示例不自动创建表、账号、目录或密钥。

接收页默认不启用处理管理，设置`SOSECURITY_WEBHOOK_EXAMPLE_PROCESSING=1`后，已通过近期密码／TOTP认证的当前管理员可以查看有界处理状态并用CSRF保护的POST重新安排dead消息。不能重做succeeded消息；人工轮数及累计尝试不清零。接收路径仍只确认持久接收，既不执行工作，也不接受管理员Cookie代替提供器签名。

CLI沿用`SOSECURITY_WEBHOOK_EXAMPLE_`前缀中的`DATABASE`、`SEAL_KEYS`、`ORIGIN`、`PATH`和`HTTPS`；另须配置`PROCESSING=1`、固定服务器工作端标签`WORKER`及规范Web目录`DOCUMENT_ROOT`。数据库和封存密钥须为Web根外0600文件，其父目录为0700；配置及业务数据库访问权限由运行CLI的系统账号控制。工作端不读取提供器密钥、管理员密码来源、MFA密钥或浏览器Session；WORKER标签本身不构成认证。

```sh
php examples/webhook-worker.php --once
# next_cursor取上一页输出的32位next_cursor；不要使用固定示例编号。
php examples/webhook-worker.php --once --after="$next_cursor"
```

每次最多扫描20条接收记录，输出claimed、succeeded、failed、next_cursor和complete。调度方须保存并继续next_cursor，complete=true后下一轮从空游标开始；空候选但complete=false也要继续，否则可能始终扫描前面的已完成记录。每次调用有界，不内置常驻循环或自动调度。

退出码0表示本页没有已知业务处理失败；退出码2表示业务回调失败且事务清理成功后，已尝试按固定错误码安排受限自动重试，仍需按返回游标继续扫描和后续回访。失败事务中的业务执行记录与投影写入一起回滚。配置、来源、权限、提交或清理结果不确定时退出1，只输出固定错误码；不得凭该退出码直接重新执行业务，应新建连接核对持久状态与领取期限。组件不会在同一执行调用中自动重跑handler。

业务示例以租户＋提供器账号＋稳定事件键约束执行记录，并核对实际正文摘要、资源和版本。接收／处理历史局部丢失后，同内容再次合法接收不会递增已有业务投影；同事件不同内容拒绝完成。这不证明所有旧备份已一致恢复，删除业务账本、外部副作用或多数据库仍需要停机核实及对账。

本地接入检查为`python3 tests/webhook_processing_http.py <php> --http`及默认真实隔离TLS；增加`--browser`执行移动Chromium原生表单。另可用`python3 tests/webhook_processing_history.py <带sodium的php> <不带sodium的php>`验证真实Ed25519接收记录在另一运行时脱离提供器密钥、过签名时间窗后仍按封存与当前业务授权处理一次。该测试不把历史来源当作当前业务授权。
