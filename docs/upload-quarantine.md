# 上传持久隔离

`Upload\Quarantine`是可独立构造的有界隔离工作流，复用`AtomicStore`保存永久状态，在现有的私有本地目录保存内容。它不会启动工作进程、创建目录、发送通知或接管宿主权限。原`Saver`同步接口保持兼容；异步流程始终要求实际扫描，不能由管理员直接标记为干净。

```php
$queue = new SoSecurity\Upload\Quarantine(
    $sharedState,
    new SoSecurity\Upload\Policy(['extensions' => ['jpg', 'jpeg', 'png']]),
    new SoSecurity\Upload\ClamAvScanner('/run/clamav/clamd.sock'),
    $privateSpool, $actualDocumentRoot, 'site-uploads'
);
// 身份、对象权限、CSRF及容量预算通过后：
$pending = $queue->enqueueUpload($_FILES['file']);
// 宿主工作进程一次处理一项，调度循环自行设置有限次数：
$result = $queue->process(); // 无到期任务时为null
// 每次下载均先核对当前用户和业务对象，再按宿主保存的ID读取：
$snapshot = $queue->readAvailable($resourceUploadId);
```

`enqueueFile()`只接收可信服务端路径，复制源文件而不删除。原始文件名仅用于验证，不保存到队列。返回的`QuarantineStatus`只描述ID、状态、尝试次数、版本、下一尝试时间、失效时间和固定错误分类，不含路径或工作进程凭据，也不授予文件访问权限。`readAvailable()`始终读取当前账本，并返回经过完整大小／摘要检查的不可变`Candidate`快照，不向调用方暴露隔离路径。宿主负责响应头和安全下载；已经返回给调用方的字节不能在之后撤回。

## 工厂配置与诊断

也可显式配置`upload_quarantine`，再调用`Security::quarantine()`。它与原`upload`／`uploader()`独立，旧配置不会自动启用隔离流程。

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/security-state'],
    'upload_quarantine' => [
        'directory' => '/private/upload-spool',
        'document_root' => '/srv/site/public',
        'scanner' => 'upload_scanner',
        'scope' => 'uploads',
        'policy' => ['extensions' => ['jpg', 'jpeg', 'png'], 'maximum_bytes' => 5242880],
        'queue' => ['maximum_entries' => 64, 'maximum_total_bytes' => 67108864],
    ],
], ['upload_scanner' => $scanner]);
$queue = $security->quarantine();
$checks = $security->diagnose('/srv/site/public');
```

`directory`、`document_root`及`scanner`服务名为必填，`scope`默认uploads，`policy`与`queue`默认沿用对应组件预算。工厂总是要求扫描，显式设置`policy.require_scan=false`会被拒绝。共享storage必须为文件、Redis、MySQL或满足持久原子契约的自定义服务；拒绝Session／MemoryStore及直接包装它们的已知命名空间存储。原生file配置的元数据目录也必须位于配置的Web根之外；自定义服务的物理保护由宿主保证。

Redis和MySQL元数据后端已在本地私有实例上运行相同的隔离核心与真实进程竞争测试：PHP7.2—8.5九版每个后端各535项核心断言，另覆盖暂停扫描时管理员拒绝、工作进程SIGKILL后的租约恢复，以及暂存预留进程终止后的安全清理。PHP8.2／8.4默认缺少POSIX／Redis扩展，相关Redis专项由经签名校验、仅加载私有扩展的运行包装器完成。Redis需先由可信部署步骤显式初始化命名空间并允许[限量读取命令](redis-recovery.md)；MySQL需显式安装表结构。普通请求和工作进程只连接已经准备好的共享后端，不自动建表或恢复Redis。运行 `python3 tests/quarantine_redis.py php72 quarantine`、`python3 tests/quarantine_redis.py php72 quarantine-process` 或 `python3 tests/mysql_check.py --quarantine php72 php85` 时，控制器仅启动自己创建的无TCP测试实例并在结束后清理；这些测试不能指向业务数据库。

真实ClamAV组合也已在两个后端本地验证：PHP7.2／8.5的Redis与MySQL各36项，PHP8.2／8.4的私有扩展包装器与Redis各36项，包含干净文件、测试签名拒绝与扫描限额；控制器分别运行 `python3 tests/quarantine_redis.py php72 quarantine-clam` 和 `python3 tests/mysql_check.py --quarantine-clam php72 php85`。使用的是私有无TCP后端及本地测试签名数据库，不代表生产病毒检出率。

配置阶段只做严格类型／未知字段和预算校验，不访问服务、解析目录或创建状态。调用工厂方法时验证服务类型与已有目录，仍不启动扫描或写入任务；只有后续显式操作才读写账本。工厂按站点与固定作用域派生独立逻辑命名空间，复用同一物理存储也不能跨站点取用任务。直接构造与工厂派生的作用域不同，切换时应排空并明确迁移。

诊断只读目录并核对实际Web根，不发送扫描样例，也不读取任务；扫描器、持久化契约和工作流仍标为manual。未传实际Web根时位置核对为manual，明确传入无效／不匹配路径时失败；只输出固定原因码，不返回私有路径或底层异常。

## 状态和并发

| 状态 | 含义 | 可读取 |
| --- | --- | --- |
| staging | 已预留准确文件名，写入或提交尚未完成 | 否 |
| pending | 已完成私有写入，等待扫描 | 否 |
| scanning | 当前工作进程持有有界租约 | 否 |
| retry | 依赖故障或超时，等待下一次尝试 | 否 |
| available | 当前版本的准确内容明确通过扫描 | 读取时再次核对 |
| rejected | 检出内容或管理员拒绝 | 否 |
| failed | 内容异常、尝试耗尽或没有足够剩余保留时间 | 否 |
| deleting | 已禁止使用，物理删除待完成 | 否 |
| expired | 固定保留期已过的描述视图 | 否 |

先提交`staging`记录，再以排他随机文件名、0600权限写入并刷新，最后提交`pending`。写入／删除通过目录内永久的`.quarantine.lock`串行化，锁等待最多1秒；进程终止后操作系统释放锁。不要删除或替换锁文件，也不要在还有工作进程时清空目录。目录必须为Web根外的规范0700目录；重新核对目录身份、普通文件／链接数、大小、完整摘要及文件权限。所有上级目录仍须由宿主保护。

扫描在原子存储回调之外进行，回调可安全重试。结果绑定当前状态版本和随机尝试凭据；扫描中的管理员拒绝／重新扫描、另一工作进程接管均使旧结果失效。扫描通过后再次读取准确内容；服务异常、内容替换、超时或无法确定的状态不按成功处理。工作进程死亡后，只能在租约到期时接管，尝试次数继续累计。扫描器负责自己的传输期限；工作流在调用前后检查总预算，不强制中断一个不返回的第三方PHP适配器，宿主还应配置进程和引擎资源限制。

## 预算和管理

| 配置 | 默认 | 允许范围 |
| --- | --- | --- |
| maximum_entries | 64 | 1—64，包含终态／staging |
| maximum_total_bytes | 64MiB | 1字节—1GiB，按已验证内容累计预留 |
| maximum_attempts | 3 | 1—10，包含过期租约 |
| lease_seconds | 60 | 2—300，必须大于扫描总预算 |
| scan_milliseconds | 30000 | 1—30000 |
| retry_seconds | 60 | 1—86400 |
| lifetime_seconds | 86400 | 60—2592000，重新扫描不延长 |

每个文件继续受`Upload\Policy`的类型、单文件字节、像素及工作内存限制。64项账本受现有存储64KiB编码上限保护；正文不进入JSON。`items(1..64)`只枚举有界账本，不遍历磁盘。容量满时在写入目的文件前拒绝。工作进程以`process()`选取一个到期项，也可用`process($id)`；没有取得该项时返回其当前状态或null。

管理员操作只允许宿主已授权且通过CSRF保护的POST调用：`rescan($id)`将非过期、非staging／deleting项重新置为pending，重置该轮尝试次数并增加版本；`reject($id)`立即使之后的可用读取失败。API没有手动放行入口。`remove($id)`只删除staging、rejected、failed、deleting或过期项；先永久标记deleting，再删除准确文件，最后移除记录。确认丢失或删除失败时保留记录，重新读取并继续明确删除，不猜测成功。

文件和账本不是同一物理事务。崩溃／确认丢失时可能保留staging或deleting项，均不可用；维护必须检查这些项并执行上述清理。PHP7.2使用fflush，支持fsync的版本额外刷新内容；这不构成断电后文件系统与任意元数据后端原子持久化的保证。宿主应设置全局磁盘配额、备份及恢复流程。

所有工作进程须使用同一当前权威元数据和同一受保护本地目录。不支持NFS／任意网络文件系统的锁保证；内存存储仅用于测试，Redis等后端不得以丢失／过期状态代替当前记录。命名空间必须由服务端固定，不能把任意请求参数变成独立容量桶。目录物理身份与验证／队列策略均参与绑定，改变策略需要排空并明确迁移，不能静默沿用旧记录。旧备份恢复和存储被有权限者回滚仍需宿主独立恢复权威，不由摘要或此队列保证。

独立构造示例见[upload-quarantine.php](../examples/upload-quarantine.php)，扫描引擎边界见[扫描接入](upload-scanning.md)。SDK核心、[原生HTTP／TLS／浏览器组合](upload-quarantine-native.md)及R4.4本地阶段已验证；生产、远端CI、独立审查及公开发布未执行，完整R1—R6继续。

## 本地复验

```sh
php72 -d memory_limit=8M tests/upload-quarantine.php
php85 -d memory_limit=8M tests/upload-quarantine.php
php85 -d memory_limit=32M tests/upload-quarantine.php images
python3 tests/upload_quarantine.py /path/to/php72
python3 tests/upload_quarantine.py /path/to/php85
```

核心专项使用自己的私有FileStore、文件和可控扫描器。`images`配置另行验证含NUL的真实PNG及相同内容往返，适用图片验证器已有的内存预算。进程专项只启动自己的PHP子进程，验证管理员与暂停扫描竞争、真实SIGKILL后的接管，以及预留写入与清理互斥；仅删除自己的临时目录。执行结果及未覆盖范围见[验证记录](verification.md)。

原生接入的受保护网页、宿主SQLite索引与CLI工作进程见[原生指南](upload-quarantine-native.md)。如需将该本地TLS检查纳入常规门禁，可显式设置`SOSECURITY_REQUIRE_QUARANTINE_HTTP=1`；要求本机有可启动的私有clamd，不接管系统服务。


## 完整来源的底层保护

`Account\QuarantineStateSnapshot` 可将真实私有隔离文件纳入同一 CompositeStateSnapshot；元数据仍需独立 FileStateSnapshot 完整覆盖。为匹配实际队列，传入同一上传策略、maximum_entries 和 maximum_total_bytes。构造保持只读，之后显式 `protect($boundary, $witness, $source, $sourceName)` 绑定准确物理目录，并通过既有 `bindFileStore()` 保护元数据。

这一步只建立来源与底层访问保护，不提供当前业务权限或自动原生入口。`Security::quarantine()` 的保护模式工厂仍默认拒绝；手工组合必须由宿主提供准确授权的外层边界，不允许以普通回调一律放行代替授权。详细范围与证据见[文件来源专项](quarantine-state-source-2026-10-22.md)。

## 原生完整来源连接

受保护模式可向 `Security::quarantine($connection)` 显式传入 `Account\StateQuarantineConnection`。它组合准确元数据来源、`QuarantineStateSnapshot`、同一独立见证／边界、实际扫描器和当前宿主授权；不自动建立或恢复权威。所有操作按当前调用者检查，扫描自动选择后再次检查实际条目。授权回调必须只读且可重复；第一次为空描述，之后包含准确条目及内容摘要。

查询不会推进见证，入队／扫描／读取／管理走各自准入。最终失权或到期不返回文件；未知进行中状态保持拒绝，不提供过期扫描接管、未知回执续办或恢复启用。完整构造约束、兼容性和本地证据见[原生上传隔离专项](native-quarantine-2026-10-22.md)。
