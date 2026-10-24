# 授权下载与内容版本

状态：R3.6本地验收完成。核心、显式工厂、诊断及[原生页面](../examples/authorized-download.php)已有实现；九版本完整检查／275核心／1456独立Range／749原生HTTP／733真实TLS／16MiB低内存／ENOSPC／新消费者，以及PHP7.2／8.5 Chromium通过，详情见[验证记录](verification.md)。完整精修仍在继续，不将本页视为生产接入证明。

## 信任与文件版本

`Download\File`只能由服务器权威文件索引构造：`Authorization\Resource`、相对路径、下载名、真实字节数及完整SHA-256。客户端只提供受限的业务编号，不能选择磁盘路径、所有者、租户、内容摘要或文件状态。宿主在上传／更新流程中计算并事务保存摘要，下载时重载当前记录；待扫描、已删除或未授权的文件不返回可下载记录。

`sourceResource()`保留业务版本；`resource()`派生的版本同时绑定业务资源指纹、路径、名称、大小和摘要。权限判断及签名链接使用后者，不能只签业务编号、大小或mtime。任何索引字段或资源属性变化都会使旧下载上下文失效。

## 最小接入

```php
// 这些目录由部署创建，源与快照目录都在实际Web根目录之外。
$downloads = new SoSecurity\Download\Downloads(
    '/private/files', '/private/download-snapshots', '/srv/site/public'
);
$file = $hostFiles->loadReadyFile($tenant, $id); // 返回Download\File|null
$request = new SoSecurity\Download\Request($actualMethod, $actualBoundedHeaders);
$access = new SoSecurity\Download\SessionAccess(
    $sessions, $authorizer, $tenant, $currentSubject, $actualSessionToken,
    $requestGuard, 'file.download'
);
$transfer = $downloads->prepare($file, $request, $access, function ($scope, $type, $id) use ($hostFiles) {
    return $hostFiles->loadReadyFile($scope, $id);
});
try {
    http_response_code($transfer->status());
    foreach ($transfer->headers() as $name => $value) { header($name . ': ' . $value); }
    $transfer->send(function (string $chunk): int {
        echo $chunk;
        return strlen($chunk); // 仅证明交给输出层，不证明客户端完整收到。
    });
} finally {
    $transfer->close();
}
```

宿主先处理`$file === null`，不能将null传入prepare。示例中的身份、索引、请求保护和输出回调是宿主职责。请求保护校验必要的CSRF、来源、请求与字节预算；由SessionAccess在首次授权时调用一次，后续读取反复复核共享会话和当前对象权限。自定义`Access`和`Grant`也是受信服务器适配器，不能根据客户端提交的“已授权”标志构造。

组件导入和配置不启动Session、不发送响应头、不创建业务表、不联网。`Security::downloads()`需显式配置`downloads.directory`、`temporary_directory`、`document_root`及可选`policy`，创建工厂时才检查实际目录。只读诊断报告配置和需人工确认的边界，不显示私有路径。

## 原生页面配置与宿主表

页面真实验证密码与SQL当前身份；私有下载在读取文件索引前先核验当前会话，匿名访问存在／不存在的编号均拒绝且Cookie行为一致。仅文件所有者的reader／editor能私有下载，所有者editor能签发／撤销分享。公开分享读取不依赖Cookie身份；可重复GET、一次GET及CSRF保护的明确POST兑换使用不同签名目标。页面不自动创建账号、业务表、目录、密钥或并发账本。

以下环境变量必须由可信部署提供，不能从请求参数生成：

| 变量前缀SOSECURITY_DOWNLOAD_EXAMPLE_ | 值 |
| --- | --- |
| DATABASE | Web根外0600私有SQLite数据库 |
| STORAGE | Web根外0700共享FileStore规范绝对目录，命名空间download-example；原生入口拒绝放在实际Web根下的状态目录 |
| KEYS | Web根外0600／最大16KiB JSON，结构与[签名链接](signed-links.md)相同；current和keys，密钥值为规范base64 |
| ORIGIN | 固定HTTPS来源及必要端口，精确匹配实际Host |
| ROOT／TEMPORARY | 已存在的私有源／匿名快照目录 |
| DUMMY_HASH | 与实际密码配置相同算法／成本的有效占位哈希，不是真实账号密码 |
| PATH | 可选，默认/authorized-download.php，须为实际部署路径 |
| HTTPS | 默认开启；仅隔离本机测试显式0允许HTTP；不信任任意Forwarded／X-Forwarded-Proto |
| BUDGET_KIB | 可选1—1000000，默认65536；站点每60秒完整源文件KiB预算 |

SQLite需具有`download_accounts(tenant,subject,username,password_hash,version,enabled,roles)`，主键`(tenant,subject)`，同租户username唯一；roles是有界JSON字符串数组，enabled严格0／1。文件索引`download_files(tenant,id,owner,version,relative_path,filename,bytes,sha256,state)`，主键`(tenant,id)`；所有示例业务租户固定`download-example`，仅`state=ready`可读取。宿主负责迁移、合法记录、大小／摘要的上传时计算及更新事务。当前所有者的有效密码身份指纹进入文件资源，改密、禁用、角色变化使旧签名失效。

部署时由授权CLI一次初始化同一存储与策略的并发账本：

```php
$store = new SoSecurity\Storage\FileStore($privateStorage, 'download-example');
$leases = new SoSecurity\Concurrency\LeaseManager($store, new SoSecurity\Concurrency\LeasePolicy(4, 30, 30));
$epoch = $leases->initialize('download-example', 'transfers');
// 保存部署／恢复记录；HTTP获取遇到账本缺失直接拒绝，不能每次自动initialize。
```

示例在真实授权后，原子预占请求数和向上取整的完整源文件KiB（空文件也计1），再取最多4个、30秒期限的并发租约。单字节Range和HEAD仍核验完整源，使用相同成本。重试、已消费一次性链接、读取失败与租约满额不退还已提交预算；已消费链接不会因资源预算失败恢复。传输期间复核租约，finally释放；崩溃由期限回收逻辑名额，文件描述符由进程关闭。该配额约束尝试窗口与并发，不代替磁盘硬配额、恶意同UID防护或基础设施一致性。

登录／管理及POST兑换采用宿主Session的CSRF令牌，登录与退出更新ID并废弃旧控制令牌。开始流式输出前关闭Session锁，Cookie头在输出前完成。只有预输出错误返回有界JSON／页面；部分输出故障仅停止流和记录固定`download.stream_aborted`，不记录密码、URL、路径或异常正文。反向代理部署须由可信Web服务器设置实际HTTPS状态，组件不接受客户端伪造的代理头。

## 私有快照与异常

1. 在读取源文件前验证当前访问权限，重载权威索引并复核版本。
2. 检查私有目录链、源文件类型／链接数和文件描述符身份；拒绝符号链接、硬链接、设备、管道及Web可读目录。
3. 将完整内容按块复制到私有、创建后立即解除目录链接的快照描述符，核对完整大小和SHA-256；检查复制前后文件及目录身份。
4. 返回传输对象前再次重载索引和授权；每块读取前后均复核当前权限、元数据和期限。源文件随后被替换，也不会改变已验证快照的字节。
5. 拒绝、依赖故障、时间倒退、超时、输出异常或部分写入停止后续输出并关闭快照；输出回调返回后也检查期限，最后一块读完不能将晚返回当作完成。组件不重新打开源路径进行“最终输出”。

同一`Transfer`的`read()`、`send()`、`status()`和`headers()`不允许从其授权、元数据、读取、输出或关闭回调内再次调用。重入会关闭传输并使其失败；回调捕获重入异常也不能继续成功返回。宿主应在`send()`之前读取状态和响应头。`bytesRead()`和`complete()`仍可用于观察状态，`close()`保持幂等；已输出内容不回滚、不重试。

已交给宿主输出层或客户端的内容无法追回；权限检查与外部数据库变更也不是一个全局原子操作。检查响应头后仍可能在后续块失败：宿主不得向部分文件追加JSON／HTML错误页，不得再次发送已提交的头或自动重试输出。`bytesRead()`表示已返回／读取的字节，`send()`返回写回调确认的字节数，均不证明网络交付。

## 方法、Range和响应

仅接受显式GET／HEAD／POST。GET支持单个字节范围、后缀和开放末端；拒绝多范围、溢出或不满足范围。HEAD不返回正文且忽略有效Range；POST不按Range切片。`If-Range`只有与当前强ETag精确一致才部分返回，其他值完整返回。`If-None-Match`和`If-Modified-Since`不产生304，也不能绕过当前授权与内容核验。

固定使用`application/octet-stream`、attachment、UTF-8文件名、安全ASCII备用名、nosniff、no-store/private、no-referrer和受限CSP。默认禁止将下载直接作为内联HTML／SVG展示。`RangeException::totalBytes()`仅在当前授权后提供范围计算中的总大小；未经授权的拒绝不得自行补上私有大小。

`LinkAccess`验证本次真实签名URL、请求方法及可选绑定，`targetFactory(File)`必须使用`File::resource()`。可重复链接在传输期间复核共享撤销状态；一次性链接在开始授权时消费，仅用于本次有期限传输，后续失败不退款。一次性链接的HEAD和Range拒绝且不消费，允许改用完整请求；不能将消费过的`VerifiedLink`当作未来下载授权。链接及URL不能写入日志或公开Referer。

## 默认资源预算与部署边界

策略在规范化前断开调用方数组的引用，默认值推导不改写原配置；修改原变量或返回的options不会改变已验证的大小、Range或时限预算。下载前仍按原大小预算拒绝文件，不能通过修改原变量放大读取上限。

| policy字段 | 默认 | 允许范围／行为 |
| --- | --- | --- |
| maximum_bytes | 20971520 | 1—268435456，完整源文件核验上限 |
| maximum_response_bytes | 同maximum_bytes | 不超过完整文件上限，范围请求仍核验完整源 |
| io_milliseconds | 3000 | 1—30000，授权／锁等待／复制共用预算 |
| send_milliseconds | 30000 | 1—30000，传输对象创建后总预算 |
| chunk_bytes | 65536 | 1024—262144，有界读取和复制 |
| ranges | true | 严格布尔值，一次性链接仍不支持Range |

源目录和快照目录必须是已存在的规范绝对路径，目录不允许组／其他用户访问；文件至少所有者可读且无组／其他权限，链接数为1。快照目录须可写。仅支持受信本地POSIX文件系统，不声称覆盖Windows ACL、网络文件系统或同UID恶意进程；部署也须保护父目录、挂载、备份与其他Web映射，配置一个document_root不能发现所有虚拟主机映射。快照会占用完整文件的私有磁盘空间，宿主必须组合全局磁盘／字节配额和并发租约。

期限在可检查的位置检测，不能强行中断所有内核阻塞I/O或宿主回调。生产需配套工作进程、文件系统与反向代理超时。组件逐块读取不代表宿主／代理没有缓冲；磁盘峰值、低内存、客户端断开及慢输出需分别验收。加速下载或对象存储需另行实现满足同等内容／授权边界的适配器，不能未经验证返回公开源文件URL。

参考：[HTTP Range语义](https://www.rfc-editor.org/rfc/rfc9110.html#name-range)、[Content-Disposition](https://www.rfc-editor.org/rfc/rfc6266.html)、[OWASP文件上传与私有保存](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)。
