# 昂贵操作与危险功能清单

本清单对应[ASVS责任矩阵](security-control-matrix.md#安全编码与架构域逐项适用与证据)的15.1.3、15.1.5及15.2.2、15.2.5。它标识当前SDK及独立示例中可能大量消耗CPU／内存／I/O，或解析不可信二进制与文档格式、访问网络和持久状态的入口。表内限额来自当前源码或相应指南，是**单次组件调用**边界；宿主仍须限制进入该调用之前的请求体、每主体频率、全站并发、队列长度、工作进程内存／时间及下游消费方超时。清单不证明这些宿主限制已部署。

| 操作／入口 | 风险与当前单次边界 | 宿主需补足的隔离及调度 |
| --- | --- | --- |
| [ZIP只读预检](../src/Upload/ArchiveInspector.php) | 不可信中央目录和压缩内容交给`ext-zip`；默认归档16MiB、100条、单条4MiB、展开合计32MiB、10秒检查期限；先做有界目录预检，再只读逐项检查，不解压到目标目录 | 上传前授权和私有不可替换的来源文件；进程级内存／CPU／墙钟限制、每主体并发及真正提取器的独立审查。期限检查不能抢占正在执行的原生扩展调用，见[归档指南](archive-inspection.md) |
| [HTML清理](../src/Output/HtmlCleaner.php)与可选[HTML Purifier](../src/Output/HtmlPurifierSanitizer.php) | `DOMDocument`解析不可信HTML，之后可调用第三方语法器；默认输入64KiB、输出128KiB、2048节点／属性、深度64；禁实体展开和外部网络，非法编码／输出拒绝 | HTTP层先限大小、并发与超时；自定义清理器单独审查，实际渲染仍按上下文编码。DOM及第三方解析不是可中断CPU沙箱，见[清理指南](html-cleaning.md) |
| [图片上传验证](../src/Upload/Validator.php)及[策略](../src/Upload/Policy.php) | GD解码和重编码不可信图片；默认文件5MiB、最大4百万像素、估算工作内存128MiB；仅允许显式扩展名及内容类型 | 受保护临时文件、请求／并发／进程内存限制、真实扫描与私有保存；GD原生解码和宿主自定义文件类型须单独评估，见[上传指南](upload.md) |
| [ClamAV本地扫描](../src/Upload/ClamAvScanner.php) | 通过受保护Unix套接字向外部扫描进程发送完整内容；默认5MiB、5秒总期限，响应最多4096字节；超限／非完整准确回复拒绝 | 限制扫描队列、clamd进程资源与文件权限，维护病毒库；应用期限不能代替扫描守护进程隔离，见[扫描指南](upload-scanning.md) |
| [受限HTTP外连](../src/Http/Outbound/Client.php)及[cURL传输](../src/Http/Outbound/CurlTransport.php) | DNS、TLS、跳转与响应可能耗时或触达内网；默认总预算5秒、请求64KiB、响应1MiB、头16KiB、最多3跳；精确目的端、公开地址及连接对端逐跳核对 | 仅为确需跳转的用途配置跳转；按真实服务设置连接池、出口防火墙、并发及消费方超时，自定义解析／传输适配必须独立验收，见[外连指南](outbound.md) |
| [密码哈希／验证](../src/Password/PasswordHasher.php)与[成本预检](../src/Password/HashBudget.php) | 原生算法消耗CPU和内存；旧哈希字符串最多512字节，并拒绝超预算成本参数 | 登录前预占共享请求预算、限制并发并在部署环境校准成本；[校准CLI](../examples/password-calibrate.php)使用本地子进程，不在请求／构造时运行，见[密码指南](passwords.md) |
| [私有状态](../src/Storage/FileStore.php)、[RedisStore](../src/Storage/RedisStore.php)及[SQL Outbox](../src/Outbox/SqlOutbox.php) | 锁、事务、扫描和异常字段读取可能耗尽存储／工作者；Redis及SQL读取有类型与字节界限，Outbox正文在认证元数据及长度后读取 | 按作用域限制总键／队列容量、数据库连接池、锁等待和清理批量；保留持久恢复锚点与监控。组件内限量读取不限制整个宿主数据库的体积，见[存储](mysql.md)、[Outbox](outbox.md) |
| [近期审计事件索引](../src/Audit/RecentEvents.php) | 单站点最多64条、保留不超过86400秒；每次写入和受权查询均经共享原子状态事务，容量满会拒绝本次审计写入 | 在审计前限制匿名／主体流量并监控容量、锁等待及后端故障；宿主另行实现严格运维授权和长期不可篡改日志，见[审计指南](audit-budget.md#受权近期事件查询) |
| [持久上传隔离](../src/Upload/Quarantine.php)及[私有文件读取](../src/Download/LocalReader.php) | 需要处理文件版本、路径、扫描状态与读写竞争；路径／文件身份及状态检查已有定向测试 | 受保护私有目录、最小文件权限、磁盘配额、任务池和网络文件系统适用性审查；已向客户端输出的字节无法由后续拒绝追回，见[隔离](upload-quarantine.md)与[下载](downloads.md) |

当前`src/`未发现对不可信输入调用PHP`unserialize()`、PHP`eval()`、动态PHP文件包含或进程启动入口。`RedisStore`的`eval()`执行仓库固定Lua脚本，属于数据库侧代码执行能力，须限制Redis账号权限和脚本操作范围；[诊断器](../src/Diagnostics/Inspector.php)另执行固定`return 1`探测。此结论基于当前源码搜索，不涵盖宿主代码、第三方依赖或将来的变更。独立CLI示例中的`proc_open()`仅用于受限密码成本校准，不能开放为Web参数驱动的命令执行。

多项昂贵操作组合时，宿主应在开始前同时核对入口大小、主体预算和并发名额；业务操作与外部通知使用有界队列或显式异步工作流程，并让下游超时大于可控的服务端处理窗口。若无法满足，须在业务副作用前拒绝或返回明确的待处理状态，不能让调用方超时后盲目重试已可能提交的操作。具体限额和排队策略须按实际部署负载测量，不能从此目录推定生产容量。
