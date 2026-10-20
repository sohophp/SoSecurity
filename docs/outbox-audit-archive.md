# Outbox 对账审计归档与密钥轮换

这是[原生对账](outbox-reconciliation.md)的可选同库分层归档。在线审计仍限 1000 条；最多 100000 条已完成记录可归档到独立历史表，完整证据、公钥快照、操作者和验证时间全部保留。在线／归档两组成员与封存摘要一起绑定到新版审计根，迁移在同一 PDO 事务提交。归档释放在线容量，归档历史仍占数据库与备份空间；到达归档上限会拒绝新增归档，不自动删除原始证据。

## 部署与升级

新建发送示例库的完整 DDL 已包含归档表；已有库由宿主管理流程执行[归档增量 DDL](../resources/sql/outbox-example-resolution-archive-sqlite.sql)。使用私有持久 SQLite、日志及 FULL／EXTRA 同步，普通请求不自动创建表或初始化根。

审计根、在线审计和归档表不得声明或被其他表通过外键引用，避免归档删除在线行时级联删除业务数据，或重封存时产生额外副作用。即使当前连接关闭外键执行，仍拒绝这些结构依赖；与审计表无关的业务外键可以保留。结构检查固定查询 main 数据库的内建外键信息，拒绝同名持久对象遮蔽，不修改连接的外键设置。

停止旧管理／工作进程，在当前已核验的发送端先运行 `--resolution-audit-status`，将其中 `root_hash` 独立保管为升级基线。备份整个发送业务库、接收检查点、私有配置与密钥，在发送 JSON 配置中显式设置布尔值 `"resolution_archive": true`，再使用该基线执行：

```sh
php examples/outbox-admin.php --initialize-resolution-archive="$AUDIT_ROOT_HASH"
```

该命令只接受与独立保留基线相符的已认证旧审计根和空归档表；错误基线、非空未登记归档均拒绝采用。不能对刚恢复的未知旧库临时计算哈希后将其当作最新权威基线。首次初始化推进**发送审计根**为格式 2，保留全部原在线记录，重复执行不重置状态。它与 SDK 队列格式 2、接收业务根格式 2 分别属于三个独立状态域。原对账审计根已经是格式 2 时，不能关闭配置开关或回退旧代码继续工作。

如果从未初始化对账审计，可在准备好归档表和开关后执行原 `--initialize-resolution`，直接创建空格式 2 审计根。原配置省略开关时仍使用格式 1；未经显式启用不读取归档历史或调用归档命令。

## 分页归档与查询

```sh
php examples/outbox-admin.php --archive-resolution
php examples/outbox-admin.php --archive-resolution --after="$EVENT_CURSOR"
php examples/outbox-admin.php --resolution-audit-status
php examples/outbox-admin.php --resolution-audit-list=archived
php examples/outbox-admin.php --resolution-audit-list=archived --after="$EVENT_CURSOR"
php examples/outbox-admin.php --resolution-status="$EVENT_ID"
umask 077
php examples/outbox-admin.php --export-resolution-audit="$EVENT_ID" > audit.json
```

每批最多检查 20 条在线审计，返回 `examined`、`archived`、`next_cursor`、`complete`。游标是原始事件编号，须使用返回值，不能用条数推算；新一轮从空游标开始。以下记录会跳过并保留：仍处于 prepared、未满足保留时间，或 SDK 队列行仍存在。先按原命令完成队列维护与保留期，再归档已清理的 resolved 审计。

`--resolution-audit-status` 返回当前已认证的格式、在线／归档条数、容量、启用状态和修订号，不输出证据或密钥。达到容量时先核对状态；一次归档页不能容纳时整页回滚，记录继续留在在线表。

`--resolution-audit-list=active` 或 `=archived` 每次返回最多 20 条经过目标签名复核的审计元数据，包含事件编号、状态、结论、操作者、验证时间与证据摘要；使用返回游标继续查询。列表不输出完整证据或公钥，单条原文通过专门导出命令取得。

命令重新验证当前 `outbox_admin` 与 `outbox_reconciler`、配置和文件身份、在线审计封存、原签名及当时验证时间，并在事务中核验 SDK 队列的封存成员历史。归档完整复制原封存行、删除原在线副本并更新审计根；SQL、权限或提交前校验失败会一起回滚。COMMIT 结果不明时用新连接查询状态或重复同一归档页，不能手工删记录修复。

启用归档后的状态结果增加 `archived`。已归档记录继续通过当前管理权限查询、重复导入原证据或导出完整审计；历史读取独立于原业务订单是否仍保留，原签名证据的在线公钥也可以按已说明的规则移除。`--export-resolution-audit` 每次只返回一条已完成的已认证记录，不写文件、不删除记录，不自动信任导出的数据；如需独立保管，由宿主受控备份／审计系统接收。

根记录每次分批验证在线与归档成员集合：最多 64 条一页；归档历史只投影有界元数据与实际 BLOB 类型／长度。对目标记录的读取、导出及重封存仍完整验证 HMAC、规范结构、原证据签名与验证时间。同长度正文损坏会在目标验证时拒绝，元数据计数或摘要不匹配也会拒绝；分页成员校验不等于一次打开所有归档正文做完整内容巡检。

成员分页按明确限定的原表主键排序，避免按有界投影的同名别名排序而反复创建临时排序树。字段字节上限、存储类型检查和超限拒绝仍然保留。

归档是同一数据库内的在线／历史分层。备份和恢复须同时保留审计根、在线表、归档表及 SDK 队列／业务历史；单独恢复旧表或删除归档会被拒绝。全部历史及外部配置一起回退仍需宿主的独立恢复基线，HMAC 本身不证明最新版本。

## 有界重封存

签名公钥快照与审计 HMAC 密钥用途不同。移除旧在线接收公钥后，已经接受的证据仍可读取；移除旧 HMAC 密钥前，必须先完成所有在线和归档记录及队列根的重封存。

1. 私有封存密钥文件加入新密钥并将 `current` 指向新编号，同时保留旧密钥。新材料不能与投递或幂等密钥复用。
2. 依次遍历在线和归档审计：

```sh
php examples/outbox-admin.php --rekey-resolution=active
php examples/outbox-admin.php --rekey-resolution=active --after="$EVENT_CURSOR"
php examples/outbox-admin.php --rekey-resolution=archived
php examples/outbox-admin.php --rekey-resolution=archived --after="$EVENT_CURSOR"
```

3. 按正常游标维护 SDK 队列，使其记录与根也切换到新封存密钥；两端其他独立状态分别按各自流程处理。
4. 核对所有历史键编号都完成迁移、保留完整备份并停止旧进程后，才从当前配置移除旧密钥。不能根据单页 `complete` 推断其他记录集合也已遍历。

每批最多 20 条，返回 `examined`、`rekeyed`、`next_cursor`、`complete`；原证据、验证公钥和业务字段不改写。未过期的 prepared 记录也可重封存，但不能归档。未知旧键、损坏证据或重复成员会拒绝迁移，不能借新签名确认损坏数据。

## 验证边界

`tests/outbox-resolution-archive.php` 覆盖同 PDO 提交／回滚、提交后结果未知、两阶段真实 SIGKILL、归档后查询／导出、旧密钥完成迁移后移除、满额容量释放、未清理／prepared 跳过、16MiB NUL 大字段及同长度篡改拒绝。容量填充使用明确的合成封存待处理元数据；被归档记录及释放后进入的新记录均由实际原生流程产生，不把合成容量数据视作真实远端业务。

`tests/outbox-archive-schema.php` 覆盖入站／出站外键、外键开关、大小写与结构查询遮蔽；拒绝后业务子记录和审计根保持。`tests/outbox-archive-budget.php` 与 `tests/outbox-index-budget.php` 分别检查十万条合成归档元数据和一万条已封存合成队列记录的内存与实际查询计划，不将合成数据视作真实投递验收。

本地执行结果见[验证记录](verification.md)。权威业务恢复对接及完整 R4.3 门禁继续；没有据此完成生产恢复、独立审查或全部 R1—R6 规划。
