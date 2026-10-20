# R4.3 幂等、处理与事务发件箱验收

本页按完整 R4.3 要求核对实现与证据，不能用单个 Outbox 专项代替整个阶段。2026-10-17 已完成本地阶段验收：整合修复后九版常规门禁及下述补充入口均取得通过终态，473 程序文件哈希保持；四项初次浏览器运行环境失败及同源码复验分别保留。采用的日志由 `/tmp/sosecurity-key-export-a6rb_geg/r43-final-acceptance.json` 逐项列出；[验证记录](verification.md)说明快照、归档和外部边界。完整 R1—R6 的其他要求继续按[跟踪表](security-refinement.md)推进。

共享及 Webhook 独立结构校验已补齐入站／出站外键拒绝，并合入工作树与常规门禁；九版 SQLite／两版 MySQL 的正式依赖回归在同字节候选上通过。原版本完整矩阵与修复后的实际入口复验分开记录，实际工作树 30 组复验已通过，修复后 473 文件快照的完整九版矩阵已通过，补充门禁亦已完成，不能混作原始源码快照。

## 要求与对应证据

| 要求 | 实现与明确边界 | 验收入口 |
| --- | --- | --- |
| 持久接收与业务处理分开确认 | `SqlInbox` 接收确认不代表业务成功；`SqlProcessor` 验证真实正文、独立封存、原始来源和当前关联后领取／执行 | `tests/webhook-inbox.php`、`tests/webhook-processing.php`、`tests/webhook-body-budget.php`；两种 SQL 后端 |
| 处理状态、退避、人工重试与去重 | 有界候选／重试次数／期限；同 PDO 提交业务与成功状态，稳定业务唯一键防止接收历史重建造成重复效果 | `tests/webhook-processing-concurrency.php`、`tests/webhook-processing-factory.php`、`tests/webhook-processing-ownership.php`；真实进程终止、故障与事务替换 |
| 历史接收可信，处理不依赖在线签名密钥 | 接收时的独立封存证明原始来源；业务执行仍复核当前权限，不要求已接收消息重新取得提供器签名 | `tests/webhook_processing_history.py`，实际先验签后移除在线密钥，再使用无 sodium 的运行时处理 |
| 通用幂等绑定实际请求与当前权限 | `SqlExecutor` 绑定主体、操作和原始请求指纹；业务与结果同事务，重复请求当前授权后重放，冲突拒绝；到期键不复活 | `tests/idempotency.php`、`tests/idempotency-safety.php`、`tests/idempotency-body-budget.php`、`tests/idempotency-concurrency.php`；两种 SQL 后端 |
| 私有安全表不得触发外部级联 | Outbox、幂等、Webhook 接收／处理及 MySqlStore 检查入站／出站声明，不切换执行开关；业务外键保持独立 | `tests/sql-schema-dependencies.php`，两后端、真实子行保留及复用存储实例 |
| 事务所有权与宿主事务加入 | 公开执行器自行拥有事务；Outbox 入队加入同 PDO 的宿主事务，不擅自提交调用方业务，失败必须中止完整业务单元 | `tests/sql-enlistment.php`、`tests/outbox-safety.php`；旧 PDO 手工事务、保存点、DDL／提交替换及锁等待 |
| Outbox 身份、顺序、领取与有限重试 | 稳定事件／投递编号，逐聚合顺序与租约代次，确认丢失继续原编号；清理不重置顺序或复活旧事件 | `tests/outbox.php`、`tests/outbox-concurrency.php`、`tests/outbox-factory.php`；两种 SQL 后端、24 进程及真实 SIGKILL |
| 数据读取与输入资源边界 | SQL 限制元数据实际字节数，正文先核对真实二进制类型／长度；合法空 BLOB、NUL 和非 UTF-8 保留，超限在副作用前拒绝 | `tests/outbox-input-bounds.php`、`tests/outbox-body-budget.php`、`tests/outbox-index-budget.php`；8MiB PHP 限制、真实查询计划；不是数据库总 RSS 上限 |
| 原生生产、投递、独立接收与恢复 | 业务、幂等和出站意图同库提交；固定 HTTPS／DoH／证书与地址校验；接收保留独立业务账本、根和写前检查点 | `tests/outbox-native.php`、`tests/outbox-recovery.php`、`tests/outbox_native.py`；实际 CLI／TLS、未知确认、检查点恢复与旧文件拒绝 |
| 超期终态必须有可信证据 | 原事件、正文、挑战、目的端与接收代际绑定；接收端独有 Ed25519 签名，持久取消栅栏与发送审计，处置和审计同事务 | `tests/outbox-reconciliation.php`、`tests/outbox-reconciliation-concurrency.php`、`tests/outbox-resolution.php`、`tests/outbox_resolution.py`；独立协议互验和实际取消／签名／导入 |
| 审计保留、容量与密钥生命周期 | 同库归档保留原证据，在线／历史集合共同封存；当前权限下分页重封存与导出，拒绝级联副作用、旧升级基线和损坏历史 | `tests/outbox-resolution-archive.php`、`tests/outbox-archive-budget.php`、`tests/outbox-archive-schema.php`；真实旧源码兼容证据按已保存哈希复核 |
| 业务恢复不能重授旧权限 | 显式独立只读权限源；同一决定的角色、版本和对象关联来自一个一致视图，当前撤权持续生效，不自动信任备份权限 | `tests/outbox-authority.php` 与 `tests/outbox_native.py --authority`；真实备份及三类权限并发写进程 |
| 原生管理与消费者接入 | 管理操作当前强认证／CSRF／对象权限，Bearer 业务入口不依赖 Cookie；工厂／诊断／导入无隐式副作用，旧接口兼容 | `tests/webhook_processing_http.py --browser`、`tests/idempotency_http.py --tls --browser`、`tests/install.py`、`tests/archive.py`、`bin/api-contract.php` |

## 完整门禁命令

核心和关联回归使用 `python3 tests/mysql_check.py --matrix <运行时列表>`：运行 `bin/check.sh`，在自建禁用 TCP 的 MySQL 实例与私有 SQLite／Redis 上执行实际检查，不读取宿主数据库凭据。开启所有适用的 `SOSECURITY_REQUIRE_*` 标志，包括 `SOSECURITY_REQUIRE_AUTHORITY=1`，缺失必需依赖不能悄悄跳过。PHP7.2—8.5 九版逐一执行，模块缺失的可选能力单独说明。

另执行九版 `tests/outbox_native.py` 的默认与 `--authority` 两种模式、独立 `tests/outbox_resolution.py` 协议互验、独立消费者和发行归档；前两者使用独立网络命名空间、进程私有 CA 和本地服务。PHP7.2／8.5 额外执行处理管理与幂等业务的真实 TLS Chromium 验收。磁盘耗尽检查只允许 `bin/full-disk-check.sh` 创建的自有微型临时文件系统。

CI 配置显式安装 SQLite3、强制权限源能力，并执行私有 MySQL 全矩阵、两种原生 TLS 模式和终态协议互验；静态检查同时覆盖 SDK 和五个原生辅助文件。修改工作流不代表远端 CI 已运行。

## 宿主与外部验收边界

业务表、角色规则、可信身份来源、实际路由、迁移互斥、密钥保管和备份恢复由宿主负责。示例验证的是明确的测试权威源，不能替代实际发行方、真实邮件／业务系统、生产灾备或独立安全审查。

同一 PDO 的事务不能扩展为跨资源恰好一次。网络结果未知时保留稳定编号；接收去重、显式终态证据和业务对账共同处理。检查点只重放已封存的最后一个转换；更早备份、部分恢复或全部外部锚点共同回退，需要权威业务恢复，不能清空安全历史重新初始化。

本地阶段验收完成后仍保留这些宿主责任，其他 R1、R2.7、R4.4—R4.6、R5、R6 要求不会因此关闭。推送、公开发布和生产操作须分别按授权执行。
