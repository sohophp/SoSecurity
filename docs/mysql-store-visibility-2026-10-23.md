# MySqlStore 触发器元数据可见性修复（2026-10-23）

此前只检查 information_schema.TRIGGERS 是否为空；没有 TRIGGER 权限的账号可能看不到真实触发器。隔离 MySQL 上已复现普通数据账号仍执行一次回调并提交一条触发器副作用，见 [before.log](mysql-store-visibility-evidence-2026-10-23/before.log)。失败证据保留。

MySqlStore 现在在构造以及每次自有事务内验证当前账号的直接表／库 TRIGGER 权限；全局直接权限需在 partial_revokes=OFF 时才能作为证明。权限与触发器存在状态放在同一 SELECT 中，防止已复现的表／库权限证明与触发器查询之间的撤权间隙。账号标识有长度和字符约束；仅角色授权或无法证明可见性默认拒绝。任何可见触发器仍拒绝，不能以“为空”代替可见权限证明。源码只改 MySqlStore 的私有校验方法，精确差异见 [runtime.patch](mysql-store-visibility-evidence-2026-10-23/runtime.patch)。

## 兼容与部署

请求数据库账号除了 SELECT／INSERT／UPDATE／DELETE，须具备上述可证明的直接 TRIGGER 权限。旧文档“只需数据权限”已更正。SDK 不授予权限、不创建触发器、不迁移数据；权限由宿主部署流程管理。规范 DDL、数据格式、公开 API277、事务边界和默认预算不变。缺少权限时使用既有 configuration.schema 拒绝原因；底层 PDO 异常仍脱敏。

实测 MySQL8.0.46。全局权限证明涉及 partial_revokes，其他 MySQL／MariaDB 版本未验证；不能把本批结果扩展为这些版本的通过结论。此次没有 SQLite 运行时变更，未重复其完整矩阵。

## 本地验证

新增 tests/mysql-store-visibility.php 覆盖缺少权限（有／无真实触发器）、直接库／表／全局授权、仅角色授权、partial_revokes、对象创建后撤权、表／库查询间撤权，以及撤权后的过期清理。拒绝发生在业务回调和状态修改之前，过期清理拒绝时保留已有状态，事务退出后保持可用连接。每轮只创建和清理自有私有服务器上的合成账号与测试数据。

已执行并通过：九版权限专项9项程序／639项断言；PHP7.2／8.5 驱动与事务14项、索引18项、触发器24项；九版异常脱敏36项程序／288项断言；归档与两端全新消费者6步；PHPStan和API277。静态分析可选turbo扩展因GLIBC不匹配不可用，普通分析正常完成。

初轮异常专项在PHP7.2有2项通过、2项失败，PHP8.5未执行。旧测试依靠触发器制造错误，但既有触发器保护会在数据操作前拒绝；用本轮修改前源码也复现同样失败（errors-baseline.log／json）。现保留原脱敏、回调、事务及数据保留断言，将故障注入移到目标数据语句前，由私有MySQL执行SIGNAL，并新增注入确实发生的断言。九版36项补验通过，初轮失败记录未改写。见errors-fixed.json及errors-test.patch。

最终结果见 [verification.json](mysql-store-visibility-evidence-2026-10-23/verification.json)，运行时摘要见 inputs.json。归档、离线新消费者安装、PHP7.2／8.5 加载来源和消费者实际 MySQL 权限专项见 [archive-fixed.json](mysql-store-visibility-evidence-2026-10-23/archive-fixed.json)。首轮 fixed-first.log 是补入清理场景前的65断言快照，最终矩阵每版71断言，两者不混计。

此为独立存储专项，不是完整稳定版验收。默认 MySQL 凭据签发预算、历史 PHP7.2 墙钟失败及其他未齐门禁继续开放；暂缓交接、未知回执续办、最终恢复及外部验收均未执行。goal 保持 active，没有提交、推送、部署或生产数据库操作。
