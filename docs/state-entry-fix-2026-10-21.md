# F01 授权入口与保护存储包装修复

日期：2026-10-21（Asia/Shanghai）。状态：主 SDK 已修复，17 条有限专项命令已通过并收口；完整 F01／R1—R6 仍未完成。本次继续完成 G1 的真实入口接入，不新增计划需求或延长周期。

## 实际缺口与修复

旧快照的独立 SQLite 复现表明：已受保护的原始 FileStore 配合受保护会话，直接构造并调用无边界 `Grants::begin()`，请求守卫调用一次、提供器读取一次，会话文件和见证检查点均发生变化，随后才返回 `authorization.denied`。另一个复现中，`NamespacedStore(WitnessedStore)` 的保护标识被解包逻辑遗漏，三类认证构造器均接受省略边界。准确源码、输出和命令分别保留在[授权复现](state-boundary-evidence-2026-10-21/grants-entry-before.json)及[包装复现](state-boundary-evidence-2026-10-21/nested-store-before.json)，不是以帮助脚本失败冒充安全拒绝。

本次修改五份运行源码：

- `Grants` 构造时要求保护存储及保护会话使用显式、准确的共同边界；五个状态入口在请求回调、会话读取及写入之前检查活动上下文。早于目录保护登记构造的旧对象，在目录后来被登记后同样提前拒绝，不自动补接旧依赖。
- `FileStateBoundary::protects()` 解包 namespace 后仍识别 `WitnessedStore`，使会话、认证、持久登录和授权构造器覆盖这一 SDK 自带包装组合。
- `SessionRegistry::requiresStateBoundary()` 只返回保护模式；认证、持久登录及授权构造器据此拒绝“保护会话＋未保护存储＋省略边界”的混合服务图。
- 独立恢复的 `Grants::recoveryContext()` 同时核对显式边界字段，恢复测试服务图补上该依赖。

所有普通未保护服务仍可使用原构造形式。既有参数顺序、默认值和返回类型保留；`Grants` 仅追加第七个可选参数，另增加一个无参数布尔查询。251 个既有公开候选类型及其原成员全部保留，见[接口核对](state-entry-evidence-2026-10-21/api-compatibility.json)。没有改变授权记录、凭据格式或数据库结构。

## 显式接入变化

保护模式中的授权服务需要同一个准确会话、边界及被覆盖的存储：

```php
$grants = new SoSecurity\Operation\Grants(
    $store, $sessions, $authorizer, $grantRequestGuard, $grantPolicy, $clock, $boundary
);
```

这些服务在构造时不进入活动操作。使用时由正确的外层 `StateBoundary::authorized()` 及当前账号策略覆盖整个业务操作；构造成功本身不授予权限。不能在缺少边界时靠一次内部会话验证先产生新检查点，再操作授权存储。此前仅传入 WitnessedStore 的候选用法需要追加准确边界；保护模式尚未发布，不通过自动猜测依赖来兼容错误接线。

完整工厂接线仍未交付，不能把普通 `Security::operations()` 当作已启用保护的服务图。完整接口说明见[中文指南](state-boundary.md)与[English](state-boundary.en.md)。

## 固定验证与停止条件

新增 `tests/state-boundary/grants-entry.php` 覆盖：五个授权入口；提前构造后的目录登记；原始／克隆／namespace／保护包装；错误会话与混合保护模式；构造器拒绝之前没有回调、提供器、SQL、文件或见证变化；具体角色策略与当前账号策略批准下的合法操作仍可执行。它已加入常规边界套件；修复后的套件为 28 个固定用例，但本专项不重跑整组来替代最终候选门禁。

有限命令共 17 条：两端分别执行新增入口、普通授权、认证、持久登录、原始存储、独立恢复和公开 API；五份源码静态检查；入口语法；控制器自建禁 TCP MySQL 的新增入口与独立恢复。开始／结束摘要、准确命令和各自结果以[执行记录](state-entry-evidence-2026-10-21/execution.json)为准。17 条命令均退出 0；两端 SQLite／MySQL 入口各 71 条、独立恢复各 43 条通过，开始／结束运行输入摘要一致。控制器创建的 `/tmp/sosecurity-mysql-ku9toj35` 已关闭删除，[交付核对](state-entry-evidence-2026-10-21/delivery-check.json)已通过。

MySQL 组的目标账号及账本使用 MySQL，物理状态使用 FileStore；独立恢复管理员另用自建 SQLite 服务图。MySQL 专项通过 `tests/mysql_check.py --state-entry <runtime...>` 启动，仅运行这两项受影响用例，不重跑前一轮两端各 27 项。普通测试账号仅获自建数据库范围权限；这一组没有启用此前完整固定处置测试所用的全局 TRIGGER 权限，不能由此证明固定破坏性恢复已解决低权限元数据适配。

PHP7.2 继续使用私有原生单调时钟与 sodium，PHP8.5 使用当前本机解释器；SDK 用例保持 16 MiB。静态工具限额 512 MiB 与 SDK 预算分开；可选 turbo 扩展的 GLIBC 启动警告保留。API 检查脚本最初错误地把返回类型结构当成字符串而退出 1，修正脚本的数据结构判断后完成核对，原失败另有记录，未降低接口约束。

本组已达到 17 条命令通过、输入一致和临时 MySQL 清理的停止条件，不再扩测。后续继续完整工厂、全部生命周期／后台／API 授权写入者及最终安全恢复；不能以这个入口修复关闭完整 F01、R1—R6 或稳定版验收。
