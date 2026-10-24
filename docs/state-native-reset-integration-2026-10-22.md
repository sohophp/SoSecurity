# 原生重置证明与同边界密码 SQL

日期：2026-10-22。继续既定 F01／G1／R2.6；31 项、80 个有效工作小时上限保持。ResetTokens 是一次性证明原语，完整邮件／MFA／账号恢复仍由 Account\Recovery 负责，本次不创建第二套恢复流程。

## 工厂与实际绑定

`Security::resetTokens($ttl, $stateAccountPolicy, $requestGuard, $addressColumn='address', $addressVersionColumn='address_version')` 显式接入完整状态账号策略和当前请求授权。要求准确的 witness／source、认证 FileStore、Clock、SessionRegistry、站点，以及实际 SQL 中独立的邮箱／邮箱版本列。字段不能重叠或借用密码、角色等其他映射；构造只验证声明，不查询数据库或调用授权函数。不同 ttl 分别缓存；同一缓存禁止更换账号映射、邮箱映射或请求授权对象，语义等价的状态策略对象可以复用。保护模式未传策略仍拒绝，普通 `resetTokens($ttl)` 沿用原行为。

原生对象提供 `issueFor(scope, subject)`、`consumeFor(scope, subject, token)`、`revokeFor(scope, subject)` 及 `withConsumption(scope, subject, PDO, tables, token, work)`。拒绝旧的 issue／consume／revoke，避免调用方在锁外自称账号版本；普通对象和既有手工保护接线继续使用原方法。手工保护方法先检查已进入准确边界，再进入底层令牌路径。

准入在独立见证排他锁内从完整来源重建真实账号、有效密码身份、当前因子目录／物理因子绑定、邮箱和邮箱版本。绑定包含站点、scope、subject 和这些实际字段的摘要；不是请求中的版本字符串，也不要求宿主恰好同时递增 credential_version。密码哈希、角色、MFA 绑定、账号状态或邮箱版本变化会使旧绑定失效。native AccountRecord 保留真实 SQL 凭据版本，供宿主按当前行做条件更新。

原生请求授权签名为 `(string $entry, string $scope, ?AccountRecord $record): bool`，entry 为 issue／consume／revoke／execute。它必须严格返回 true，只读、不输出、不交付邮件、不改状态；异常统一为 reset.request_unavailable，false 为 reset.request_denied，均在 pending 前结束。原生对象拒绝误传另一种签名的 StateRequestGuard。当前账号不存在、未启用、未验证或当前因子状态不可用时不生成证明；授权函数须接受 null，宿主对外响应必须遵守既有防账号枚举策略。

**这个回调是宿主明确的请求／恢复授权，不是 SDK 替宿主完成 MFA。** issue 可用于受信任服务器的恢复请求处理；返回值是秘密，只能交给既有受保护交付流程，不能作为匿名 HTTP 响应。consume 或 execute 须由宿主验证实际路由、方法、CSRF、预算以及适用的 MFA／独立恢复审批；revoke 须有当前撤销权限。SessionRegistry 依赖用于准确服务图和当前身份重建，本身不意味着调用者已登录或已获得恢复批准。需要完整邮件、强恢复、通知和队列事务时继续使用 Account\Recovery。

## 准入与事务

真实证明代际、原账本、格式、有效期和单次消费资格在 pending 前读取。未知／过期／已消费证明、无当前账号以及空撤销不写 pending；格式错误在状态读取前返回拒绝。每个绑定沿用四个证明容量及旧的最早项淘汰规则。revokeFor 只撤销当前实际绑定；命名空间范围的旧证明统一退役仍使用 StateProofRetirement，不能把这两种范围混淆。

pending／current 的准确描述包含 password.reset.issue／consume／revoke／execute、显式请求摘要、目标账号摘要、实际身份／邮箱绑定、证明摘要、声明表名、观察来源摘要和原生策略摘要。请求摘要不伪装成当前账号登录；根记录不保存原令牌、密码／哈希、邮箱或会话秘密。描述本身不是批准能力。

`consumeFor` 只完成本次证明消费，不能作为后续写入的缓存权限。业务写入用 `withConsumption`：在同一见证内消费，独占一次 SqlTransaction，调用一次 `work(PDO, AccountRecord)`，提交前后检查时间和证明期限，最终见证确认后才返回结果。传准确 PDO 和完整实际效果表声明；work 不得输出、外部 I/O、DDL 或控制事务。密码策略、泄露检查和昂贵哈希须在消费前按原有预算执行；work 用当前 AccountRecord 比较更新密码／凭据版本，不能自动删除 MFA 或登录。

```php
$proofs = $sdk->resetTokens(1800, $statePolicy, $hostResetRequestAuthority);
// 完成密码策略与所需 MFA／独立恢复授权后，消费当前证明并条件更新。
$result = $proofs->withConsumption($scope, $subject, $pdo, $completeAccountTables, $token,
    static function (PDO $connection, SoSecurity\Account\AccountRecord $current) use ($accounts, $newHash): string {
        $changed = $accounts->replacePassword($current, $newHash);
        if ($changed === null) {
            throw new SoSecurity\Exception\SecurityException('Current account changed.', 'reset.conflict');
        }
        return 'applied';
    });
// null 表示本次没有有效证明；只在整个调用成功返回后发送成功响应。
```

宿主 Repository 必须使用同一 PDO，完整声明其全部效果。不会自动清理全部会话／API／通知记录；实际密码版本会使依赖当前身份的旧授权失效，其他授权仍按完整恢复清单处置。SQL 回滚、证明到期、提交后最终见证失败均保留 pending，已消费证明不退款、不自动重放。

## 冻结验收

[执行清单](state-native-reset-evidence-2026-10-22/execution.json)固定八条命令：PHP7.2／8.5 × SQLite／私有 MySQL，各执行四个原生重置专项、既有 Links 工厂、三个证明退役兼容专项及三个真实 SIGKILL 点。SQLite 另执行原普通重置 SQL 与低层代际。其余四条为两端公开契约、PHP7.2 目标静态分析和 PHP7.2 语法；保护图 16 MiB，普通专项 8 MiB。源码／测试／契约输入冻结，PHP7.2 沿用私有 sodium／posix／CLOCK_MONOTONIC 环境，不声明系统原版 PHP7.2 验收。

测试单独修改邮箱版本而保持密码版本，旧证明应在 pending 前拒绝；通过真实密码／TOTP 会话构建宿主只读授权，条件更新真实 account_example 密码，保持 MFA 必需，之后新密码仍须 TOTP 登录。回执独立重建准确字段；根记录不得包含原始令牌／会话／密码哈希。确定性回滚／到期／提交后未知结果不重放。

真实停点为 pending 持久化后、密码 SQL 修改后提交前、SQL 提交后 current 前。控制器真实 SIGKILL，新进程重新打开 PDO／服务，必须在请求授权和 work 前拒绝 pending；中间停点另有等待同一锁的竞争者。测试读取器现在按明确 format／generation 重建原权威，避免把格式 3 限定为含文档表的宿主。

冻结前静态冗余类型判断和工厂测试残留 operations 配置失败见[预检记录](state-native-reset-evidence-2026-10-22/preflight-notes.md)。最终结果以冻结清单与交付核对为准。

**已执行并通过：固定八条命令全部退出 0，冻结输入前后哈希一致。** 四种组合的重置生命周期／拒绝／未知结果／工厂分别为 108／77／48／24 项；既有 Links 工厂 24 项、证明退役／拒绝／续办 81／78／221 项。SQLite 两端另通过原普通重置 SQL 21 项与低层代际 23 项。十二次真实 SIGKILL、四次等待竞争者均通过；新读取器在请求授权与 work 前拒绝 pending。两端 263 类公开契约、PHP7.2 目标静态分析及 845 个 PHP 文件语法通过，保留可选 turbo GLIBC 加载警告。

[交付核对](state-native-reset-evidence-2026-10-22/delivery-check.json)确认四个测试根、十二个中断子目录和两次私有 MySQL 全部清理，无在途测试。[库增量](state-native-reset-evidence-2026-10-22/library-delta.json)为五个既有源码文件；原普通重置／低层代际、Links 工厂、证明退役测试，以及旧重置示例和受管 HTTP 示例字节保持。[API 增量核对](state-native-reset-evidence-2026-10-22/api-additions.json)确认没有新增公开类型，新增九个方法（含敏感调试／序列化保护）；ResetTokens 构造函数追加七个可选参数，Security::resetTokens 追加四个可选参数。移除这些增量后与旧契约摘要完全一致。本批达到停止条件，不追加功能或扩测。

## 本批停止条件

本批通过只关闭上述原生证明原语入口及定向检查，不关闭完整账号恢复、生产邮件、实体设备、新入口 HTTP／浏览器、其他旧授权／写入者、维护容量统一核对、最终恢复启用及当前九版本完整门禁。上一业务宿主未解释 503 保持开放，本批不重复其诊断。没有提交、推送、发布；完整 F01／R1—R6 保持未完成。
