# TOTP、恢复码与密钥加密

提供 TOTP 计算、绑定确认、防重放、共享错误预算、恢复码和因子生命周期。宿主保留身份、权限、CSRF、会话及通知职责。TOTP 不是抗钓鱼认证；WebAuthn 在完整精修路线中另行实现。

## 配置

TOTP 计算仅使用核心 hash；加密因子管理要求支持 XChaCha20-Poly1305 的 `ext-sodium` 与 64 位 PHP。缺少扩展抛出 `dependency.sodium`，不会改用明文或其他算法。组件兼容与运行时官方安全维护状态分别评估。

```php
// $keys 来自部署侧密钥管理器，值为独立生成的 32 字节随机密钥。
$cipher = new SoSecurity\Crypto\Cipher('current', $keys, 'my-site:mfa');
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/shared/security'],
    'mfa' => ['issuer' => 'My Site', 'cipher' => 'mfa_cipher'],
], ['mfa_cipher' => $cipher]);
$mfa = $security->mfa();
```

目录必须预先创建为私有可写目录并位于 Web 根目录之外。多节点使用共享 Redis/MySQL 等后端。工厂拒绝内存及 Session 作为 MFA 存储；直接构造时调用方必须满足相同契约。构造工厂不自动启动 Session、创建目录、建表或发响应头。密钥不进入源码、普通配置转储、URL 或日志。

`mfa` 选项：`issuer` 和 `cipher` 必填；`enrollment_ttl` 默认 300 秒（30—900）、`attempts` 默认 5（1—10）、`cooldown` 默认 60 秒（1—3600）、`algorithm` 默认 `sha1`（也支持 `sha256`/`sha512`）、`digits` 默认 6（可用 8）、`period` 默认 30 秒（15—120）。每个因子保存自身算法配置，修改默认值不会改变已绑定设备。

作用域包含可信站点／租户，主体来自服务器已验证身份，不直接采用访客提交的用户编号。

`Enrollment` 通过静态闭包保存含种子的配置 URI，`var_export()`、`print_r()` 和 JSON 导出不包含该值，并拒绝序列化／反序列化。只有显式调用 `provisioningUri()` 才返回配置；不要记录该返回值。进程内存、调试器或显式反射读取不属于普通导出防护边界。

## 绑定与登录

1. 宿主检查当前账号、权限、CSRF 和分配预算；替换已有因子还须近期强认证。
2. `begin($tenant, $subject, $accountLabel)` 返回 `Enrollment`。只向当前授权用户展示 `provisioningUri()`，可以用本地可信二维码渲染器展示；不得发送给外部二维码生成站。提供可访问的手动设置方式，响应使用 `Cache-Control: no-store`。
3. 在期限内提交 `id()` 和设备验证码，调用 `confirm()`。确认后才启用；替换过程中旧因子保持有效。
4. 成功返回十个 128 位随机恢复码，只展示一次，数据库仅存摘要。重复确认不会再次显示恢复码。
5. 宿主按策略撤销旧会话并记录通知任务。因子变更和宿主会话／通知不是跨资源原子事务；失败需要可追踪的重试与恢复。

登录先建立短期、受保护、绑定当前凭据版本的待 MFA 身份。执行 CSRF、预算及 `verify()`；恢复码使用 `verifyRecovery()`。成功后更新 Session ID 并建立完整身份；未完成 MFA 的身份不能访问受保护业务。

参见[接入示例](../examples/mfa-account.php)。回调由服务器实现，成功必须返回严格的 `true`；返回 `false`、空值或其他值以及抛异常都会阻止后续操作。不能将客户端“已授权”字段作为依据。

## 重放、预算和管理

- 接受当前步及前后各一个时间步；消费最高匹配步。绑定确认同样消费该步，同一因子的相同／旧步及并发重放都被拒绝。
- TOTP、恢复码和确认共享账号错误预算。成功清零，达到阈值进入有限冷却；冷却内请求不延长冷却。外层仍须控制跨账号／IP 滥用和分配成本。
- `regenerateRecoveryCodes()` 要求新 TOTP 证明并原子替换旧码。
- `disable()` 要求新 TOTP 或恢复码及宿主授权，删除因子与恢复状态。
- `revoke()` 是受控恢复／管理钩子，无验证器证明；宿主必须实现更强的恢复校验、审计、通知和会话失效，不得作为匿名接口开放。
- 结构损坏、解密认证失败、时钟倒退及存储失败拒绝相关操作；未知账号验证不分配记录。
- `status()` 只返回是否启用、因子 ID、待确认状态、恢复码数量和冷却秒数；审计不能记录秘密、验证码或恢复码。

## 加密和轮换

`Crypto\Cipher` 使用随机 24 字节 nonce 和 XChaCha20-Poly1305，封装版本、密钥 ID、用途及对象绑定。先限制大小再解码验证。修改内容、用途、对象绑定、版本或密钥 ID 都不能作为原对象成功解密。

默认明文预算 64 KiB，可设 1 字节到 1 MiB；绑定最长 1024 字节且不能为空。密钥为 1—8 个具名的 32 字节随机值。调试脱敏并拒绝序列化；运行时内存、进程转储和存储写权限仍属于部署防护边界。

轮换时先部署同时持有旧／新密钥并将新 ID 设为当前；按已知主体调用 `TotpFactors::reencrypt()`。它在事务外生成密文，以完整记录比较更新，遇到并发变更返回 `false`，调用方有界重试。确认记录及恢复备份符合策略后才移除旧密钥。宿主维护账号清单和进度，组件不提供全库扫描。

`Cipher::reencrypt()` 只生成新封装，保存仍需宿主事务或比较更新。诊断不能代替备份、轮换或宿主授权验收。

## 验证

覆盖 RFC 6238 独立向量、时间偏差／2038 后时间、确认、重放、恢复码轮换、冷却、替换、过期、撤销、密钥轮换、损坏状态及实际存储并发。当轮结果见[精修跟踪](security-refinement.md)；测试凭据和作者自检不代表实际账号或独立审计。

参考：[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)、[OWASP MFA](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)、[PHP sodium](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php)。
