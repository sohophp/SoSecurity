# CSRF／验证码的原生完整状态连接

原计划把一次性请求证明、已消费记录和验证码尝试次数列为受保护效果。原 Security::csrf／captcha 工厂只有独立 tokenStorage 路径，无法显式加入实际认证见证；预算目录隔离并不能替代证明状态见证。本批补齐 FileStore 原生连接，不以新增拒绝替代实现。

新增 StateProofConnection，构造时绑定准确 StateBoundary、LocalStateWitness、CompositeStateSnapshot、FileStateSnapshot、FileStore、站点、权威 scope、安全代际及同一个 Clock。完整来源可同时包含实际账号 SQL、会话／因子文件和其他已声明来源。只具体支持 FileStore；没有声称 MySqlStore、Redis 或 PHP 原生 SessionStore 已有完整快照适配。

## 接入

宿主先构造已有完整来源和见证，在其覆盖目录声明站点的 tokens 命名空间；不是另建孤立于账号来源的证明见证。

```php
$proofStore = new SoSecurity\Storage\FileStore($coveredDirectory, $site . ':tokens', $clock);
$proofs = new SoSecurity\Account\StateProofConnection(
    $boundary, $witness, $source, $files, $fileSourceName,
    $proofStore, $site, $authorityScope, $epoch, $clock,
    $currentRequestAuthority
);
$csrf = $security->csrf($proofs);
$captcha = $security->captcha($proofs);
```

currentRequestAuthority(action, authorityScope, proofScope, browserBinding) 必须只读，验证当前实际浏览器／请求及准入权限，返回有界 UTF-8 不透明调用者标识；null／false 拒绝，true 不是调用者标识。不要伪造账号身份，不要在回调中再次消费 CSRF、扣除独立预算、投递或执行业务。action 精确为 proof.csrf 或 proof.captcha 后接 issue／verify／revoke。示例变量须由宿主实际依赖提供，不是可直接执行的安装脚本。

证明校验在后续认证／业务的外层保护操作之前单独执行；不允许嵌套借用已有活动边界。独立请求预算仍须物理隔离。password-reset 保留给已有原生 ResetTokens 连接，不允许通过 CSRF 新连接冒充该流程。

## 行为和限制

- 只读准入检查完整摘要、当前请求授权、物理文件容量、记录格式和 64 KiB 编码预算，再持久化准确意图。签发随机值在准入之外产生，意图仅保存摘要，不保存答案、令牌或浏览器绑定正文。
- 正常 CSRF 错误证明／重放和拒绝不创建 pending；重复使用 CSRF 在状态无变化时只读。验证码错误答案仍按原规则扣除尝试次数，并且这次写入也经过见证。
- 实际消费、签发和撤销在活动边界内使用原 FileStore 原子写入；写入前后复核同一当前调用者、期限和时间。后期失权／到期保留 pending 和 account.completion_unknown，不重试、不续办、不恢复已消费证明。
- 原始同物理域 FileStore／组件不能绕过访问门槛。回写旧的已消费证明文件会在请求授权回调之前被完整来源摘要拒绝。纯格式错误仍可直接返回 false。
- 时限对象创建失败不会留下连接 busy 状态；这只是恢复测试注入的时钟故障，不是恢复账号或未知回执。
- 新连接的默认操作时限为 1000ms。未为通过测试延长时限；矩阵中一次时限失败保持开放。

## 兼容与 API

普通模式调用方式及数据格式保持。CsrfTokens／Captcha 构造函数和 Security::csrf／captcha 增加末尾可选连接参数。保护模式现在要求显式连接，省略时 configuration.state_proof，不能继续悄悄使用未纳入见证的证明存储。连接采用自己明确声明的 store，不用独立预算 storage 替代。

公开类型从 271 增为 272。已逐项核对新增 StateProofConnection、StateOperation::proof 及四个可选参数的候选差异；没有删除旧类型或改变原参数顺序。连接时钟、授权故障分别为 proof.clock／proof.authority_unavailable，原异常链不透传。

## 本地证据

[证据目录](native-proof-evidence-2026-10-22/)：

- matrix.json：PHP7.2—8.5 九版 99 条定向命令，98 通过、1 失败。覆盖原生基本行为／旧文件恢复／消费后失权／准入及消费后到期、真实认证工厂、原有 CSRF 时限／基础／验证码／会话及 API 反射。PHP8.5 的 restore 场景在准备签发阶段触发 proof.timeout，转为 account.completion_unknown；没有执行到恢复断言，不能算通过。完整失败日志保留，未重跑该源码矩阵项以覆盖失败。
- race.json：九版四进程消费，9/9 通过，每次恰好一个成功，最终见证 current 且完整摘要一致；只清理自己创建的进程和资源。
- deadline.json：九版真实 Deadline 构造故障，9/9 通过；失败未写状态且连接可继续合法操作。
- mysql.log：私有无 TCP MySQL，PHP7.2／8.5 各五个原生场景及真实认证工厂，共12套通过。这里是完整来源包含 MySQL，不是 MySqlStore 证明后端适配。
- static-final.log：最终 PHPStan 通过；可选 turbo 扩展 GLIBC 环境警告保留。completion.json 记录两端 20 项语法检查通过和最终源码摘要；shell／Python 入口及相关空白检查通过。
- archive.json 与 archive-final.json：首轮 12/12 通过；最后故障清理顺序调整后的归档、安装、两端来源／正常原生场景／Deadline 故障／认证工厂复验 10/10 通过。后者的六个运行时文件摘要与最终源码逐项一致。消费者使用归档、离线 Composer 非符号链接安装，验证真实 vendor 来源。后续消费者通过不覆盖前述源码矩阵的超时失败。

以上是本批范围证据，不是全项目或完整稳定版验收。既有持续时间超时及本批超时没有被解释或关闭。后续仍需核对通知／Outbox 写入者和其余独立非暂缓入口；工作进程跨代交接、未知回执续办、最终账号恢复启用及完整 F01 继续暂缓。外部验收未执行。没有提交、推送、部署或生产访问，goal 保持 active。

> 后续请求证明最终返回复核：见[签发／验证／撤销的最终权限与时限](proof-return-2026-10-22.md)。公开清单仍为273；已提交状态不退款或恢复，历史失败及其他缺口保持开放。
