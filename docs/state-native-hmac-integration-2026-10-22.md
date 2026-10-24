# 原生 HMAC：密钥配置来源、nonce 与业务 SQL

日期：2026-10-22。属于既定 F01／G1 与 R4.2 请求证明／重放覆盖；31 项、80 个有效工作小时上限保持。本批接入不可变 KeyRing 配置模式，不把任意在线 KeyProvider、Webhook 收件箱、密钥轮换迁移或最终恢复称为已完成。

## 配置也是实际状态

只保护 nonce 不足以阻止旧密钥配置恢复。新增 `KeyRingStateSnapshot(PDO, profile, KeyRing, SignaturePolicy)`，将实际密钥内容及身份／范围、固定来源、期限、容差、正文预算等签名策略一并纳入完整复合摘要。KeyRing::stateDigest 使用明确域的 HMAC 材料探针及规范化 ID／subject／scopes，只输出摘要，不保存秘密原文；顺序变化不改变权限集合的摘要。策略选项按名称规范化。

来源指纹只绑定显式 profile，实际内容在 digest 中：同 profile 的旧配置仍可重建同一来源身份，但其内容摘要不同，必须由独立见证拒绝，不能因为“新建了一个配置对象”就把旧材料当作可信状态。来源没有额外数据库表或文件，也没有配置读取回调；storageDomains 为空只表示这个不可变内存值不拥有物理存储，并不证明部署备份独立。物理隔离、私有密钥交付和停止旧进程仍需部署契约。

CompositeStateSnapshot 只增加对这个具体 final 类型的支持。配置部分参与每次完整摘要及 SQL／文件采集复核，不作为可选择的行／文件返回；任意 StateSnapshot 实现仍不能借此获得保护配置资格。KeyRing 来源必须使用同一 PDO，且原生验签器使用完全同一 KeyRing 对象和等价 SignaturePolicy。

创建新保护域时，在首次明确预置见证之前加入来源：

```php
$signaturePolicy = new SoSecurity\Api\SignaturePolicy($signatureOptions);
$keySource = new SoSecurity\Account\KeyRingStateSnapshot($pdo, 'api-signing-config', $ring, $signaturePolicy);
$source = new SoSecurity\Account\CompositeStateSnapshot($pdo, [
    'complete-sql' => $sqlSource,
    'authentication-files' => $fileSource,
    'api-keys' => $keySource,
]);
// 按既有首次预置契约构造见证、边界和状态账号策略。
$verifier = $sdk->hmacVerifier($stateAccountPolicy, $keySource, 'api-keys', $hostRequestGuard);
```

既有部署增加来源会改变完整来源指纹，不能删除／重新 initialize 原见证。更新 KeyRing 或签名策略内容也不能自动采纳为 current；正常轮换、来源迁移及恢复后的新材料启用仍需完整的独立审批转换，尚未由本批提供。原材料、名称和 nonce 都不能靠清空或改 namespace 绕过。

## 原生入口与业务权限

`Security::hmacVerifier($statePolicy,$keySource,$sourceName,$requestGuard)` 要求准确的认证 FileStore／Clock／SessionRegistry／站点与状态账号策略、同一具体密钥配置来源，以及显式请求保护。原生配置缓存禁止更换字段映射、来源对象／名称或授权回调。没有显式状态策略的保护工厂继续拒绝；普通 hmacVerifier() 与任意可信 KeyProvider 的旧接口保留。原生在线／KMS 提供器尚未适配，不静默退回无见证路径。

原生对象拒绝旧 verify，使用 `verifyFor(scope,method,url,body,headers,requiredScope)`，或用 `withVerification(scope,PDO,tables,prepare,method,url,body,headers,work,requiredScope)`。verifyFor 返回当次服务身份，不是未来写入的权限缓存。原始规范 URL、正文摘要、Content-Type、签名、方法、范围与时间仍按原协议校验，外部签名格式保持。

withVerification 的 `prepare(PDO, Identity): Intent` 在锁内加载当前真实对象／版本和字段；须将实际路由／正文映射为当前 Intent，不接受客户端声称的 owner／version。`requestGuard(entry, Identity, ?Intent, method, url): bool` 只读并严格返回 true：验证实际路由、预算、当前资源权限及混合身份规则。服务身份来自已验签且受完整来源保护的 SigningKey，不伪造账号会话；声明 SessionRegistry 是为了准确服务图，不代表调用者已登录。回调是受信任宿主代码，不是任意 PHP 沙箱。

nonce 的真实原字节、重放、时间和物理文件容量在 pending 前检查。无效证明、权限拒绝、重放及满额不持久 pending。旧手工保护验签器在访问外部 KeyProvider 前先要求准确活动边界，避免先查询第二份身份再触发存储保护；普通未保护调用保持原样。

准确 hmac.verify／hmac.execute 回执绑定服务身份摘要、真实 Intent、方法、URL／正文／完整签名输入摘要、所需范围、声明表名、观察摘要及实际原生策略。根不保存正文、原始 URL／Signature 或密钥原文，回执本身也不是权限证明。

## 消费、提交与故障

nonce 消费与业务 SQL 在同一独立见证中完成。work(PDO, Identity, Intent) 仅调用一次，由 SDK 独占 SQL 事务；禁止输出、外部效果、DDL 或控制事务。提交前后复查时间，最后持久 current 后才返回结果。SQL 回滚、到期或提交后见证失败保留 pending，已消费 nonce 不退款、不自动重放。

NonceStore 的事务回调现在只处理捕获的值及原记录，不在回调内读取 Clock；重复调用必须得到同样效果。真实时钟复查移到事务之后，已写入后到期或倒退返回拒绝，保留消费结果。不能把 nonce 当成旧授权账本清空；过期维护和旧工作进程仍需同一边界与既定恢复对账。

## 冻结验收

[执行清单](state-native-hmac-evidence-2026-10-22/execution.json)固定八条命令。PHP7.2／8.5 × SQLite／私有 MySQL，各执行五个 HMAC 专项、旧重置工厂、范围证明退役及三个真实 SIGKILL 点；SQLite 另执行原普通 API 200 项和密钥来源／纯 nonce 回调专项。最后核对两端公开契约、PHP7.2 目标静态分析和 PHP7.2 语法。保护图 16 MiB，普通专项 8 MiB；PHP7.2 沿用私有 sodium／posix／CLOCK_MONOTONIC 环境，不代表系统原版 PHP7.2 整轮通过。

新进程配置回滚探针重建同 profile、同 PDO／文件、旧真实密钥。先以普通验证器证实旧请求密码学有效，再要求原生见证在请求保护与 nonce 写入前拒绝旧配置；原根不改变，当前配置仍可正常使用。另验证策略变化会改变来源摘要、nonce 真实容量、恢复旧 nonce 字节、错误对象／连接／完整表声明，以及回调外时钟检查和事务未知结果。

三个真实停点为 pending 后、SQL 修改后提交前、SQL 提交后 current 前。控制器 SIGKILL 后新进程重建完整密钥来源，核对准确回执和 SQL 提交／回滚；中间停点加入等待竞争者，pending 时 guard／prepare／work 均不得重放。

首次公开类型分类遗漏和复合采集具体类型检查遗漏均保留于[预检记录](state-native-hmac-evidence-2026-10-22/preflight-notes.md)。最终结果以冻结清单和交付核对为准。

**已执行并通过：固定八条命令全部退出 0，冻结输入前后哈希一致。** 四种组合的 HMAC 生命周期／拒绝／未知结果／工厂分别为 32／91／51／21 项；配置回滚父测试与新读者各 9 项，旧重置工厂 24 项、证明退役兼容 81 项。SQLite 两端另通过原普通 API 200 项和配置来源／纯 nonce 回调 23 项。十二次真实 SIGKILL、四次等待竞争者均通过；pending 阶段新进程 guard／prepare／work 均不重放。两端 264 类公开契约、PHP7.2 目标静态分析和 855 个 PHP 文件语法通过；保留可选 turbo GLIBC 加载警告。

[交付核对](state-native-hmac-evidence-2026-10-22/delivery-check.json)确认四个测试根、十二个中断子目录和两次私有 MySQL 全部清理，无在途任务。[库增量](state-native-hmac-evidence-2026-10-22/library-delta.json)为九个文件（含一个新增具体来源），原普通 API、旧重置工厂、证明退役及受管 HTTP 示例字节保持。[API 增量](state-native-hmac-evidence-2026-10-22/api-additions.json)确认新增一个公开类型，既有类型新增十四个方法；HmacVerifier 构造函数追加八个可选参数，Security::hmacVerifier 追加四个可选参数。去掉这些增量后与旧契约摘要完全一致。本批到此停止扩测。

## 停止边界

本批完成后不追加功能或扩测。在线 KeyProvider／KMS、Webhook／Inbox、旧 ApiKeys 保护工厂、剩余维护与写入者、密钥／来源迁移及最终恢复启用、新入口 HTTP／浏览器和当前九版本最终门禁仍开放。旧业务宿主未解释 503 不被本组 CLI 通过抵销，也没有重复诊断。完整 F01／R1—R6 未完成；无提交、推送或发布。
