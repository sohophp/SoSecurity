# 高风险操作授权

`Operation\Grants`提供准备、重新认证后明确确认、原子单次消费三个步骤。它绑定服务器确定的动作、资源／版本／属性、参数、字段、当前账号和当前会话，不把普通登录或一个旧VerifiedSession对象当作本次操作授权。R3.4本地九版本完整检查、共享后端并发、新消费者及真实密码／TOTP浏览器验收已完成；仍为未发布候选，宿主业务及生产须分别验证，见[需求跟踪](security-refinement.md)和[验证记录](verification.md)。

## 调用顺序

1. 宿主验证请求、身份、对象／租户和输入schema，从权威存储读取Resource，再创建 `Intent(action, resource, parameters, fields)`。
2. `begin(scope, subject, sessionToken, intent)`返回Confirmation。向用户展示本次动作、目标、版本及重要参数；确认界面不能只显示“继续”。保存nonce及服务器意图，不能让客户端覆盖待确认数据。
3. 在同一注册会话中完成一次新的重新认证，更新宿主保存的sessionToken。AuthenticationFlow会保留会话ID并轮换秘密；重新登录创建另一个ID不能确认原操作。普通登录凭据尚新也必须重新认证，确认检查秘密确实在准备后变化，并检查认证时间。
4. 用户明确确认后调用 `confirm(..., intent, confirmationToken)`；通过当前认证方式／强度、账号和权限复核才返回Grant。准备nonce不能直接消费，重复确认不会返回新授权。
5. 执行业务前重新加载资源和参数，调用 `consume(..., intent, grantToken)`；得到Permit才可立即开始宿主事务。消费是共享账本内的单次移除，失败或依赖异常不能继续业务，不能退款或自动补发。

每个步骤均要求请求保护回调返回严格true，并查询SessionRegistry的当前凭据；授权策略在开始和返回前复核。匿名、过期待MFA、撤销／禁用／角色或凭据版本变化、不同作用域／主体／会话均不能借用授权。自建Account／VerifiedSession／Permit对象不是登录证明，不从客户端反序列化这些对象。

默认Policy为120秒固定工作流期限、每账号最多8项、认证最大年龄300秒、强度2、方式仅totp／webauthn。密码和恢复码不自动满足默认策略；确有需要须由服务器显式配置，记住登录的恢复会话不满足近期认证。WebAuthn字符串只是已验证身份源的方式标识，本阶段不声称已经实现WebAuthn协议。

## 参数与篡改

参数必须先通过宿主业务schema和字段权限检查；Intent只规范化和绑定，不能替代这两类验证。参数根为具名映射，允许UTF-8字符串、布尔值、null、-2147483647至2147483647的整数、列表和具名映射。浮点数／对象／资源拒绝；金额或大型编号用经业务验证的字符串。

每个数组最多64项，总节点256、深度8；单字符串4096字节，规范化参数JSON最多16KiB。映射按键排序，列表保留顺序，字段列表按集合排序，标量类型不混用；外部引用不能修改已绑定值。PHP空数组统一按空列表处理，不支持需要区分空JSON对象和空列表的业务模型，宿主应先转为明确schema。资源指纹另外包含作用域、类型、编号、版本和有界属性。

真实nonce／grant在其匹配会话中携带不同动作、参数或版本时，相关记录失效，不能再用原数据重试；重新准备并确认。未通过对象授权的请求先拒绝，不读取或消耗他人账本。不同会话或伪造秘密不能撤销合法授权。再次重新认证后会话秘密改变，原已确认grant也不可再消费。

## 状态与副作用边界

v1账本只保存意图／账号／会话／秘密摘要、认证元数据、阶段和期限，不保存明文业务参数或token。pending只能转granted，granted只能消费／撤销／过期；不因记录缺失而承认旧token。策略指纹改变、结构损坏、时钟回退及存储故障均拒绝。默认不启用此功能，工厂需要显式authentication、authorization和共享storage。

TTL为1—300秒、容量1—16、认证年龄1—900秒、强度1—2；显式方式列表不含remembered，不能配置低于所需强度的方式。确认不会延长原准备期限，并进一步受会话期限和认证年龄限制。满额拒绝新准备，不挤掉其他有效操作。

请求保护、身份／权限I/O、随机数和时钟读取均在可重试事务回调之外。返回前重新核对当前会话和权限，时钟回退、晚返回、依赖变化时不返回授权，并精确清理新记录；清理失败也不能继续。记录全部消失后旧token没有可恢复的授权。后端持久性、驱逐、时钟同步及旧备份恢复仍由宿主管理。

`revoke`只撤销当前会话拥有的指定ID；`revokeAll`由当前已认证账号明确取消该主体全部待确认／已确认操作。两者都要请求保护；它们只减少授权，不执行业务。退出或会话撤销后，旧记录即使仍在TTL内也不能通过新的当前会话验证。

Permit是本次已消费的授权快照，包含ID、意图、账号、会话、认证方式和期限，不是可反复使用的凭据；禁止序列化／缓存。宿主必须在同一业务事务中记录唯一执行ID、比较资源和身份版本、验证期限，并在失败时回滚。共享消费与业务数据库不是一个事务，业务失败后不能继续使用原grant；需要用户重新确认。旧备份恢复、外部支付／邮件和任意第三方副作用不能靠共享缓存承诺恰好一次。

浏览器确认只是显式操作流程，不是受恶意浏览器保护的可信显示设备或抗钓鱼交易签名。HTTPS、CSRF／协议、请求预算、可信身份源、业务授权、通知和最终SQL／外部服务事务均须由宿主落实。

设计参考：[OWASP Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)。业务接入与恢复边界见下文，完整测试证据见verification.md；本地验收不表示生产已接入。

## 工厂与SQL示例

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/my-site/security'],
    'authentication' => ['identity_provider' => 'identities', 'request_guard' => 'request_guard'],
    'authorization' => ['policy' => 'authorization_policy'],
    'operations' => [],
], ['identities' => $provider, 'request_guard' => $guard, 'authorization_policy' => $policy]);
$operations = $security->operations();
```

可在operations中显式覆盖request_guard服务名；不提供时继承authentication配置。工厂拒绝Memory／Session共享后端，未知配置／错类型／缺失服务拒绝；无授权策略仍默认拒绝。诊断仅提示请求保护、明确确认和业务事务须由宿主验证，不创建授权。

[operation-work.php](../examples/operation-work.php)提供SQLite／MySQL文档标题更新：宿主开启事务，先消费grant，再插入业务库的唯一执行ID，按租户／归属／资源版本及权威账号版本条件更新；语句返回后重新核对数据库和工作节点期限。任何失败都由宿主回滚整笔事务，已消费grant不退款。它不支持检查之后长时间暂停再提交，也不是COMMIT时钩子。

示例需要宿主预建operation_accounts、operation_documents、operation_receipts；账号／角色／凭据变更必须推进这里检查的同一个权威版本，不能把延迟同步的镜像字段当作瞬时撤权。唯一执行ID与数据变更在同一数据库事务，缓存旧备份即使连同旧资源版本恢复，也不能重复已有receipt的操作。外部邮件／支付等副作用继续需要宿主幂等与恢复协议。

使用PasswordIdentityProvider时，Account::version()为原始账号版本与保存哈希共同生成的有效版本；不能直接拿它比较数据库原始version。PasswordRecord::account()保留原始账号，identity()返回有效身份。将当前权威PasswordRecord作为apply最后一个可选参数传入：先核对Permit的有效身份指纹，再以原始版本和password_hash联合约束SQL。其他身份源仍按同一权威版本检查。角色／因子要求等变化仍必须推进原始版本；未配置凭据列的既有SQL示例不启用密码记录参数。

## 原生浏览器接入

[operation-authorization.php](../examples/operation-authorization.php)是独立原生PHP／SQLite示例，使用真实PasswordIdentityProvider、AuthenticationFlow、SessionRegistry、可选TotpSecondFactor及上述SQL事务。导入入口会处理实际HTTP请求；业务辅助文件operation-work.php仅定义函数。入口不自动建库、建表、创建账号或绑定因子。

显式配置以下环境变量：SOSECURITY_OPERATION_EXAMPLE_DATABASE为Web根之外现有0600私有SQLite文件；SOSECURITY_OPERATION_EXAMPLE_STORAGE为独立0700共享状态目录；SOSECURITY_OPERATION_EXAMPLE_DUMMY_HASH为与默认bcrypt cost12匹配的假账号哈希。数据库除上述文档／receipt表外，账号表需tenant、subject、username、password_hash、version、enabled、roles及mfa_required列，按(tenant,subject)和(tenant,username)唯一；roles为角色JSON，enabled／mfa_required只能0或1。示例租户固定operation-example，document.update要求editor角色且owner等于当前subject，仅允许title字段。

SOSECURITY_OPERATION_EXAMPLE_MFA_KEY为外部秘密管理提供的32字节密钥之Base64；因子使用同一FileStore命名空间operation-example、Cipher用途operation-example:mfa、发行方Operation example和同一租户／subject，通过可信CLI或已保护的宿主管理入口预先绑定。不要通过Web暴露测试初始化脚本或私钥。默认操作策略接受TOTP／WebAuthn方式，示例只实现密码／TOTP／恢复码协议；没有MFA时不会自动降为密码。SOSECURITY_OPERATION_EXAMPLE_PASSWORD_PROFILE=1显式选择仅密码策略，只供允许此强度的宿主示范，并不代表强MFA验收。HTTPS默认启用；仅隔离本机HTTP验证时可显式SOSECURITY_OPERATION_EXAMPLE_HTTPS=0。

页面先校验CSRF和入口／动作预算，读取权威资源元数据，向用户展示动作、对象／版本及拟变更标题；提案、确认nonce、grant和注册会话秘密均保存在服务器Session，页面只携带公开工作流ID。重新认证会更新原注册会话秘密及原生Session ID。每个确认／执行／取消表单、操作中的重新认证／MFA都绑定其展示的review_id，旧标签页不能确认另一标签页新提案；执行时重新加载元数据并在宿主SQL事务内消费及写入。取消、重复执行、源不可用、版本／归属／账号变化均拒绝继续写入。输出HTML编码、no-store、no-referrer及限制CSP；未配置则503通用错误，不返回内部路径或异常。

公开页面不是生产管理平台；宿主仍需完整路由保护、账号／因子管理、通知、权限及备份恢复验收。常驻Apache尚未配置此示例的私有数据库或MFA密钥，不能把独立测试实例的通过描述为实际站点已接入。
