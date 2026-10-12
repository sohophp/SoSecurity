# 旧 PHP 网站分步迁移

0.1 不接管路由、数据库、认证/授权、Session 生命周期或文件管理器。先在测试站点安装和验证，再选择一个低风险入口试点。原有检查继续保留到替代路径真正验证通过；不要同时删除所有旧代码。

## 1. 接入前盘点

列出登录、注册、找回密码、后台表单、AJAX和上传入口，标记认证凭证是Cookie还是Bearer。查清Session驱动是否加锁，代理是否正确重写X-Forwarded-For，已有框架是否自带CSRF。备份配置和原有实现，不备份明文密码到日志。

Composer公开包尚未发布，当前使用README中的路径仓库安装。指定测试站点唯一namespace，私有目录必须在Web根之外、0700且应用拥有；跨主机部署选择Redis，禁止SessionStore做登录限流。不要直接改宿主数据库结构；数据库适配尚未实现。

## 2. 先加请求预算

保留原密码验证函数，在它前面调用 `RateLimiter::consume`。账号规范化使用原有登录规则，避免不同大小写/别名绕过预算。用组合IP+账号桶保护密码计算，用阈值较宽的IP桶控制总体请求；不要默认锁死账号或共享IP。

第一阶段可以单独记录预算结果来评估阈值，但原有防护必须保持；真正启用时 denied 立即结束业务，临时拒绝返回429/Retry-After，存储故障返回503。验证码生成/刷新也限流。成功登录不要默认清空宽松IP总量桶。

## 3. 替换一个验证码入口

替换生成端及服务端验证端，保留相同业务路由。绑定Session中的随机值和具体scope，表单提交 challenge.id 与用户答案。刷新先revoke；不要把答案、摘要、Session ID交给前端。AJAX和传统表单使用相同后端检查，任何依赖异常都拒绝业务。

多标签页默认保留4个挑战；并存容量可配置。先验证正常/错误/过期/重放/并发提交，再移除旧答案存储键。数学和基础图片不证明能抵抗自动识别；高风险入口可启用Turnstile并保持现有业务限流。

## 4. 加CSRF

已有Symfony等框架提供正确CSRF时优先保留；没有时使用CsrfTokens。按scope给每个表单发令牌，放隐藏字段或AJAX请求头，验证后才执行状态变更。选择足够的并存容量和TTL，验证多标签页/长时间打开页面后刷新流程。

不要使用GET写数据；不要给所有路径做通配符豁免。兼容老前端可先给页面加隐藏字段，再在后端强制检查；旧防护不能在改前端时一并撤掉。无Cookie自动认证的Bearer API需根据实际机制分析，不机械套表单规则。

## 5. 密码渐进升级

复用原有用户查询（参数化SQL）。针对准确旧格式注入legacyVerifier，仅验证成功时生成现代哈希，再按原哈希CAS更新：

```php
$result = $hasher->verifyAndUpgrade($submittedPassword, $row['password_hash'], $legacyVerifier);
if (!$result->valid) { /* 返回统一登录失败 */ return; }
if ($result->replacementHash !== null) {
    $statement = $pdo->prepare('UPDATE users SET password_hash = :new WHERE id = :id AND password_hash = :old');
    $statement->execute(['new' => $result->replacementHash, 'id' => $row['id'], 'old' => $row['password_hash']]);
    // 若未更新到1行，重新读取确认账号状态；可能发生密码重置，不能按旧凭证继续登录。
    if ($statement->rowCount() !== 1) { /* 请求重新认证 */ return; }
}
```

表名/字段仅示例，不能未经审核在宿主执行。根据现有哈希长度审核列容量（通常至少255字符）。未知旧格式、不可验证哈希、超bcrypt字节上限的旧密码不能安全自动迁移；采用支持的Argon2id或受控重置。禁止把哈希改成“先MD5再bcrypt”规避长度限制。

## 6. 会话与Cookie

把configure放在宿主session_start之前；登录/权限提升确认成功之后且写认证状态之前rotate；敏感页面调用touch，false立即取消宿主认证。PHP7.2在start/rotate后显式发送cookieHeader，同名同路径的最后一个Cookie头携带SameSite属性。生产只用HTTPS和Secure。

不自动处理宿主退出登录字段，先确认现有path/domain、并行请求行为、自定义Session驱动的strict_mode支持。更新Session ID时旧并发请求可能失败，验证表单/AJAX重试体验。

## 7. 输出和响应头

保留Twig自动转义；普通PHP仅替换对应HTML/引用属性输出，不对整个输入先“清洗”再宣称没有XSS。JS只以JSON数据方式注入，不生成用户可控代码。CSP先Report-Only，收集违规后检查第三方资源；HSTS待HTTPS和恢复流程验证后显式启用。

现有CKFinder/上传系统先保留。本次没有上传或SSRF实现，不应以本库已安装为理由取消已有校验。

## 观察与回滚

观察只记录固定事件代码、响应状态、Retry-After和假名化主体，不能记录密码、验证码答案、Cookie、令牌或完整请求。明确保护开关和异常响应；测试误封率与共享IP正常用户。

回滚时先恢复原有可靠防护，再停用新调用；若旧实现已知不安全，回滚不能意味着匿名放行，可暂时关闭该敏感入口。CSRF/验证码切换后的旧表单可能需刷新，通知用户并保留正常错误响应。不要通过清空所有Redis/Session/文件数据来恢复访问，这会删除封禁及单次消费状态。

## 本地完整示例

[legacy-login.php](../examples/legacy-login.php) 是可运行的原生PHP示例，需要：

- `SOSECURITY_EXAMPLE_STORE`：预创建的0700私有目录；
- `SOSECURITY_EXAMPLE_USER`：测试账号；
- `SOSECURITY_EXAMPLE_PASSWORD_HASH`：原生password_hash生成的哈希，不是明文密码；
- `SOSECURITY_EXAMPLE_HTTPS`：默认Secure，仅隔离本地HTTP设为0。

不要将示例直接作为生产认证平台。`python3 tests/test_http.py php72` 会创建独立环境并验证真实HTTP、Cookie和登录流程，不连接旧网站数据库。真实站点的授权和业务数据验收仍需在宿主进行。
