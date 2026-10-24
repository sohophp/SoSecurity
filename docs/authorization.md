# 默认拒绝的对象、字段与批量授权

`Authorization\Authorizer` 在每个受保护业务入口检查当前身份与策略，不替代登录、CSRF、数据校验、请求预算或业务事务。`Account` 必须来自本次请求已经验证的宿主身份；仅凭 `IdentityProvider::find()`、请求中的主体／角色／租户，不能证明用户已登录。匿名默认拒绝，公开页面由宿主显式提供公开数据传输对象（DTO）。

## 配置与策略

```php
$policy = new SoSecurity\Authorization\RolePolicy([
    'document.update' => ['type' => 'document', 'roles' => ['editor'],
        'fields' => ['title', 'body'], 'owner_attribute' => 'owner', 'match' => ['state' => 'draft']],
]);
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'authorization' => ['identity_provider' => 'users', 'policy' => 'documents'],
], ['users' => $identityProvider, 'documents' => $policy]);
$authorizer = $security->authorization();
```

也可直接构造 `new Authorizer($identityProvider,$policy,$auditLogger)`。工厂不需要共享状态，不自动建立Session、连接数据库或注册路由。若已配置 `authentication`，授权的身份服务名默认沿用它；不配置策略时组件始终拒绝，服务名错误抛配置错误。

`RolePolicy` 按精确action和资源type匹配，要求至少一个明确角色；没有通配符、角色层级或“管理员自动全权”。`owner_attribute` 指向资源元数据中的字符串归属，缺失／非字符串／非本人均拒绝。`match` 是严格类型的标量属性比较，缺失不等于null。角色由当前权威身份源给出，组继承／细粒度关系由宿主展开或实现提供器。

`PolicyProvider::decide(Account,action,Resource,requestedFields)` 只读地返回 `Decision|null`；null表示不支持，不能当作允许。`CallbackPolicy` 可接基于属性的访问控制（ABAC）、关系查询或既有权限SDK；必须读取当前可信数据、限制I/O并在故障时抛异常，不以缓存旧权限或布尔true替代Decision。

`PolicySet` 要求每个提供器都明确允许，拒绝／不支持任一项即拒绝；字段白名单取交集，空集合不产生许可。组合不是任一同意即可。可选 `authorization.audit` 注入现有 `AuditLogger`，仅发固定允许／拒绝事件、作用域、主体假名及allowed值，不记录资源内容、字段值或异常原文；已配置审计失败则本次授权抛异常，业务不能继续。审计允许事件只记录审计前的策略决定，不等于最终放行或业务已提交。允许路径在审计返回后对原始资源重新评估当前身份与策略；期间账号停用、角色／版本变化、策略撤权、请求字段失权或依赖故障均拒绝返回允许。最终字段权限取审计前后交集，不因中途扩权增加返回权限；资源列表先断开外部引用，回调不能更换待授权对象。不重复投递审计事件，初始拒绝也不重新求值。策略和身份提供器必须只读、可重复，并返回当前权限；带审计允许路径的策略评估最多两轮，每轮仍受100个资源和32个组合策略的既有上限约束。

## 资源、作用域和身份变化

```php
$resource = new SoSecurity\Authorization\Resource($trustedTenant, 'document', $row['id'], (string)$row['version'],
    ['owner' => $row['owner'], 'state' => $row['state']]);
$authorizer->assertAllowed($trustedTenant, $verifiedSession->account(), 'document.update', $resource, array_keys($validatedPatch));
```

租户来自服务器当前上下文，资源来自包含租户条件的数据库查询，不采用提交的owner／版本／角色构造授权元数据。请求里的编号只作为参数化查询定位值；不可预测编号不能替代权限。作用域必须同时匹配请求、账号、资源和身份源；跨租户管理需要明确的服务器成员关系映射，不借一个全局角色越过边界。

授权前后重新查询身份，比较scope／subject／enabled及完整指纹。账号版本、角色或策略变化后拒绝旧快照；身份源返回其他主体属于契约故障。提供器／身份／审计异常被转换为无原始异常链的稳定服务错误，不降级允许。

这是授权检查，不重新验证登录凭据或认证强度；宿主每次先验证Session／API身份，高风险操作另检查近期认证。组件不永久缓存Decision；Account、Resource和Decision不得序列化成下一次请求的权限证明。UI可据决定隐藏控件，后端仍须再次检查。

API凭据的scope／调用者限制不能在映射为Account时丢掉。宿主按当前请求重新验证凭据，将其主体与Account关联，再用额外 `CallbackPolicy` 检查该动作所需scope；与对象策略放入 `PolicySet` 求交集。额外策略允许时只声明本次请求字段，不能扩大对象策略白名单。不要把某个请求的凭据快照放入跨请求复用的策略单例，也不要从Cookie与API身份中任选权限更大的一个。

## 字段与输出

`Decision::allow(['title','body'])` 只声明这些顶层字段；空fields表示只有对象权限，绝不表示所有字段。`assertAllowed(...,$fields)` 要求全部字段在白名单中，遇到越权字段整次拒绝，不默默丢掉部分输入。读取用 `project(...,$serverRow,$fields)`，只返回指定允许字段；进入任何身份、策略或审计回调前先复制并断开字段列表中的PHP引用，回调不能改变本次实际投影字段。缺失列是宿主映射错误，不自动返回整行。

字段名大小写精确、最多64项，不支持星号／点路径／JSON Pointer或隐式父子继承。一个顶层对象字段若被允许，其内部结构仍需宿主明确DTO和嵌套校验；不要把含更高敏感级别内容的整棵对象挂在一个低权限字段下。`Validation\Validator` 的字段白名单和嵌套结构检查仍独立执行。写入只映射固定允许列，不把任意数组交给ORM批量赋值。

## 批量与资源预算

`decideBatch`／`assertBatch` 接收1—100个唯一Resource和一组共同请求字段。每个资源、每个字段均须允许；没有空批次的真值、跳过失败项或只检查首项。完成整个授权后才开始业务副作用。不同对象字段规则取交集；需要异构操作时宿主先分别全量检查，再统一事务提交。

资源type／action最多64字符；scope／id／version为有界UTF-8标签；元数据最多64个顶层标量属性、单字符串1024字节、编码总量8KiB，不接受对象／数组钩子。角色规则最多128项，每项最多32角色；组合最多32提供器。元数据、规则和字段数组复制为只读快照，原输入引用变化不改变已构造对象。回调计算／数据库锁及整个请求时限仍由宿主约束，不能以数量上限冒充任意回调的时间保证。

## SQL和原生接入示例

[authorization.php](../examples/authorization.php) 是显式PDO适配，宿主提供 `documents(tenant,id,owner,version,title,body,confidential_note)`，唯一键为 `(tenant,id)`；导入不建表或提交事务。示例规则为租户内角色读基本字段、编辑者改本人title／body、管理角色读额外字段，没有隐式写所有文档权限。

读取先查询授权元数据，通过后只选择允许列，并带当前资源版本条件；输出前再次核对权限。更新先加载全部元数据、检查整批对象和字段，再校验全部载荷，然后只写固定列、比较tenant／id／version并增加版本。没有更新未提交的字段，也不预先加载机密正文。所有归属／敏感属性变化都必须增加资源版本。

调用更新前宿主开始事务，任何拒绝／冲突／SQL故障都回滚整批；辅助函数不擅自提交或回滚调用者事务。先授权再报告版本冲突，避免向未授权对象泄露版本状态。实际验证使用SQLite触发器在首项写入后改变次项目版本，确认条件更新失败并由HTTP宿主完整回滚。

身份源、策略数据和业务数据库没有跨资源事务承诺；身份变化发生在检查返回后仍可能与写入竞态。严格一致性业务需在自己的数据库事务内锁定权限／成员关系和资源，或用权威权限版本条件更新。不要把两次查询或资源版本CAS当作全局原子撤权。生产数据库隔离级别、锁等待及冲突重试需另外验收；本轮SQL适配没有宣称所有PDO驱动已验证。

原生 [authentication.php](../examples/authentication.php) 可选配置 `SOSECURITY_AUTH_EXAMPLE_DATABASE`：Web根外、既有且权限私有的SQLite文件；需PDO SQLite，由宿主预建上述表并设置账号roles。与认证配置／存储一样使用显式测试身份，不创建管理员或默认账号。新增读取／管理字段／整批更新均为POST，先检查CSRF、请求预算和真实共享会话；目标租户固定来自服务端，客户端传tenant字段不改变查询。

原生示例未知／未授权对象使用相同403和稳定原因；已授权的版本冲突409、载荷400、权威服务故障503。页面和JSON均no-store；事务失败不回显SQL、路径或私有字段。未配置数据库时不显示文档操作，也不自动打开数据库。

## 验证与参考

专项 `tests/authorization.php`、真实SQLite `tests/authorization-sql.php`、原生HTTP／Chromium `tests/authorization_http.py [--browser]`；当轮记录见 [verification.md](verification.md)。接口检查不代表生产业务权限已正确配置，独立审查仍未完成。

参考：[OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) 的默认拒绝、逐请求及对象权限；[Symfony Voters](https://symfony.com/doc/current/security/voters.html)、[Laravel Policies](https://laravel.com/framework/docs/12.x/authorization) 的策略扩展模式。当前组件采用上述明确组合契约，不宣称复制框架所有行为或通过ASVS认证。
