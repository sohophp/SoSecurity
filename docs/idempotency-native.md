# 原生幂等订单接入

[原生页面与POST接口](../examples/idempotency.php) 使用显式Bearer凭据，不启动Session，不读取Cookie作为身份，也不提供HTTP管理入口。它组合已有ApiKeys、当前SQL账号、Authorizer、入口／主体预算和通用SQL幂等；[业务适配](../examples/idempotency-business.php) 将订单与执行账本、幂等结果放在同一PDO事务。当前为本地未发布示例，出站消息箱和完整R4.3继续。

## 部署配置

运行时需64位PHP及PDO SQLite；核心组件本身同时有MySQL实现，示例的业务表结构为SQLite。部署前准备现有的私有0700状态目录、0600数据库和独立封存密钥文件，均放在实际Web根之外；所有路径使用规范绝对路径，不通过符号链接绕过检查。HTTP请求不创建目录、密钥、账号、表结构或命名空间。

| 环境变量前缀 `SOSECURITY_IDEMPOTENCY_EXAMPLE_` | 内容 |
| --- | --- |
| `ORIGIN` | 固定HTTPS来源，含实际端口，不带路径或末尾斜线 |
| `DATABASE` | 已存在的私有SQLite文件 |
| `STORAGE` | 私有FileStore目录，用于Bearer凭据与请求预算 |
| `KEYS` | 私有JSON封存密钥文件，结构为current及keys，密钥为至少32个随机字节的标准Base64；与API凭据独立 |
| `EPOCH` | 数据库外保存的固定64个小写十六进制字符，恢复时与业务账本对账 |
| `DOCUMENT_ROOT` | CLI必须提供实际Web根；不能为了通过私有路径检查填入其他目录 |
| `PATH` | 可选，默认 `/idempotency.php`，严格匹配实际原始路径，不接受查询参数 |
| `TTL` | 可选，有效期秒数1—31536000，默认86400 |
| `CAPACITY` | 可选，每主体／操作保留键数1—100000，默认1000；清空正文不释放键名／容量 |
| `HTTPS` | 默认开启；仅隔离本地演示可显式设为0，并同时使用固定HTTP来源 |

部署管理程序显式执行[通用幂等DDL](../resources/sql/idempotency-sqlite.sql)和[宿主示例DDL](../resources/sql/idempotency-example-sqlite.sql)。账号由宿主建立，tenant固定为 `idempotency-example`，subject与version为1—64个ASCII字母／数字／下划线／连字符；enabled与roles来自当前权威数据。创建订单需要 `orders_writer` 角色及 `orders:create` API范围。没有预设密码或默认凭据。

## 私有CLI管理

[管理工具](../examples/idempotency-admin.php) 只允许CLI，以能够访问私有配置／密钥的本地操作系统身份作为管理边界。发布时将该工具放到实际公开目录之外更便于权限管理；直接HTTP访问只返回404，不加载私有配置。

```sh
php examples/idempotency-admin.php initialize alice
php examples/idempotency-admin.php issue alice 86400
php examples/idempotency-admin.php maintain alice
php examples/idempotency-admin.php maintain alice PREVIOUS_NEXT_CURSOR
php examples/idempotency-admin.php revoke CREDENTIAL_ID
```

initialize只初始化指定主体的幂等命名空间，不创建业务账号或表；重复执行返回false，不重置历史。issue要求当前启用的writer账号，返回id、token及到期时间，秘密仅此次返回，不能放到日志／网址。revoke接收凭据ID，不接收秘密。maintain每批20条，保留墓碑并按当前密钥轮换封存，满批时继续next_cursor，直至complete为true；私有CLI可以维护已删除／停用账号的旧命名空间。

凭据的服务端主体绑定 `subject@version`，HTTP入口核对当前账号版本；宿主变更凭据／恢复账号等敏感生命周期时递增version，使旧版本API凭据拒绝。角色与enabled也逐阶段重新读取，角色变更须遵守宿主版本与撤销规则。凭据轮换、服务账号委派和会话管理的完整产品接口仍见[账号API凭据](api-credentials.md)，此工具不替代完整管理平台。

## 原始HTTP边界

POST只接受精确的 `application/json`、有界Content-Length、最多8192字节实际正文和16—128个受限ASCII字符的Idempotency-Key。正文只含reference与整数amount，参考编号最多64字符，金额为1—1000000整数分。拒绝额外字段、JSON重复成员（含编码别名）、浮点／布尔金额、压缩／不支持的分帧、非固定Host／实际HTTPS和额外查询。

可信接入层必须在PHP SAPI丢失信息前拒绝重复认证、幂等及分帧头，包括大小写变体，再设置服务端属性 `SOSECURITY_IDEMPOTENCY_HEADERS_VALIDATED=1`。它不是客户端HTTP头；仅设置该值而不实际检查原始请求不满足契约。不得信任用户自报的同名头、X-Forwarded-Proto或检查结果。未取得该属性时POST停止；单独启动PHP内置服务器不会自动满足接入条件。生产反向代理、真实客户端地址及各跳协议仍须按实际部署验收；默认预算使用可信的实际连接地址。

GET仅提供不含秘密的操作页面，凭据输入不会写入URL、Cookie、localStorage或sessionStorage。浏览器显式发送Authorization，fetch省略Cookie，输出只用textContent。响应固定no-store/private、nosniff、no-referrer及CSP；页面使用随机nonce，不能把示例的本地HTTP例外扩大到生产。

## 业务与恢复

每次执行／重放都复核当前Bearer、账号版本／启用／角色和对象权限；重放按HMAC已认证的执行ID与存储指纹关联当前宿主执行账本，核心随后比较实际请求指纹。冲突请求先检查原执行是否仍可访问，再返回409，不因传入了不同参数而泄露旧结果。

同键同内容返回历史创建结果，HTTP头Idempotency-Replayed说明是否使用缓存，X-Execution-Id标识本次幂等执行。订单的order_id属于独立业务记录；换键但使用同一主体／参考编号／金额会关联原订单，保持order_id和创建结果，不能重复创建。相同参考编号但不同金额返回可重放的409业务拒绝。HTTP结果不确定时保留原键和业务参考编号重试，不能自动改键重做。

订单按tenant／subject／reference_id唯一，执行账本关联请求指纹、金额与订单ID，即使获授权重建已完全丢失的安全历史，业务库仍拒绝重复创建。保留孤儿历史、封存损坏或不一致状态时不自动初始化／清空；完整有效旧备份或整个业务库丢失仍需外部epoch和业务恢复对账。历史创建结果不代表订单此后的实时状态，也不是跨网络副作用恰好一次保证。

当前九版PHP7.2—8.5真实HTTP／私有CA TLS各433项、SQLite409／MySQL356、161类API及安装包消费者专项全部通过。PHP7.2／8.5真实TLS移动Chromium、丢失确认后的进程重启和仅一次业务也已通过；源码451文件在整轮未变。无sodium的php72另通过HTTP433项。出站消息箱及完整R4.3继续。这里的TLS通过受控本地终止代理实际建立并校验证书，不是生产代理或真实旧站验收；原始失败与完整记录见[验证记录](verification.md)。

本地浏览器验证使用Playwright；可通过 `SOSECURITY_PLAYWRIGHT_MODULE` 指向已安装模块，未设置时按Node标准模块路径解析。浏览器对隔离私有CA的忽略信任仅用于测试，HTTP测试运行框架仍实际校验证书。
