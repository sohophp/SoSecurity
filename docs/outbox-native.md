# Outbox原生生产、发送与接收

状态：R4.3原生接入候选。该示例把现有Outbox、SQL幂等、受限HTTP客户端、Webhook验签／接收／事务处理及独立业务唯一账本组合起来；核心接口仍见[Outbox](outbox.md)。当前没有公开部署或生产验收，超期墓碑的业务对账处置和完整R4.3仍继续。

超期墓碑现有显式[签名证据／取消栅栏／审计与 CLI](outbox-reconciliation.md)候选。已有示例库升级须安装该指南中的增量 DDL，并停止旧进程；完整阶段验收和生产接入仍分别保留。

## 组成与信任边界

业务备份可能含旧权限；需要恢复隔离时显式配置[独立当前权限源](outbox-authority.md)，发送、接收与管理角色／关联不再从业务库读取。该可选接入要求 ext-sqlite3，默认配置保持原查询来源；生产身份发行方和权限源恢复时效由宿主管理。

- [业务适配](../examples/outbox-business.php)是惰性的函数集合，导入不读取配置、打开数据库、生成密钥、建表、启动Session、发头或发送请求。
- [生产命令](../examples/outbox-producer.php)使用当前CLI服务身份和数据库角色，在SQL幂等组件拥有的同一PDO事务内提交订单、固定业务事件及Outbox意图。订单唯一参考和原始创建时间保持事件身份；同业务不同金额拒绝，同业务不同请求键不产生第二条消息。
- [发送命令](../examples/outbox-worker.php)每轮最多20条元数据，按真实顺序游标调用精确领取。领取提交并返回、当前权限／期限再检查之后才联网；固定HTTPS目的端、公开地址／DoH／实际IP绑定、证书验证、默认1秒且显式可配置的网络总预算、8KiB请求、768字节响应、8KiB响应头，不跟随POST重定向，不转发Cookie或应用Bearer。
- [接收入口](../examples/outbox-receiver.php)只接受固定实际Host／HTTPS／路径的POST和有界JSON，要求由真实入口在信息丢失前拒绝重复头及歧义消息边界。`SOSECURITY_OUTBOX_HEADERS_VALIDATED=1`是服务器能力标志，不能从HTTP请求头或客户端声明赋值。未建立这一能力时入口拒绝。
- [发送管理命令](../examples/outbox-admin.php)显式初始化、有限重试和分页维护；[接收管理命令](../examples/outbox-receiver-admin.php)显式初始化、核查检查点、恢复及旋转代际。HTTP访问CLI文件返回404，导入CLI文件不执行命令。管理基于受控OS账号对私有配置／密钥／数据库的访问及当前数据库角色，不能把任意CLI参数中的账号标签当作身份；本示例没有Cookie管理页面或隐式强认证豁免。

共享适配的 `receive(settings, Request, requestGuard)` 必须显式提供当前真实请求保护回调；结构化Request不证明原始网络头已检查。HTTP入口重复核对真实上下文，独立消费者测试中的模拟回调不构成生产入口验收。

## 显式部署

发送数据库安装Outbox、SQL幂等两套核心DDL，以及[发送业务结构](../resources/sql/outbox-example-sender-sqlite.sql)。接收数据库独立安装Webhook接收／处理两套核心DDL，以及[接收业务结构](../resources/sql/outbox-example-receiver-sqlite.sql)。本示例只使用SQLite；核心的SQLite／MySQL兼容证据分别保留，不将此示例描述为MySQL原生接入。

数据库文件、配置、密钥和共享预算目录必须预先存在，位于实际Web根之外；文件0600、私有父目录和预算目录0700，使用规范绝对路径，拒绝符号链接及缺失数据库。HTTP、普通CLI和诊断不安装结构或创建账号／默认密钥。

由宿主管理受控数据：发送账号的 `orders_writer`、`outbox_worker`、`outbox_admin` 角色可分别委派；接收服务使用 `receiver_worker`，管理使用 `receiver_admin`，并配置当前启用的发布方路由与业务拥有者。每次请求／领取／提交／返回复核数据库状态和配置绑定的服务身份版本；禁用或版本变化拒绝旧进程。角色记录及持久化事件字段按实际字节数限制读取，不能只信任SQLite字段声明。

对账另需发送端 `outbox_reconciler` 或接收端 `receiver_reconciler`，均与对应管理角色同时满足，普通工作权限不能升级为终态处置权限。签名密钥与部署绑定配置、私有请求／证据文件、命令顺序及历史公钥规则见[超期对账](outbox-reconciliation.md)。

配置文件通过 `SOSECURITY_OUTBOX_EXAMPLE_CONFIG` 指定。发送方例子中的路径和epoch由部署系统提供，不可直接使用占位值：

```json
{
  "role": "sender",
  "document_root": "/absolute/public",
  "database": "/absolute/private/sender.sqlite",
  "storage": "/absolute/private/sender-state",
  "actor": "orders-service",
  "version": "1",
  "epoch": "<64位十六进制外部部署代际>",
  "seals": "/absolute/private/outbox-seals.json",
  "idempotency_keys": "/absolute/private/idempotency-keys.json",
  "wire_keys": "/absolute/private/publisher-keys.json",
  "url": "https://receiver.example.com/outbox-receiver.php",
  "transport_budget_ms": 3000,
  "policy": {"maximum_payload_bytes": 8192}
}
```

接收方使用 `role=receiver`、自身数据库／预算目录／服务账号及独立seals，不需要idempotency_keys；另须提供预先安装检查点结构的独立 `checkpoint_database` 和预先创建的 `checkpoint_lock` 私有文件。url必须与真实HTTPS入口完全相同，document_root必须匹配实际服务器目录。默认示例正文限额8192字节，其他Outbox策略沿用核心默认值；更改已初始化队列策略需要明确对账／迁移，不能在普通请求中覆盖策略指纹。

发送方可用原生配置顶层transport_budget_ms显式设置100—10000毫秒的整数网络总预算，包含DoH和HTTP；省略保持既有1000毫秒，null／字符串／越界值拒绝，接收配置不使用此项。每次发送在当前状态／权限查询之后重新读取剩余租期，预算取配置值与“剩余有效期减1秒”的较小值，不足2秒拒绝联网。此项不属于Outbox队列策略指纹，运营调整不改变原事件或投递身份，也不会因某次超时自动加大预算。示例配置的3000毫秒用于容纳接收持久提交延迟；宿主须按实际处理时间选择，并给租期和确认写入预留余量。

epoch同时绑定接收业务根及独立检查点。接收前显式执行 `php examples/outbox-receiver-admin.php --initialize`；正常请求拒绝旧代际、旧备份及prepared状态。恢复只允许重放已封存的最后一个转换，代际旋转还要求业务备份之外保留的原根摘要；配置、迁移、停机顺序和限制见[接收恢复](outbox-recovery.md)。不能自动采用非空未封存旧库。

每份密钥文件形状为 `{"current":"key-id","keys":{"key-id":"<标准Base64编码的32字节独立随机密钥>"}}`。Outbox封存、幂等封存和投递签名必须使用独立材料，加载时检查当前配置中的所有版本；发送／接收共享的只有同一投递协议密钥。接收封存与发送封存彼此独立。投递密钥轮换支持最多8个版本，发送读取当前版本、接收每次重新读取当前快照；移除旧版后旧签名拒绝。未确认消息和接收历史的封存轮换继续遵守对应核心维护约束。

## 操作顺序

在拥有受控私有配置的OS服务账号下显式执行；账号名由配置绑定，不能用命令参数改变操作者：

```sh
php examples/outbox-admin.php --initialize=orders-service
php examples/outbox-producer.php --key=original-request-key-0001 --reference=order-001 --amount=500
php examples/outbox-worker.php --once
php examples/outbox-worker.php --once --after=20
php examples/outbox-admin.php --retry=o1.1234567890.<原业务事件摘要>
php examples/outbox-admin.php --maintain
php examples/outbox-admin.php --maintain --after=<上一页next_cursor>
```

先由迁移创建结构／账号，再初始化整个发送队列及指定写入账号的幂等根。`--once`返回claimed、sent、failed、next_cursor、complete；空领取不代表全队列为空，按实际游标完成一轮后从0重新扫描等待／退避消息。failed大于0时退出2，配置、权限或结果不确定退出1且只输出固定错误码。管理重试需要原事件编号，不接受新正文、目的端或新投递编号。

CLI生产按账号每分钟60次预算，发送按固定目的端每分钟60次；接收入口每来源每分钟240次，验签后发布方每分钟120次，均使用显式私有共享状态。预算消耗不自动退还，不在SQL回调中执行网络或预算副作用。多主机部署须换成对应共享适配并重新验收，不能把本地文件预算当作跨主机额度。

## 接收去重与确认丢失

Standard HMAC签名覆盖稳定投递编号、当前尝试时间和原始正文。签名时间随尝试更新，业务事件编号／创建时间、正文和投递编号保持不变。接收先持久验签来源，再在处理组件自己的事务中同时提交业务唯一账本与投影；唯一账本同时约束发布方／原事件、投递编号和业务订单。

只有持久业务成功、独立唯一账本匹配且当前身份／路由／密钥仍允许时，接收返回恰好三个字段：committed=true、delivery_id及body_digest。发送端严格检查HTTP200、单一application/json、字段形状、原投递编号和原始正文摘要，才确认Outbox。普通200、重定向、错误正文、未提交接收状态、证书错误、超时或断连均不能标记sent。

接收已提交但响应丢失，发送会保留原投递编号有限重试；工作进程终止则等待旧租期结束后重新领取。独立接收业务账本在接收／处理安全历史恢复或重建后仍阻止重复业务，但不能随安全历史一起删除。相同事件换投递编号或变更业务内容拒绝，不把新编号当成恢复方案。业务库回退与独立检查点不一致时拒绝确认，只有受控恢复成功才恢复接收；更早备份仍须完整权威恢复与业务对账。两库及所有外部配置同时回退无法单靠封存检测，不能据此承诺跨系统恰好一次。

4xx除429视为不可重试而进入dead；其他未确认结果使用核心有限退避。授权拒绝、存储或提交结果不确定时不自动重做业务。过期消息正文退休后仍保留阻塞墓碑，人工超期对账／处置闭环尚未实现；本示例没有“清空状态后重发”或伪装成功的管理命令。新的请求键重用已超过原事件入队期的业务参考会拒绝，不能自动重新生成创建时间。

原生发送器的last_error只保存固定分类：transport.timeout、unavailable、dns、redirect、response_limit、header_limit、peer、confirmation、rejected、remote、policy或unconfirmed，均使用transport.前缀。新增对账核心的resolved状态使用保留标签reconcile.received／reconcile.cancelled，由Status.resolution()读取结论。元数据不会持久保存HTTP响应正文、异常文本、URL凭据或领取秘密；未确认结果需要按原消息状态重试或对账，不能直接改为sent。原生签名证据及取消栅栏仍待完成，见[超期对账核心](outbox-reconciliation.md)。

## 验证

`php tests/outbox-native.php` 检查惰性导入、私有配置、真实SQL生产与独立接收账本；可用8MiB PHP限制检查超大NUL角色字段拒绝。`python3 tests/outbox_native.py php72 php85` 使用私有网络命名空间、测试CA、真实DoH／curl IP绑定、两个独立PHP接收进程、24个实际TLS请求、响应丢失和工作进程SIGKILL；不连接外部提供器，不修改宿主路由或CA信任。

上一轮445文件固定快照完成九版PHP7.2—8.5实际TLS每版274项、8MiB限制下适配57项、关联SQL／配置／工厂与既有核心回归，各版166类API及359文件语法通过；PHP7.2／8.5实际安装后的生产／接收／历史重建、PHPStan和311文件归档通过。首轮一次未确认返回的瞬间原因未确定，原失败及后续诊断／确定性故障均保留。

后续[接收恢复](outbox-recovery.md)新增独立检查点、业务根和代际管理，九版本地专项各501项（恢复342、适配58、输入50、字段限额51）、最终实际TLS每版314项、各166类API／364文件语法、两版消费者与315文件归档通过。该阶段首次TLS复验的超时失败与测试入口握手修正单独保留，最终终态见[验证记录](verification.md)。本地隔离TLS不是生产域名证书、外部服务、真实部署或独立安全审查证据。
