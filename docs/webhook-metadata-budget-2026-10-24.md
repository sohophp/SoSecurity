# Webhook接收元数据的返回字节预算

2026-10-24。复核现有接收路径后确认普通接收读取损坏元数据会在校验前耗尽PHP内存。本批补齐同一接收器两处元数据SELECT的返回字节边界，没有增加新功能或实现未知续办。

## 实际资源失败与最小修复

在自建SQLite上先完成正常接收，再把event_type改为12MiB测试字符串。PHP7.2／8.5、普通receive／私有observation四个子进程在8MiB限制下均退出255，报尝试分配12582944字节、内存耗尽。私有方法复现是组件读取证据，不能当作完整受保护入口失败：后者另有来源快照校验。

父控制器为每个子进程创建独立TMPDIR，即使PHP内存耗尽未能执行finally，也只清理该控制器自己的目录。四个子进程均终止，目录清理已记录。修后同四个程序退出0，捕获webhook.inbox_corrupt，PHP峰值2097152字节，仍保留1条、12MiB损坏字段；没有通过改写或删除数据取得通过。

证据：[四个修前终态](webhook-metadata-budget-evidence-2026-10-24/before-result.json)、[修前8.5](webhook-metadata-budget-evidence-2026-10-24/before-85-receive.log)、[四个修后终态](webhook-metadata-budget-evidence-2026-10-24/after-result.json)、[修后8.5](webhook-metadata-budget-evidence-2026-10-24/after-85-receive.log)。

SDK只改SqlInbox的私有columns投影，由普通读回和原生准入观察共用。固定14个字段按现有校验器的字节上限返回，SQLite用length(CAST(... AS BLOB))，MySQL用OCTET_LENGTH；超限不将完整值送入PHP。非空字段超限返回NULL供原校验器拒绝；source_time合法NULL保持NULL，非法非NULL超限返回负数哨兵，避免变成可通过原NULL签名的值。既有整数格式、HMAC、关联与正文校验不变。

没有强制SQLite存储类型转换：长度内原先可接受的文本／BLOB表示和规范整数仍交给原校验器处理。合法已存值不被截断或改写。MySQL声明本来限制字符串宽度，专项按实际支持范围验证合法上限、范围内篡改拒绝、数字和NULL；没有放宽Schema或SQL模式来存入超限值。

只新增有界投影表达式；原WHERE、参数、LIMIT 1、锁、读回顺序、权限与提交复核、事务和默认预算保持。公开API仍278类／接口，存储格式、DDL和候选契约不变，其余366份运行输入保持。读取返回上限不依赖数据库字段当前实际大小。见[源码增量](webhook-metadata-budget-evidence-2026-10-24/source-change.diff)、[冻结输入](webhook-metadata-budget-evidence-2026-10-24/final-inputs.json)。

## 专项、回归与失败边界

九版SQLite／API原批次23/27，MySQL17/18。每个预算程序目标31场景；SQLite覆盖12个字段1MiB异常值及可空时间的普通／私有读取，MySQL用声明范围内的真实篡改验证拒绝。五个正常场景涵盖已确认回执重复、GitHub合法NULL、多字节256字节资源名及最大字符串／32字节密钥标识、19位整数、原先可接受的SQLite二进制表示。

PHP7.2、7.3、7.4、8.0各两项私有观察断言错误地只接受整数-1；旧SQLite PDO返回字符串-1。修正仅允许这两种规范负数表示，仍要求不是NULL、原校验器拒绝、无更新、记录保持、映射不重做及内存不超过8MiB。只补8个原未完成验证的场景，4个补充程序通过，未重复已通过用例。原测试源码、失败日志和更正说明保留。

九版本558个预算目标场景，557个取得通过证据，保留PHP7.2 MySQL的event_type/receive一项未解释失败。原测试只记录了断言失败，未保存最初SDK错误码，不能确定原因。独立新消费者同项通过只作补充证据，不覆盖或关闭原失败，本批未重跑该场景凑绿色结果。

现有接收清理专项只更新SQL选择器，使其能准确命中新的投影查询，所有断言保持；九版SQLite／MySQL900个回归场景通过，九版API278通过。两端两后端原生共享状态3/4通过，PHP7.2 MySQL在FenceStateSnapshot读取遇真实持续时间时钟倒退，停止后续步骤并保留失败，未续办。测试时钟只用于既有逻辑时间边界，不修正真实Deadline时钟。

证据：[SQLite／API](webhook-metadata-budget-evidence-2026-10-24/local-result.json)、[MySQL](webhook-metadata-budget-evidence-2026-10-24/mysql-result.json)、[PHP7.2原MySQL预算失败](webhook-metadata-budget-evidence-2026-10-24/72-mysql-budget.log)、[哨兵测试修正](webhook-metadata-budget-evidence-2026-10-24/sentinel-test-correction.json)、[8场景补充](webhook-metadata-budget-evidence-2026-10-24/sentinel/local-result.json)、[回归选择器唯一差异](webhook-metadata-budget-evidence-2026-10-24/regression-selector-change.diff)、[原生SQLite](webhook-metadata-budget-evidence-2026-10-24/native-sqlite-result.json)、[原生MySQL](webhook-metadata-budget-evidence-2026-10-24/native-mysql-result.json)、[原生时钟失败](webhook-metadata-budget-evidence-2026-10-24/72-native-mysql-shared.log)。

## 归档消费者与未关闭事项

实际ZIP与离线新安装核对367份SDK／SQL、安装来源和无符号链接。原消费者6/7外层步骤、7/8功能程序通过，PHP7.2 SQLite的2个哨兵类型断言失败；新安装中仅补这2场景通过，4个准备／功能步骤及自身资源清理完成。原消费者失败保持，不写成原批次全绿。

静态最终No errors，保留可选turbo扩展GLIBC_2.32启动警告，未改环境；PHP27项、Python和Shell语法通过。[消费者原终态](webhook-metadata-budget-evidence-2026-10-24/consumer/consumer.json)、[消费者MySQL各程序](webhook-metadata-budget-evidence-2026-10-24/consumer/test-rows.json)、[两场景消费者补充](webhook-metadata-budget-evidence-2026-10-24/sentinel-consumer.json)、[静态](webhook-metadata-budget-evidence-2026-10-24/static.log)、[语法](webhook-metadata-budget-evidence-2026-10-24/syntax.json)、[交付核对](webhook-metadata-budget-evidence-2026-10-24/delivery.json)保留。本批不是全项目或稳定版验收。

默认凭据性能、PHP7.2历史时钟与未解释依赖错误、上述MySQL未解释失败、共享检查和最终非暂缓整合仍开放，goal保持active。暂缓跨代交接、未知回执续办、最终恢复启用和完整F01；未定义OIDC关联迁移按授权跳过。真实IdP／设备、生产代理／WAF和外部投递未验收。未运行完整check.sh或处理器未知路径，未提交／推送／部署、未访问生产数据库，既有环境、数据和其他未提交改动保留。
