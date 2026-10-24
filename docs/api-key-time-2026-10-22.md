> 后续状态：显式 FileStore 原生接入已实现并有专项验证，见[接入记录](api-key-native-2026-10-22.md)。下文保留时间修复批次当时的范围。

# 旧 ApiKeys 时间边界修复

继续核对非暂缓产品缺口时，确认旧 ApiKeys 仍未原生接入保护模式；保留 Security::apiStore 的明确拒绝。本批实际修复独立的认证、签发和轮换时间缺陷，不把它冒充原生接入完成。

## 已复现及修复

1. authenticate 在最后读取主体epoch之前检查期限，最后一次存储I/O期间过期或时钟倒退，仍会返回身份。现在每轮相关I/O后复核，并在最后epoch读取后再检查期限；已观察到的时间不得倒退。
2. issue／rotate 在存储提交和最终epoch读取后缺少时间复核，可能返回已经过期的凭据。现在写入前拒绝过期请求，写入后发生过期、倒退、时钟或最终核对异常时，只返回 api.issuance_unknown／api.rotation_unknown，不返回成功凭据、不恢复旧秘密、不重试未知结果。TTL仍从原签发时间计算，轮换不延长到期。
3. 跨请求时钟倒退到 created 之前时，尚未生效的凭据仍可能认证或轮换。现在初次记录读取就拒绝 created 大于当前时间的记录，原凭据保持不变。
4. Clock异常现在固定为 api.clock，写入后的异常纳入上述未知结果；不泄露原异常消息或previous异常链。可重试的AtomicStore回调仍不读取时钟、不随机生成秘密、不执行外部I/O。

修复前原始失败分别保存在 `before.log`（最后存储读取后的过期身份仍被接受）与 `future-before.log`（未来创建时间的身份仍被接受）。记录均为隔离合成数据。

## 本地验证

证据目录：[api-key-time-evidence-2026-10-22](api-key-time-evidence-2026-10-22/)。

- `final-matrix.json`：PHP7.2、7.3、7.4、8.0—8.5共27条运行时检查全部通过；各版新时间测试130断言（内存＋真实文件存储）、原epoch交错10断言、原API凭据／签名200断言。
- 加入Redis适配后，测试时钟改为真实时间附近的独立基准，避免Redis EXPIREAT按服务器时间提前清除合成数据。`current-time.json` 对最终测试源的九版130断言均通过。没有改变运行时TTL或时钟保护。
- `mysql-current.log`：自建无TCP MySQL，PHP7.2原生单调时钟运行时／PHP8.5分别通过时间65、epoch交错10及原API281断言，控制器退出0并清理自己的实例。ApiKeys使用的AtomicStore当前没有SQLite实现，未虚报SQLite后端验证，也未访问任何生产库。
- `redis.log`：自建无TCP Redis Unix socket，PHP7.2／8.5分别通过时间65与原API281断言。所有进程由新测试运行框架持有并终止，仅清理自己创建的临时目录。
- `final-time-consumer/archive.json`：最终运行时代码的ZIP归档、离线全新Composer安装、vendor来源反射和两端三套专项，共10条命令通过。当前ApiKeys摘要与安装副本一致；`current-consumer.json` 对更新后的测试基准再验证两端各130断言通过。此前归档是修改阶段快照，不代替这个最终运行时结果。
- `matrix.json` 初轮27条运行时与4条反射检查通过，另5个旧PHP反射进程因误设16MiB工具内存限制而OOM，未完成检查；原日志保留。`api-tooling.json` 改回前批已使用的32MiB反射工具预算后五条通过，未修改组件预算或任何拒绝规则。`completion.json` 另记录最终两端270类型API检查通过，本批未改候选契约。
- `static.log` 初轮把时钟检查误推断为纯函数，重复调用被判为恒真；增加准确的 @phpstan-impure 注释后，最终运行时代码 `static-final-time.log` 退出0。保留现有可选turbo扩展GLIBC警告，未删除检查或改动返回类型。
- shell／Python入口语法及相关空白差异检查通过。内存／文件回归和MySQL路径接入 bin/check.sh；MySQL可用 `tests/mysql_check.py --api-key-time`，Redis可用 `tests/api_key_time_redis.py` 独立复查。未运行包含暂缓能力的完整脚本。

## 兼容及仍需完成

公开签名、270类型清单、sosk_令牌、v1／v2记录格式保持。自定义时钟会被更多次读取，必须只读且稳定；原来返回过期凭据的行为改为明确拒绝或未知结果。未知结果不等于未写入，调用者不能据此恢复旧密钥或自动重复执行。

普通无见证旧备份的epoch丢失反例仍存在且被原测试保留；本批没有声称时间修复能解决状态回滚。旧ApiKeys原生声明、显式主体／作用域授权及容量接入仍未完成，不能移除现有保护模式拒绝来宣称支持。在线提供器、维护等其余计划缺口仍需继续核对；此前PHP7.2维护／共享账号超时、暂缓的代际交接／未知回执续办／最终恢复及外部验收均未关闭。goal保持active，没有提交、推送、部署或撤销既有改动。
