# 当前权限时钟的错误边界（2026-10-22）

复核原生维护入口时，实际复现StateAccountPolicy::now直接抛出宿主Clock异常，泄露其原消息和异常类型。原始失败见[before.log](permission-clock-evidence-2026-10-22/before.log)，使用合成私密标记，没有读取实际凭据。

现在捕获Clock调用中的Throwable（含错误返回类型触发的TypeError），统一为固定account.clock StorageException，不保留原异常链。负时间及溢出上限仍按原规则拒绝；正常时间、操作时限、SQL和见证保护不变。这不修复或解释此前基于持续时间的sql.timeout。

## 验证

扩展tests/state-boundary/native-maintenance.php的clock场景：真实公开工厂、账号／会话／角色和完整来源下，分别注入异常、错误类型、负时间和溢出时间。每项同时验证直接policy.now与原生维护入口，确认错误原因固定、无原消息／previous链、管理回调未被调用且见证不变。恢复合成时钟后原连接仍能执行合法维护。没有执行恢复确认、账号启用、工作进程交接或未知结果续办。

[证据目录](permission-clock-evidence-2026-10-22/)：

- matrix.json：PHP7.2—8.5九版27条命令全部通过；时钟故障各107断言，影子账号表拒绝各77断言，API反射保持271类型。
- mysql.log：私有无TCP MySQL控制器退出0，两端各时钟／映射两套，共四套通过。
- archive.json：最新ZIP、离线全新非链接Composer安装、两端实际StateAccountPolicy vendor来源与两个场景，共8条命令通过，安装文件与当前源码摘要一致。
- static.log：PHPStan退出0，原环境可选turbo扩展GLIBC警告保留。
- completion.json：两端四份PHP语法及shell／Python入口、相关空白检查通过；记录源码和测试摘要。未改API候选。

## 兼容与限制

Clock异常现在统一为account.clock，调用方不能依赖底层异常类型、原消息或异常链；自定义时钟仍须只读。公开签名、271类型清单与既有数值范围保持。测试的恢复仅指故障注入后还原测试时钟，不是账号恢复或未知回执续办。

本批为定向错误处理修复，不是全项目门禁。既有PHP7.2持续时间超时、剩余写入者／通知对账、暂缓能力和外部验收均未关闭。没有提交、推送、部署或生产访问，goal保持active。
