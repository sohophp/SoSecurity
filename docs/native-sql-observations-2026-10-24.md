# 原生 MySQL 同次观察去重

本批减少两处重复数据库观察；没有提高默认3000ms预算，也没有缓存权限、工作进程事实或会话变量值。默认首次凭据签发仍失败，最终非暂缓候选仍未完成，goal保持active。

`SqlSchema::ledgerSchemaContext`在准确原生路径中让固定双表共享同一SQL语句内的主体／数据库／schema和global触发器权限观察。修前每条语句含两份schema、两份global权限子查询及四次CURRENT_USER文本引用；修后为一份／一份／两次。两表各自的逐表权限和触发器检查、重复物理表解析、临时表遮蔽拒绝、元数据锁及完整账本认证保持。自定义时钟、PDO和语句适配器仍走原路径。64次未开启查询日志的局部观察在一次对照中由约0.198秒变为0.133秒，仅作该次局部取证，不是完整签发的性能验收。

`SqlTransaction::readIn`在准确原生路径中用一条新执行的固定查询读取行锁和元数据锁两个当前会话超时值，代替两条独立读取；读取前后均核对当前原生资格。按原剩余期限收紧，错误／超时退出及主体修改会话配置后按原规则恢复。`SqlStateAccess`只把这一固定查询加入既有八槽有界语句复用范围；每次仍执行读取，不复用值。自定义时钟／PDO／语句、未知入口守卫保留原逻辑；模拟预处理继续在构造时拒绝。

## 当前验证

PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3、8.4、8.5在自建禁TCP MySQL8.0.46实例共执行45条程序／594场景，全部通过。其中同次公共观察9场景、会话成对读取117场景、共享权限135场景；另有双表上下文117场景与元数据等待216场景。权限包括逐表、不完整授权、全局、partial_revokes、两表触发器及同事务撤权；等待包括最新值、配置恢复、自定义依赖降级、注册状态、原生属性、主体错误和真实到期。只清理本次创建的资源。

九版SQLite3.26.0相关锁等待及借读失败传播18条程序／261场景通过；九版API检查均为278个类／接口。初轮PHPStan报告一次错误：原生资格判断依赖可变PDO状态，却被推定为纯方法。补充`nativeLockPolicy`的`@phpstan-impure`标注后静态分析通过，没有加入忽略规则。该标注是专项后唯一SDK修改；[token核对](ledger-shared-visibility-evidence-2026-10-24/token-equivalence.json)证明可执行代码与九版专项一致，其他366文件字节保持。标注用法按[PHPStan官方说明](https://phpstan.org/blog/remembering-and-forgetting-returned-values)核对。

实际Composer ZIP离线安装到全新非符号链接消费者，367份SDK／SQL文件逐一匹配最终源码。PHP7.2／8.5各执行上述五条程序，共10程序／132场景通过；5个准备／来源／运行步骤全部通过，临时目录无残留。发行包排除测试、工具、私有证据和符号链接。这是专项及安装检查，不是全项目整轮验收。

原始失败分别保留：旧查询去重断言失败、旧双独立超时读取断言失败，以及第一候选测试错误地期望模拟预处理受支持的构造拒绝。修正测试预期后验证原有拒绝，不修改构造保护。前期候选副本、正式工作区、消费者各自绑定准确输入，不重复累加。

## 未关闭项与兼容

只合并公共权限观察的默认签发实验约3.003秒失败；两项改动均落地的当前原生SystemClock／PDO实验同样约3.003秒失败，返回`account.completion_unknown`且为pending，未续办。失败在写入后的最终身份复核，不用局部SQL成本下降代替签发成功；见[当前默认实验](ledger-wait-pair-evidence-2026-10-24/default-85-timing.json)。历史PHP7.2时钟／预算失败、其他非暂缓产品余项和最终候选核对仍开放。

公开签名、类型数278、DDL、存储格式、默认期限及授权规则保持。原生数据库查询数量减少；自定义依赖保留兼容路径。没有执行安全代际交接、未知回执续办、最终恢复启用、完整F01、生产或外部投递；没有提交、推送或部署。

[汇总及输入摘要](ledger-shared-visibility-evidence-2026-10-24/delivery.json)、[源码差异](ledger-shared-visibility-evidence-2026-10-24/source-change.diff)、[九版MySQL](ledger-shared-visibility-evidence-2026-10-24/matrix.json)、[SQLite／API及原静态结果](ledger-shared-visibility-evidence-2026-10-24/local-checks.json)、[最终静态日志](ledger-shared-visibility-evidence-2026-10-24/static-final.log)、[归档消费者](ledger-shared-visibility-evidence-2026-10-24/consumer/consumer.json)。
