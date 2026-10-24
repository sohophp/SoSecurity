# 私有SQL结构与耐久性观察的游标清理

2026-10-24。本批处理独立可复现的非暂缓产品缺口，保留此前全部环境、数据和未提交改动。

## 问题确认与修复

SqlSchema::table／tables的物理解析及多处SQLite结构观察忽略closeCursor的false，部分读取没有显式关闭。SQLite耐久性观察的三条PRAGMA也没有显式清理。调用者即使捕获异常，SQL单元仍可继续执行并提交，把不确定的结构观察当作可用证明。

SQLite最初64场景中48项未满足拒绝要求；补入耐久性后每端88场景中66项失败。MySQL修前单表／双表、注册／未注册连接的16场景中12项失败。关闭异常、获取和关闭同时失败、捕获后仍可继续等实际记录保留：[PHP7.2原始](private-schema-cleanup-evidence-2026-10-24/php72-before.log)、[PHP8.5原始](private-schema-cleanup-evidence-2026-10-24/php85-before.log)、[扩展PHP7.2](private-schema-cleanup-evidence-2026-10-24/php72-extended-before.log)、[扩展PHP8.5](private-schema-cleanup-evidence-2026-10-24/php85-extended-before.log)、[MySQL修前](private-schema-cleanup-evidence-2026-10-24/probe-before.json)。原测试副本和修前运行时摘要另存，不覆盖既有源码增量。

所有SqlSchema的结果读取均转入现有SqlTransaction::metadataRows关闭通道：每次执行并完整消费、检查关闭结果；false／异常以sql.cleanup拒绝并标记单元不可继续。底层既有清理实现不把原始获取异常作为辅助函数参数，组合故障也不泄露原私有消息。零行物理解析现在还要求结果确实为空。没有删除历史认证、当前授权、表名解析、外键／触发器／索引或耐久性检查。

SQLite通道严格新增三条已存在的只读SQL：PRAGMA database_list、PRAGMA main.journal_mode、PRAGMA main.synchronous，均只接受空参数。原query只读路径本已允许它们，现复用统一关闭逻辑；没有开放赋值、多语句、其他PRAGMA或MySQL的PRAGMA。赋值、大小写／尾空格变体、多语句和额外参数等拒绝用例另验。SQLite单值耐久性结果增加一行一列形状要求，字段名大小写不影响取值。

367份SDK／SQL中仅修改两个内部类，其余365份保持；公开签名、类型清单、DDL、摘要／存储格式、SQL文本／绑定值、行／字段／内存限制、既有8槽及默认预算保持。SqlSchema中不再遗留直接query读取。正常结果兼容；原来被忽略的关闭失败现在拒绝，并要求重建失败服务。三条SQLite只读PRAGMA是内部元数据通道的显式新增能力，其余非SELECT保持拒绝。

[SqlSchema增量](private-schema-cleanup-evidence-2026-10-24/SqlSchema.diff)、[SqlTransaction增量](private-schema-cleanup-evidence-2026-10-24/SqlTransaction.diff)、[最终367份运行摘要](private-schema-cleanup-evidence-2026-10-24/final-inputs.json)、[测试输入](private-schema-cleanup-evidence-2026-10-24/test-inputs.json)。公开API按当前实际清单核对，未据历史268或277直接修改候选。

## 本地测试

最终源码已执行并通过：PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3、8.4、8.5新增SQLite96／MySQL19场景每版，共1035项；相关MySQL主轮63程序及补充主体隐私9程序均通过；SQLite63、公开API278的九版检查9及静态1共73/73通过。PHPStan保留本机可选turbo扩展缺GLIBC版本的启动警告，实际分析无错误，未改环境。

原主轮及消费者控制器在批次程序结束后还会调用sql-schema-principal.php pair，包装器只登记了首个分发，因此拒绝额外调用并退出1；不能把原控制器称为通过。没有跳过原检查或重跑已通过批次，而是在独立隔离控制器中按原pair参数执行九版主体隐私测试，9/9通过。原失败调用、已通过程序和补充证据分别保留。

真实ZIP／离线全新消费者原28个程序全部通过（MySQL14、SQLite14），原准备／控制步骤6/7；补充消费者重新建包安装并只执行两端漏项，2程序、5/5步骤通过。按30程序范围取得通过覆盖，不把原控制器失败改写成全绿。两个消费者均核对367份运行时／SQL资源摘要、四个关键类实际vendor反射来源、非符号链接安装及自身资源清理。初始归档的其他失败记录均保留。

[MySQL主轮](private-schema-cleanup-evidence-2026-10-24/matrix.json)、[主轮控制器失败](private-schema-cleanup-evidence-2026-10-24/main-controller.log)、[补充主体检查](private-schema-cleanup-evidence-2026-10-24/principal.json)、[SQLite／API／静态](private-schema-cleanup-evidence-2026-10-24/local-checks.json)、[原消费者](private-schema-cleanup-evidence-2026-10-24/consumer/consumer.json)、[原消费者逐程序](private-schema-cleanup-evidence-2026-10-24/consumer/test-rows.json)、[补充消费者](private-schema-cleanup-evidence-2026-10-24/consumer-principal/consumer.json)、[新增覆盖](private-schema-cleanup-evidence-2026-10-24/coverage.json)、[准确范围](private-schema-cleanup-evidence-2026-10-24/counts.json)。这些是定向回归，不能替代全项目、完整默认流程或稳定版验收。

新增场景覆盖单表／双表、SQLite三条PRAGMA、物理解析、外键元数据与模块遮蔽、列／索引／索引列、触发器检查，正常／关闭false／关闭异常／获取与关闭同时失败；MySQL还覆盖注册／未注册连接。故障时要求结构证明不返回、捕获后SQL仍不能继续、最终单元拒绝、事务退出、原测试数据不变。开启异常参数记录，并检查字符串、var_export、print_r及JSON转储不含私有错误。

相关既有回归覆盖表对完整独立契约、索引批次、额外唯一约束、只读借用和上下文；产品组合仅使用Outbox首次领取与已知回执确认、幂等首次执行与已知结果查询、SQL审计记录，不执行未知结果续办或外部投递。

## 默认流程与边界

本轮先做一次全新环境的原因诊断，仅给CredentialRegistry的三个认证依赖异常捕获点插入固定原因枚举计数，没有修改SDK源码、记录原始消息／参数或放宽预算。首次签发约2.794876秒成功，随后流程在第二次issue的最终审计时限检查失败；固定捕获点计数为空，没有复现上一轮被包装的认证依赖错误，因此不能据此解释其原始底层原因。该诊断不是发行候选验收，没有续办失败结果。见[诊断计时](credential-cause-evidence-2026-10-24/default-85-timing.json)、[诊断退出](credential-cause-evidence-2026-10-24/default-85-result.json)、[固定枚举](credential-cause-evidence-2026-10-24/causes.json)、[诊断堆栈](credential-cause-evidence-2026-10-24/default-85-run.log)。

诊断之后才实施本批清理修复，未重复实际默认正常管理流程，不把旧源码的首次签发或本批专项当作当前完整默认流程通过。既有上下文／根合并原型已有无收益记录，不重复实现。默认稳定预算、历史时钟失败及最终非暂缓候选验收仍开放，goal保持active。完整check.sh、跨安全代际worker交接、未知回执续办、最终账号恢复启用、依赖完整F01及外部验收均未执行。未提交、推送、部署或修改内部任务数据库；只清理自己的测试进程、账户、表和临时资源。
