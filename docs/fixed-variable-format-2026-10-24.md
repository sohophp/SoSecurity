# 旧驱动固定系统变量结果规范化

2026-10-24。本批继续处理原生默认调用预算。当前驱动无法读取STRINGIFY_FETCHES时，固定锁等待／耐久性查询原本逐次准备；本批只修改SqlStateAccess，保持SQL、参数、数据库设置和每次查询执行。

## 修前确认与实现

真实SDK的已注册原生子读取，两次相同锁等待观察在PHP7.2准备2次、执行2次；PHP8.5原本准备1次、执行2次。见[修前两端控制器记录](fixed-variable-format-evidence-2026-10-24/matrix-controller.log)、[PHP7.2](fixed-variable-format-evidence-2026-10-24/php72-pair.log)、[PHP8.5](fixed-variable-format-evidence-2026-10-24/php85-pair.log)。未根据历史完成记录推定当前状态。

仅对已有四种无参数SQL（全局InnoDB刷盘策略、会话行锁等待、元数据锁等待及两项合并读取），且满足严格原生资格、getter确实不可读时，校验结果为一行一值或规范的一行两值，并以SqlSchema::integer校验后输出规范十进制文本。该结果不受获取格式影响，允许使用原有已关闭语句池。每次仍执行查询取得当前值；不缓存变量值或授权，也没有增加新的SQL白名单。

SQL字符串及返回键保持。支持getter、自定义PDO／Statement／Clock／非纯守卫、非自然列名和未注册连接保持原路径。原有异常模式、原生预处理、预算、游标清理、8槽限制及活跃句柄移出池机制保持。规范化在受控获取区域内完成，验证失败仍关闭游标；关闭失败继续使单元拒绝继续。日志窗口开始前，进入SQL单元已准备会话变量，所以本体内某些统计为Prepare0／Execute2，表示复用既有句柄；每次值仍重新读取，不能把0解释为没有执行。见[九版正常观察](fixed-variable-format-evidence-2026-10-24/normal-observations.json)。

[源码增量](fixed-variable-format-evidence-2026-10-24/source-change.diff)只修改一个内部类；公开API仍为278类／接口，无公开签名、DDL、存储／摘要格式或默认预算变化。[367份最终摘要](fixed-variable-format-evidence-2026-10-24/final-inputs.json)中的其余366份保持。兼容变化仅在旧驱动的严格原生固定读取中：返回值规范为已校验数字文本，现有调用者仍解析为整数；畸形结果可提前以sql.corrupt拒绝，原本由调用者报告的错误原因可能不同。

## 本地测试与证据边界

新增专项15种场景，覆盖四种变量的逐次值变化、STRINGIFY切换、未注册／适配器／自定义时钟／守卫／列名降级、零值、耐久性变化拒绝、关闭false／异常、获取及关闭同时失败、非白名单SQL和畸形结果。全局策略只在自建无TCP测试实例修改并恢复；未访问生产数据库。

最初新测试遗漏进入SQL单元前已准备的行／元数据等待语句，原1次预期与实际窗口0次不符；已按计数起点修正。MySQL会拒绝或规范化行锁等待0，零值场景改用原本合法的刷盘变量0；没有改变SDK的等待限制。关闭失败测试增加独立完成标志，避免单元最终拒绝遮蔽断言失败。原测试和日志均保留。

旧耐久性回归还在匹配SELECT DATABASE()，与此前二进制数据库探测修复不符；现只更正匹配SQL，仍要求原8次新鲜探测和原有淘汰／清理断言。已注册原生等待对的准备次数按新行为从2改为1，其每次执行、当前值和退出恢复断言保留。首次主轮启动器因日志文件已存在而在执行前失败，另存新日志启动，未覆盖旧证据。

九版主轮52程序中51通过、1项PHP7.2等待对预设时钟失败；两端前置探测其余相关通过记录及14个未执行账本场景分别保存。新增15场景／版共135场景全部通过。SQLite27、API9及静态1共37/37通过；实际ZIP离线全新消费者两端12个MySQL与6个SQLite程序共18/18，7/7步骤通过，反射来源及367份SDK／SQL摘要一致，自建资源清理完成。[主轮](fixed-variable-format-evidence-2026-10-24/matrix.json)、[前置两端结果](fixed-variable-format-evidence-2026-10-24/probe-after.json)、[账本余项](fixed-variable-format-evidence-2026-10-24/remaining.json)、[本地检查](fixed-variable-format-evidence-2026-10-24/local-checks.json)、[消费者](fixed-variable-format-evidence-2026-10-24/consumer/consumer.json)、[消费者逐程序结果](fixed-variable-format-evidence-2026-10-24/consumer/test-rows.json)。PHP7.2账本回归前置探测在四个已通过场景后遇持续时间时钟倒退，保留失败，单独执行余下14个场景通过。主轮PHP7.2等待对也在预设持久化时遇时钟倒退，不能称主轮全绿；同源码和同测试的前置13场景结果作为独立覆盖证据，不关闭时钟问题。其他已通过程序未为求绿重复执行。

全部功能及消费者程序结束后，针对实际改变的PHP7.2路径串行检查一次默认正常管理流程。使用既有只加载Sodium的包装器，保持实际PDO／SystemClock、原时长时钟、纯来源守卫、策略提示1和3000ms预算，没有注入hrtime。首次签发约3.124884秒以account.operation_timeout拒绝，见证current，尚未返回凭据；堆栈在返回审计检查的StateBoundary入口。后续查询、轮换、替换、撤销及拒绝场景未执行，没有重试或续办。其他八版默认流程本批未重复，旧失败不作为当前候选通过。[计时](fixed-variable-format-evidence-2026-10-24/workflow/default-72-timing.json)、[结果](fixed-variable-format-evidence-2026-10-24/workflow/default-72-result.json)、[失败堆栈](fixed-variable-format-evidence-2026-10-24/workflow/default-72-run.log)。一次时序不能证明稳定提速。

默认预算稳定通过及最终非暂缓验收仍未完成，goal保持active。完整check.sh、跨安全代际工作进程交接、未知回执续办、最终账号恢复启用、依赖完整F01和外部验收未执行。只清理自己的测试进程、临时表、用户和日志；未提交、推送、部署或修改内部任务数据库。
