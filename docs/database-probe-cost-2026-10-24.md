# 当前数据库身份探测与预备语句协议诊断

2026-10-24。本批没有改变SDK的查询协议。继上批确认SQL构造约13.8ms、语句池命中99.38%后，仅在证据目录的SqlStateAccess副本中统计首次签发期间的数据库身份探测，不记录SQL、参数、身份或返回数据。

一次PHP8.5原生PDO／SystemClock、自建无TCP MySQL测得454次探测，累计171.733394毫秒，约占原3000ms预算5.7244%；其中账本上下文318次、列元数据136次。该插桩首次签发约2.803661秒返回成功、见证current，随后直接返回，没有继续管理流程；不是默认完整验收或性能前后对照。原SDK／SQL367份输入在诊断结束时保持。

[预定门槛](database-probe-cost-evidence-2026-10-24/criterion.json)、[原始计数](database-probe-cost-evidence-2026-10-24/measurements.json)、[实际计时](database-probe-cost-evidence-2026-10-24/default-85-timing.json)、[结束／输入／清理](database-probe-cost-evidence-2026-10-24/default-85-result.json)保留。只有测量达到门槛，不能据此省略数据库切换、权限或物理表复核。

源码核对发现，原生账本上下文SQL已经合并物理表解析；仅移动或传递一次库名提示不会减少查询。于是另做一次原型对照：A为原来先取得新鲜库名、再执行复用语句；B为同一上下文SQL每次重新准备，省去其缓存键探测。SDK未改，所有原授权／耐久性／游标检查保留。

原型冻结两端、每方案64次预热、64轮交替ABBA／BAAB，每样本4调用；要求两端累计和中位数均至少快5%，基线首尾四分位漂移不超过5%，并需功能等价。PHP7.2实际累计比值1.28225、中位比值1.26097、漂移2.7936%，已经不满足性能要求；临时表两种方案均拒绝。随后原型清理错误调用了不存在的SqlStateAccess::unbind，程序退出255；永久绑定限制没有改动。因为前一预设未清理表，PHP8.5只在建表阶段失败，没有计时。控制器自身残留断言也失败，原始失败全部保留，外层测试拥有的临时目录和私有服务器已终止并清理。

两端原型程序均不能称为通过，数据库切换等采纳所需功能检查未完成。已有性能反证足以拒绝该方案，不补跑计时或修改SDK凑结果。[预定条件](context-prepare-protocol-evidence-2026-10-24/criterion.json)、[7.2原始样本](context-prepare-protocol-evidence-2026-10-24/result-72.json)、[逐程序退出](context-prepare-protocol-evidence-2026-10-24/prototype-rows.json)、[控制器失败](context-prepare-protocol-evidence-2026-10-24/driver.log)、[最终判断及清理核对](context-prepare-protocol-evidence-2026-10-24/decision.json)完整保留。

后续[已确认消息清理](outbox-sent-purge-2026-10-24.md)修改另一个普通路径；本诊断不冒充其最终候选的默认验收。更大的纯SQL快照分组仅是[未实现假设](database-probe-cost-evidence-2026-10-24/next-candidate.json)，须先证明原资源上限、格式、权限与锁约束再判断收益，不是已完成工作或自动执行指令。
