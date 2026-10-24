# 记住登录的风险决策完整校验与提交后复核

本批继续处理非暂缓产品缺口，实际修改RememberedLogin。没有执行跨安全代际工作进程交接、未知回执续办、最终账号恢复启用或完整F01。

## 已复现问题与修复

1. 普通记住登录只分支处理deny和step_up，其余动作落入允许路径。DeviceRiskDecision的构造器校验在PHP反序列化时不会自动执行；返回同类型但动作未知的合成缓存对象，原实现仍返回authenticated并提交轮换。初始修前失败见[before-invalid.log](remember-risk-boundary-evidence-2026-10-23/before-invalid.log)。原生保护模式提交后的allow/compromised畸形组合同样未被拒绝，修前类通过独立临时入口加载复现，未覆盖工作树；见native-before.log和native-before.json。
2. 普通路径只在存储事务之前评估风险。测试在实际轮换提交后将风险改为deny，原实现仍返回authenticated，见[before-late.log](remember-risk-boundary-evidence-2026-10-23/before-late.log)。

接入处现在重新构造并校验完整动作／原因快照，未知动作、非法组合、缺失成员及错误成员类型均按auth.device_risk_denied拒绝，不泄露原异常链；风险服务本身抛错仍按auth.device_risk_unavailable拒绝。合法的直接构造或缓存对象仍可使用，没有新增反序列化入口或修改DeviceRiskDecision的序列化接口。测试中的受限类反序列化仅用于构造异常缓存，不是生产接入示例。

普通恢复成功提交后、最后一次会话／身份校验之前，配置的风险回调再次执行；只有明确allow可返回凭据。原生模式保留已有见证完成后的风险复核，不重复新增普通路径的中间复核。风险回调始终在可重试AtomicStore回调之外，必须只读、可重复且无业务副作用。

提交前无效风险结果不消费持久令牌；提交后拒绝或服务异常不返回新会话／持久凭据，不回滚已提交轮换、不恢复旧令牌、不自动重试。测试只检查自建已提交状态，没有再次resume迟到拒绝的令牌。最后会话校验保留，可拒绝风险回调等待期间过期或身份已变的结果。独立风险与身份来源的这些读取不构成跨来源原子快照，来源及信号真实性仍由宿主负责。

公开277类／接口、方法签名、存储格式、DDL和默认预算保持。普通风险回调的调用次数在成功路径由一次变为两次；deny／step_up及无效令牌等早退路径不额外调用。畸形对象不再被隐式允许，是有意收紧。

## 当前验证与保留的失败

主体95项程序中93项通过，12067项断言通过，静态分析及PHP7.2／8.5 API277核对通过；不是整项目验收。逐项命令及退出码见[本地证据目录](remember-risk-boundary-evidence-2026-10-23/)中的verification.json、mysql-native.json及qualified-summary.json。

- 九版PHP7.2、7.3、7.4、8.0—8.5：内存／文件新专项各166项、原设备风险81项、记住登录499项及认证199项。覆盖未知动作、非法动作／原因、错误成员及服务类型、异常脱敏、合法缓存、提交后deny／step_up／异常／畸形结果、回调等待期间到期和身份变化、回调不进入重试事务、原旋转／重放／容量／固定期限等。
- 两端真实MySQL各166项通过；采用SDK实际支持的共享AtomicStore后端。本批未改SQL运行时代码。
- 九版原生SQLite的正常恢复及两个畸形风险场景，另两端deny／step_up／服务异常／撤权／到期／时钟故障；PHP8.5原生MySQL五个对应场景通过。PHP7.2两项原生场景失败，分别为72-native-risk-invalid-reason、72-native-risk-step_up；日志均明确记录Deadline检测到Security duration clock moved backwards。失败保留，没有调整、钳制时钟或通过重试改成绿色，未通过普通专项抵销。
- PHP7.2／8.5各通过本地设备风险HTTP40项及记住登录HTTP182项；182为累计总数，未将87项中途计数重复累加。使用自建本地服务与真实Cookie／Session，不代表生产或真实浏览器验收。

新SQL测试还补严格建表所有权：不用CREATE IF NOT EXISTS后无条件清理，只在实际创建成功后删除本次表。主体资格检查后的测试清理变化与旧测试源码分别保存在test-cleanup-change.json和remember-risk-boundary.qualified.php。PHP7.2／8.5补验各166项及既有表保护各2项通过；合成既有表被拒绝创建且数据保留，最后仅清理自建表。运行时代码与主体资格输入一致。

## 归档及独立消费者

真实Composer ZIP、离线全新消费者16步骤全部通过，其中12项实际程序、2217项断言。PHP7.2／8.5均验证内存／文件及真实MySQL的新风险边界，并运行原设备风险、记住登录回归；PHP8.5另验证原生SQLite正常恢复及提交后的畸形风险拒绝。确认Security、RememberedLogin、DeviceRiskDecision来自vendor，改动源码及15份实际安装SQL资源摘要匹配；测试和本地证据排除于发行包，临时目录已清理。见archive.json、archive-summary.json及archive-inputs.json，不作为完整发行验收。

主体的93项通过程序包含：普通单元／回归45项、9999项断言；原生42项、1292项断言；真实MySQL普通路径2项、332项断言；HTTP4项、444项断言。另有上述两项已执行但失败的原生程序。清理补验和消费者结果单独统计，没有重复累加同一用例或把失败场景列为未执行。

运行时、测试及清理补验的输入核对见closeout.json。主体原输入摘要仍保留，其中当前唯一预期差异为tests/remember-risk-boundary.php的测试建表／清理防护；SDK运行时代码、断言主体均保持。该测试的相关MySQL分支已在两端补验，并由全新消费者再次执行。

最近默认API签发失败仍为[上一批3.051810376秒／pending](ledger-table-pair-evidence-2026-10-23/default-timing.json)，本批记住登录改动不在该签发路径上，未重复运行。默认预算、PHP7.2时钟失败、其余非暂缓入口／提供器核对及外部验收继续开放，goal保持active。没有提交、推送、部署、生产数据库访问或外部投递。

## English compatibility

Persistent-login risk decisions are validated again as complete action/reason pairs, including cached objects that bypassed their constructor. Malformed results fail with auth.device_risk_denied; provider exceptions retain auth.device_risk_unavailable without the original exception chain. A configured ordinary risk callback is now called again after successful rotation and before the final identity/session check, so it must be read-only and repeatable. A late refusal withholds credentials while retaining committed rotation; it does not restore old tokens or automatically retry. Native completion keeps its existing final review. Public API277, signatures, storage formats, DDL and defaults are unchanged. The focused run passed 93 of 95 programs; two PHP7.2 native cases failed on backwards duration-clock readings and remain open. Installed-package checks passed separately and do not erase those failures.
