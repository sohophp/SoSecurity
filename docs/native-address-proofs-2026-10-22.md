# 地址变更邮箱证明的原生请求入口

## 已确认缺口

原计划记录地址变更仍缺少保护模式的前置准入。本批先处理其中可独立完成的邮箱确认与取消：Security::addressChange原先没有传递accounts.state_request_guard，直接调用confirm会在执行请求守卫前得到account.state_required。真实新账号、会话和一次性操作授权已准备好，但分阶段请求拒绝断言失败，见[before.log](native-address-proofs-evidence-2026-10-22/before.log)。

同时复现共享StateLifecycleRequests直接传播请求守卫的原始异常文本，见[guard-before.log](native-address-proofs-evidence-2026-10-22/guard-before.log)。这些是修复前失败记录，不是最终测试结果。

## 实现及兼容

AddressChange构造函数末尾新增可空StateRequestGuard requests参数；之前所有参数、顺序和默认值保留，公开类型仍为272，没有新增类型。Security::addressChange传递已有accounts.state_request_guard配置。未配置时仍使用原显式外层边界方式；配置后，confirm和cancel直接进入原生分阶段流程，不应再由宿主手工包裹。

请求动作分别为address_change.confirm及address_change.cancel。公开请求守卫和有界输入检查先执行，公共预算只收取一次；锁内再次检查current，之后才写pending并执行原有证明事务。selector、side、token和可信宿主source仍按原规则验证。实际邮箱令牌、当前账号与地址版本、旧／新邮箱确认、错误次数和过期条件没有放宽。

StateLifecycleRequests及LocalStateWitness仅增加address_change.confirm／cancel，不接受address_change.request或complete。申请与完成仍要求原有真实会话和一次性操作授权，不能借公共请求守卫直接改变地址。测试也明确拒绝使用此处理器执行地址申请。

受保护事务中的预算拒绝现在使用既有StateBudgetRefusal回滚证据。只有当前准确执行已确认回滚、SQL及完整来源均未改变、pending本身未被替换时，才能完成无效果拒绝；不会退款或清空公共请求额度。若回调已写入受保护文件，或者证明已提交后权限拒绝，则保留pending，不回滚已提交效果、不续办。

共享请求处理器把public及current守卫异常转换为不携带原异常的DependencyException，固定原因码account.request_unavailable。明确返回false仍为account.request_denied。此脱敏同时适用于注册、恢复、邮箱恢复的请求守卫；测试这些目的时只触发守卫异常，业务回调设置为禁止执行，没有执行恢复确认或最终启用。

## 本地验证范围

新原生场景使用实际新账号、密码会话、本人对象／字段授权、重新认证及一次性操作凭证，先在已有显式边界内创建地址申请。随后直接通过原生入口验证旧／新邮箱证明和取消，检查错误令牌计数、重复确认不重复计次、ready不自动改址、取消后失效、请求拒绝、重入拒绝及输入预算。原账号地址与版本始终保持。

主体／最终预算拒绝分别验证SQL回滚、证明不被消耗、完整来源保持且见证返回current；有文件效果的预算拒绝和提交后失权只检查pending保留，不执行任何续办。另覆盖两阶段异常脱敏和四类生命周期处理器的纯守卫拒绝。

相关普通AddressChange测试继续验证原有改址行为；这不是账号恢复启用。所有通知只在本地加密保存／读取，没有SMTP、外部账号、生产数据库或部署操作。

证据目录：[native-address-proofs-evidence-2026-10-22](native-address-proofs-evidence-2026-10-22/)。具体矩阵、MySQL、归档消费者、API和源码摘要见其中记录；不把定向验证当成全项目验收。

## 剩余范围

地址申请、意图准备和最终改址的当前账号／一次性授权在pending之前的完整原生纯判断仍需核对，不能用本批邮箱证明入口宣称完整AddressChange原生闭环。PHP7.2未解释的时限失败及前批脱敏提交异常仍保留；其他产品入口、最终候选冻结和外部验收也未关闭。暂缓的跨代交接、未知回执续办与最终恢复启用不恢复，goal保持active。

最终本批结果：九版源码定向矩阵80/81通过；PHP7.2的budget-effects在准备地址申请时约3.733秒失败，原始异常已脱敏为操作认证不可用，目标场景未执行完成，底层原因未确认。两端私有MySQL的12套原生场景及2套普通地址变更测试全部通过（普通各210断言）；PHP7.2明确使用单调时钟包装。归档消费者11/12通过，PHP7.2的guard-error在约0.366秒初始化阶段触发持久化超时，目标场景未执行完成。两项首次失败日志保留且未重跑覆盖；本批通过不关闭旧超时和提交异常。四个修改运行时文件与归档摘要一致，临时消费者已清理。语法12/12、PHPStan及最后修改文件复核通过，可选turbo扩展GLIBC警告保留。精确范围、命令和摘要见result.json、matrix-driver.py、archive-driver.py、api-review.json及source-sha256.json。
