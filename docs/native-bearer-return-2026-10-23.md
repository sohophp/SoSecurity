# 独立 Bearer 认证的最终返回边界

在全新自建账号、初始因子及独立见证环境中，`authenticate` 和 `fromAuthorization` 各复现四个反例：完成后请求权限撤销、所需范围撤销、凭据到期仍返回认证结果，以及返回对象保留已撤销的其他有效范围。两份修前矩阵共12项，八项失败；正常路径及不扩大范围的对照通过。证据见 [baseline.json](native-bearer-return-evidence-2026-10-23/baseline.json) 和 [scope-baseline.json](native-bearer-return-evidence-2026-10-23/scope-baseline.json)。

修复与业务事务共用只读返回核验，重新读取准确凭据、当前账号及范围，不使用准入时缓存的权限。返回范围取前后观察的交集；即使认证期间新授予某项范围，也不会扩大本次结果。`metadata()->scopes()`仍是签发时的范围记录，当前授权必须使用`scopes()`／`allows()`，并继续执行业务对象授权。

请求预算贯穿原生准入、内部认证和返回核验。无效令牌仍返回null；完成后失权、到期或依赖故障拒绝返回结果。核验不更新last_used，不创建新pending，不删除已完成状态，也不续办任何未知结果。回调异常和重入错误保持脱敏拒绝。

宿主边界预算守卫需支持只读动作`api.credentials.authenticate_check`；原有业务路径继续使用`api.credentials.execute_check`。原生`requestGuard`的`authenticate`及范围提供器都可能重复调用，必须只读。一次性入口预算／证明消费应在入口层完成，回调只复核本次请求上下文和当前权限，不重复扣费，也不能缓存跨请求权限。

公开类／接口仍为277，公开签名不变。公开认证入口固定转发三个声明参数，未声明的位置参数不再进入内部Deadline，也不会执行额外对象的JSON序列化；两个修复期间发现的TypeError反例保留。

PHP8.5初轮修后22/22通过。扩展矩阵最初的25项失败来自错误的版本断言，已依据见证源码修正为每次操作仅增加1，并保留原始日志；两项PHP7.2命令分别发生SQL超时和签发阶段的身份依赖故障，预期断言未完成，未按断言修正重跑。最终63/63命令通过，包含25项断言重验、九版36项额外参数边界及API／静态检查。共享业务回归8项和普通凭据回归2项通过。私有MySQL两端8/8、离线ZIP／全新消费者16/16通过，vendor摘要一致，自建资源已清理。MySQL及共享业务的PHP7.2采用真实单调时钟测试运行时，不替代默认运行时失败；功能专项预算保持原配置，没有提高生产默认值。详见[汇总](native-bearer-return-evidence-2026-10-23/summary.json)和[阶段说明](native-bearer-return-evidence-2026-10-23/phase-notes.md)。

这些是本批定向证据，不是九版全项目验收。历史PHP7.2时钟失败、两项原因未定的失败、MySQL默认预算、剩余非暂缓清单及最终候选核对仍开放，goal保持active。本批不涉及跨代际交接、未知回执续办、最终账号恢复或完整F01。

原生HTTP示例的SecurityException映射经源码核对：api_credentials.denied已有403处理，依赖故障映射503；本批没有据此宣称新增HTTP／浏览器验收。未提交、推送、部署或外部投递。
