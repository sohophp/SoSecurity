# 原生 Bearer 业务事务的最终返回权限

全新自建账号／初始因子环境独立复现三个缺陷：业务SQL已提交后，请求守卫拒绝、当前能力范围撤销或凭据到期，`CredentialRegistry::withAuthorization` 仍返回成功结果。正常路径通过，三个拒绝断言均失败；见 [baseline.json](native-business-return-evidence-2026-10-23/baseline.json)。没有执行旧账号恢复、跨代际交接或未知结果续办。

修复在完成后以同一准确来源执行只读核验，丢弃准入时缓存的能力范围，重新核对当前请求守卫、凭据、账号指纹、范围及期限。最后一次完整来源读取结束后再次检查期限。拒绝不返回业务结果，也不撤销已经提交的业务SQL；只读复核不产生新的pending。不能据最终异常盲目重放业务操作。

业务执行、SQL事务及完成复核共享原请求预算。提交前预算耗尽会回滚业务SQL并保留pending；提交后耗尽保留已提交SQL及current，但不返回结果。两种预算结果均有最终版本专项验证。`StateBoundary` 的宿主预算守卫需接受只读动作 `api.credentials.execute_check`，API请求守卫的 `authenticate` 可以重复调用，必须只读、不重复消费证明或外部请求额度。固定RolePolicy契约保持，本批不扩展自定义业务策略。

公开类型保持277，公开签名无变化。当前证据目录：[native-business-return-evidence-2026-10-23](native-business-return-evidence-2026-10-23/)。第一阶段九版功能／API命令44/45通过，保留一次PHP7.2时钟倒退；初轮静态分析的两项闭包状态类型诊断已修正。最终预算版本另以八版24/24及PHP8.5两项PASS覆盖预算结果，私有MySQL两端8/8、离线归档与全新消费者12/12通过，vendor运行时代码摘要一致，消费者已清理。最终静态分析及公开API核对通过，保留既有可选turbo扩展GLIBC警告。MySQL的PHP7.2使用真实单调时钟测试运行时，不抵销默认PHP7.2失败；预算分类在SQLite验证，不宣称MySQL强制超时分支也已执行。各阶段源码摘要及边界见[汇总](native-business-return-evidence-2026-10-23/summary.json)与[阶段说明](native-business-return-evidence-2026-10-23/phase-notes.md)。不是全项目稳定版验收。

当前goal保持active。MySQL原默认预算、PHP7.2时钟、其余非暂缓入口和最终候选核对仍开放；本批只修复withAuthorization，不能外推；后续独立authenticate／fromAuthorization的复现及修复见[专项记录](native-bearer-return-2026-10-23.md)。未提交、推送、部署或外部投递，暂缓功能未执行。
