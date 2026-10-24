# 受保护登录返回检查（2026-10-23）

## 缺陷与修复

在自有新账号、初始因子登记和当前登录状态中复现：`AuthenticationFlow::password()` 和 `secondFactor()` 在见证提交后的请求撤权、结果过期或时钟故障下仍返回挑战／登录凭据。六个反例失败，两个正常对照通过，见 [before.json](native-auth-return-evidence-2026-10-23/before.json)。

修复对原生 `password`、`secondFactor`、`cancel` 增加只读返回准入，重复检查当前请求权限；挑战和新会话不得在返回时已过期。公共请求检查、状态操作与最终检查共享30秒时限；禁止回调重入。请求及时间源异常使用固定错误码且不附带原始异常。无公开签名或类型增加。

只读检查不重做登录、不退还已消耗的第二因素证明、不回滚已完成提交。宿主需允许 `authentication.password_check`、`authentication.second_factor_check`、`authentication.cancel_check`；当前请求回调必须可重复、无业务副作用。普通模式没有新增原生状态边界，但时间源异常也会脱敏。

## 实际结果

- PHP8.5首次定向回归8/8通过，含六个原反例。
- PHP7.2—8.5矩阵48项：47通过、1失败。其中包含九版普通认证、API契约及20秒提交阶段加11秒返回检查的共享预算测试。唯一失败为默认PHP7.2取消登录撤权用例的明确时长时钟倒退，原始失败保留，不重跑覆盖。
- 私有无TCP MySQL：PHP7.2显式单调时钟包装器及PHP8.5各4项，共8/8通过。该包装器不是默认PHP7.2运行环境验收。
- 离线核心归档、新消费者安装、实际vendor来源及两端原生用例共12/12通过；安装的认证源码摘要匹配，消费者临时目录已清理。
- PHPStan通过；原有可选turbo扩展GLIBC告警保留。公开API契约277类／接口通过，未修改契约候选来获得通过。

命令、逐项退出码、日志、源码补丁和摘要见 [证据汇总](native-auth-return-evidence-2026-10-23/summary.json)、[矩阵](native-auth-return-evidence-2026-10-23/verification.json)、[归档](native-auth-return-evidence-2026-10-23/archive.json)、[本批补丁](native-auth-return-evidence-2026-10-23/batch.patch)。

本批没有执行最终账号恢复启用、跨代际交接、未知回执续办或完整F01。默认预算失败、PHP7.2默认时长时钟、剩余非暂缓候选核对及外部验收未关闭；goal保持active。随后持久登录修改另列专项，不能将本批结果自动升级为全项目验收。
