# 当前因子权限时钟异常脱敏

追踪默认签发中的当前权限读取时，发现并独立复现 `FactorAuthority` 的时钟异常泄露：操作前直接抛出自定义时钟的原异常；操作完成后的时钟异常被保留为 `mfa.completion_unknown` 的 previous，异常正文带出私有标记。修前失败分别保存在 `before.log` 和 `before-return.log`。

本批实际修改 `src/Mfa/FactorAuthority.php` 两处边界：时钟调用失败转换为固定的 `mfa.clock` 依赖异常；返回阶段仍以 `mfa.completion_unknown` 拒绝结果，但不附带原异常链。时间有效性、期限、前后授权、效果处理及锁释放逻辑保持，没有撤销已经发生的效果，也没有重放失败操作。

## 验证与边界

- PHP7.2—8.5九版，每版新增42项断言：四个时钟故障位置、效果发生前／后的结果拒绝、上下文释放、返回时拒权／回调异常，以及真实文件存储的公开 `TotpFactors::status()` 前置／返回故障。另每版原有MFA205项断言通过，共18项程序、2223项断言。
- 公开入口预设环境只新建私有目录、当前代际围栏和初始因子。失败后的另一次只读status用于检查上下文释放，不恢复未知操作、不重放原操作；没有调用交接、迁移、账号恢复或未知回执续办接口。
- 静态分析、API277、shell语法与差异检查通过。新测试已接入 `bin/check.sh`，但没有运行包含暂缓链路的整个脚本。
- 离线ZIP归档、安装及PHP7.2／8.5消费者共8个步骤通过，安装的FactorAuthority摘要与源码一致；消费者运行新测试及原有MFA测试。
- 初始公开入口测试误用了MemoryStore，后改用FileStore但缺少显式初始因子；两次预设环境失败分别记录，最终通过新建初始因子修正，没有放宽产品保护。第二次失败留下的本次临时目录已精确清理，未清理其他资源。

这是当前权限时钟与异常隐私专项，不是完整MFA生命周期或全项目验收。本批没有修改SQL或复跑默认MySQL签发；原有默认预算失败和PHP7.2墙钟问题仍开放。既有专项不当作当前完整候选通过，goal保持active。

兼容变化：公开签名、API277和存储格式不变。操作前的自定义时钟异常现在统一为 `mfa.clock`；操作后的 `mfa.completion_unknown` 不再暴露previous异常。宿主应使用固定原因码处理失败，不能据此视为效果已回滚。

证据：[本地目录](factor-authority-clock-evidence-2026-10-23/)，包含 `runtime.patch`、`verification.json`、`inputs.json`、`test-inputs.json`、`archive-final.json`、`closeout.json` 与预设环境失败记录。
