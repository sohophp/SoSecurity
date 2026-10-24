# SDK真实系统时钟下的默认首次签发

2026-10-23。本轮没有修改产品源码、预算或既有测试。为区分可变测试Clock带来的逐次结构校验成本，复制普通初始服务图到自有临时目录，将注入时钟替换为真实SDK `SystemClock`，所有读时使用now()；TOTP实际等待下一计数窗口，不回拨或加速时间。只有第一次真实签发执行，未知状态不续办。

PHP8.5／自建禁TCP MySQL仍失败：调用约3.2718秒，预算保持3000ms，最终account.completion_unknown，见证pending。栈在CredentialRegistry::issued()第213行调用actor()，其第103行tick报告到期。这是凭据状态写入之后的返回阶段；不能把它归为单纯的测试时钟开销，也不能删除末次当前会话／账号复核来获得绿色结果。

此结果将下一步限定到签发后返回路径的重复认证读取及完整语义重构。现有捕获式读取仍不能直接替代普通SessionRegistry.verify：还需保留因子目录和物理因子的当前权限回调、会话seen触达与idle／absolute收紧、失效清理，以及每次副作用后的来源复核。本轮没有启用会漏掉这些行为的快返。

新增独立测试入口 `tests/native_system_clock_issue.py`，要求显式给出运行时、版本标记及新证据目录，拒绝覆盖已有记录，限制为控制器自建MySQL及首次签发，包含实际凭据／审计行／current见证的成功断言。它额外核对真实SystemClock和原生PDO；只做语法检查，未再次执行等价的失败实验。首次诊断驱动的实际运行终态、源码摘要和临时资源清理均已保存。

[测量](system-clock-issue-evidence-2026-10-23/default-85-timing.json)、[失败栈](system-clock-issue-evidence-2026-10-23/default-85-run.log)、[运行终态](system-clock-issue-evidence-2026-10-23/default-85-result.json)、[限定分析](system-clock-issue-evidence-2026-10-23/analysis.json)。本轮只有诊断和新增回归入口，没有修复超时，也不关闭稳定版或当前goal。旧失败、暂缓链路及外部验收保持未完成；未提交、推送、部署或外部投递。
