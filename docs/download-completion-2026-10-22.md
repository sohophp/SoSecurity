# 下载最终返回与输出权限（2026-10-22）

## 复现与修复

核对 R3.6 的实际源码发现 `Transfer::read()` 最后一块在权限检查后还执行关闭回调，关闭期间失权、到期或版本改变仍返回内容；`send()` 输出前后只复核时限，最终输出回调撤销权限／改变资源版本后仍返回发送成功。关闭失败时 `complete` 还可能保持 true。

[修复前证据](download-completion-evidence-2026-10-22/before.json)保留七个失败场景及两个正常对照。修复仅修改 `src/Download/Transfer.php`：将当前元数据、权限、预算、单调业务时间检查提取为内部方法；关闭快照后、输出前后仍执行完整检查。成功关闭及最终授权检查后才标记 complete；读取失败明确保持未完成，关闭后的再次读取仍拒绝，不尝试重新打开或续传。

已有返回类型、275类公开候选及范围选择算法保持。授权／元数据回调调用次数增加，宿主必须保证只读且可重复。此修复不能撤回已经传给输出回调的字节；检测到后续失权时报告失败并停止，不宣称网络输出能够回滚，不自动重试未知输出。

## 本地验证

- PHP7.2—8.5九版定向矩阵107/108通过。新九场景、16MiB文件在8MiB进程中的流式检查和公开契约均通过。
- PHP7.2既有 `downloads.php` 在约0.166秒触发 `download.timeout`，发生于默认3秒预算的快照读取准备阶段，尚未进入本批修改的最终读取逻辑。首次日志保留 `php72-downloads.log`；未解释原因，不扩大预算、不重跑覆盖，也不以其余通过结果关闭它。
- 两端本机真实TLS、密码登录／SQLite账号权限、文件、Range／HEAD及一次性签名下载各733项通过。只使用控制器自建宿主、临时数据和私有CA，未做外部投递。
- 实际ZIP归档、离线全新Composer消费者及两端公开运行检查18/18通过；运行时文件摘要一致，消费者已清理。
- 两端PHP语法及shell语法5/5通过，全量PHP7.2目标PHPStan通过，现有可选turbo的GLIBC警告保留。
- 新测试已接入 `bin/check.sh`；本轮没有执行含暂缓链路的全项目门禁。没有改SQL代码，未重启无关MySQL专项。

命令、退出码、日志和准确摘要见 [result.json](download-completion-evidence-2026-10-22/result.json) 及同目录驱动脚本。初次PHP8.5既有下载回归280项通过是开发检查，最终矩阵独立记录，不以累计断言替代验收。

## 范围与兼容

Transfer rechecks current metadata, authorization and deadlines after closing its private snapshot and before/after each output callback. Failed reads never report completion. Host callbacks must be repeatable and free of business side effects. Bytes already accepted by a writer cannot be recalled, and ambiguous output is never retried.

这是独立产品修复，不是全项目九版验收或稳定版发行结论。默认时钟早期超时、其他未核对缺口、暂缓功能及外部验收继续开放；goal保持active，没有提交、推送、部署或清理用户数据。
