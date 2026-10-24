# 工作进程栅栏的完整物理来源

日期：2026-10-22。属于完整计划 F01 的 G1 来源覆盖与 G4 恢复前置条件，不增加需求或预算。完整 R1—R6、31 项和 80 个有效工作小时上限保持。

## 实际问题和修复

修前在 PHP8.5／SQLite 上执行真实工作进程交接，保存有效签名的 `open` 文件，再通过独立见证内的 `drain()` 永久关闭。关闭改变了实际文件，但原完整来源只观察账号 SQL／JSON 状态，没有包含 `.fence`。恢复原始签名字节后，见证仍为 current，工作回调执行了一次；首次失败保存在 [preflight-before.log](state-fence-source-evidence-2026-10-22/preflight-before.log)。

新增 `FenceStateSnapshot`，把完整权威目录的稳定身份、所有合法文件名及原始内容纳入来源。来源只读、不创建文件、不请求额外栅栏锁；在持有 SH／关闭态 EX 的回调内可以观察。权限、链接、大小、条目、数量、目录替换或连续扫描变化均拒绝。记录格式校验不是具体上下文的签名认证，后者仍由 `LocalEpochFence` 负责。

`LocalEpochFence` 绑定状态边界时必须由同一完整来源覆盖物理目录，原生认证工厂再次核对。缺失时构造拒绝，不创建权威文件、不初始化见证；未绑定的普通栅栏接口保持原行为。所有启用的旧／当前／未来权威目录应在首次根建立前声明，避免把切换后的文件排除在来源之外。

旧的有效签名 `open` 字节现在使来源与 current 摘要不同，在原进程和全新 PHP 进程中均以 `account.witness_stale` 拒绝，工作回调不执行，根与认证账本保持原字节。

## 固定验证与交付范围

固定八条命令及准确输入见 [execution.json](state-fence-source-evidence-2026-10-22/execution.json)，执行程序保存在 [runner.py.txt](state-fence-source-evidence-2026-10-22/runner.py.txt)。八条全部已执行并通过，前后输入摘要保持；864 个 PHP 文件语法通过。四个测试根、十二个强杀测试根及两个私有 MySQL 均已清理；准确资源与终态核对见 [delivery-check.json](state-fence-source-evidence-2026-10-22/delivery-check.json)。

前四条分别是 PHP7.2／8.5 × SQLite／私有无 TCP MySQL。每条执行八组受保护检查：回滚复现、完整来源、工作进程交接、认证工厂、HMAC 工厂、重置工厂、凭据安装与范围证明退役（新进程包含在完整来源组内）；另执行三个真实 HMAC 强杀点和一个等待后拒绝的竞争进程。SQLite 组合额外执行 8MiB 的来源损坏与锁内观察检查。其余四条为两版 API 契约、PHPStan 与 PHP7.2 语法检查。受保护组内存上限 16MiB。

PHP7.2.34 使用既有私有原生单调时钟及 sodium 运行环境，不是系统原版 PHP7.2；PHP8.5.9 使用本机解释器。PHPStan 可选加速扩展存在既有 GLIBC 警告，分析本身的退出码和结果单列判断。本组不宣称掉电、网络文件系统或多节点持久性验收。

相对上一组，产品源码只改六个文件；API 新增一个公开来源类及四个既有类方法。移除这些新增项后，以 PHP 原编码重建的契约摘要与上一组完全相同，证明原公开签名／默认值保持，见 [api-delta.json](state-fence-source-evidence-2026-10-22/api-delta.json) 和 [library-delta.json](state-fence-source-evidence-2026-10-22/library-delta.json)。

## 仍未完成与停止条件

本项在固定检查通过并完成资源清理后停止。加入来源会改变来源指纹，不得通过删除根、重新 initialize、采用当前数据库或绕过失败来迁移已部署见证。

最终恢复仍须完成跨安全代际的工作进程交接、完整账号集合核对、旧权限效果处置、明确的新账号启用及耐久审计后提交 current。当前凭据安装仍保持 disabled／quarantined，不开放登录。其他认证写入者、完整 G1—G6、当前九版本最终门禁、外部环境及独立验收仍开放。旧业务 HTTP 的 PHP8.5／MySQL 503 根因尚未关闭，本组没有重试该诊断。
