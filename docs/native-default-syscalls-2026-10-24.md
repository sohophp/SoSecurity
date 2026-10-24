# 默认首次签发的系统调用诊断（2026-10-24）

本次仅对新的私有测试预设环境做一次首次签发诊断。保持实际`PDO`、`SystemClock`、3000ms凭据预算及当前SDK源码；新账号初始启用、首次TOTP登记后只尝试签发一次，失败后只读取状态，未续办未知回执、恢复账号或交接安全代际工作进程。没有调整时钟或预算。

使用现有strace5.18跟踪该PHP及其子进程，选择进程、网络、文件与同步系统调用；参数只记录原始指针，不解码SQL、密钥或请求内容。包装进程umask为0077，日志不进入发行归档。以计时记录的起止点筛选签发窗口，SDK源码／SQL及测试输入摘要保持，自己的测试进程和临时预设环境已结束并清理。

诊断结果仍失败：约3.004秒，`account.completion_unknown`、状态pending。PHP自身用户／系统CPU约0.260／0.664秒，已结束辅助进程约0.034／0.034秒。窗口内根PHP记录到sendto2088次、poll1516次、recvfrom1516次、nanosleep99次；这些调用的观察累计时间分别约0.333、0.427、0.183、0.125秒。不能据此把发送次数当成SQL条数，父子进程耗时也不能直接相加为墙钟耗时。

异常发生于`CredentialRegistry::auditCurrent`调用的`StateAccountPolicy::credentialPair`和完整`SqlStateSnapshot`捕获阶段，早于被包装的签发调用返回。当前证据提示优先检查重复SQL往返与完整图捕获，不支持先把主要成本归因于反复启动辅助进程。具体SQL种类、各捕获阶段的成本和安全修复方案尚待进一步取证；本批未删除复核、缓存授权事实或改动该路径。

strace会影响调度与耗时；这不是未跟踪的默认性能结果，更不是稳定版通过。以前未跟踪的约3.009秒失败仍保留，旧时钟及原生集成失败也未由本次关闭。没有重复运行未跟踪失败实验来寻求绿色结果。

证据：[汇总](native-default-syscalls-evidence-2026-10-24/summary.json)、[计时](native-default-syscalls-evidence-2026-10-24/default-85-timing.json)、[退出与清理](native-default-syscalls-evidence-2026-10-24/default-85-result.json)、[输入摘要](native-default-syscalls-evidence-2026-10-24/default-85-inputs.json)、[原异常](native-default-syscalls-evidence-2026-10-24/default-85-run.log)。goal保持active，未提交、推送或部署。
