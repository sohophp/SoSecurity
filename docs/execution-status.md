# 完整计划执行记录

目标：完成docs/next-steps.md和产品需求中的进一步计划，不把已完成的基础版本等同于完整目标。日期2026-10-13。该记录跟随代码和实际测试更新；GitHub/Packagist发布仍需单独授权，独立审查及真实旧站验收不能以本地测试代替。

| 范围 | 当前权威证据 | 剩余工作 |
| --- | --- | --- |
| 原基础候选及演示 | src、demo/public、原验证记录 | 保持回归和演示随新功能更新 |
| 不可变配置与错误分类 | Policy/Change私有字段及getter、Exception类、Config验证、hardening.php/configuration.php | 随后续模块补齐对应错误代码和文档 |
| 文件锁/清理/编码 | FileStore有界非阻塞等待、pruneBatch、JSON原语与复杂度限制；真实小型tmpfs磁盘耗尽测试 | 更多驱动/平台的故障矩阵、容量运维说明 |
| Redis CAS/预算 | 原子Lua CAS、socket及重试总预算、冲突/暂停/OOM测试；phpredis4.3和当前PHP8.5客户端测试 | 重启/恢复时的状态丢失检测与明确初始化流程；受控重启验收；驱动/服务端版本矩阵 |
| 密码重置业务边界 | examples/password-reset.php、SQLite真实SQL版本比较/宿主事务/写库失败/后置清理失败测试 | 真实MySQL并发重置；生产宿主流程试点 |
| 配置工厂/Session兼容/诊断 | Security::fromArray、Config、Inspector、CLI、原生登录示例、Cookie path/domain/lifetime保留测试 | CLI与当前配置演示Chromium已通过；仍需全部目标PHP版本、扩展缺失场景与更多文档示例验收 |
| MySQL与输入验证 | 尚未实现 | 独立数据库原子存储、事务所有权、规则/Unicode/嵌套字段、配置和演示 |
| 上传 | 尚未实现 | 校验/保存、资源预算、私有目录/文件管理器适配、扫描接口、攻击与并发测试、演示 |
| HTTP/SSRF/API | 基础响应头与代理已有；补齐部分尚未实现 | 跳转、CORS/Permissions、受限请求与DNS/逐跳处理、Key/签名/Nonce、受控演示及独立测试向量 |
| 发布验收 | 本地Git提交、Composer安装/压缩包测试、部分PHP及浏览器证据 | 全版本实际运行及Composer安装；Linux/Windows证据；真实旧站和独立复核；授权后GitHub CI及公开包安装 |

代码测试不能证明未执行的环境；本机PHP7.2无POSIX扩展，部分写故障测试会明确跳过，但通过独立小型tmpfs完成真实ENOSPC测试。PHP8.5有POSIX扩展，实际部分写故障已执行。CI要求测试扩展完整，不能用跳过取得相应验收。

目前目标保持进行中。下一步继续Redis重启恢复边界、MySQL及基础输入验证，再推进上传和HTTP/API；不因单个阶段可用而标记完整计划完成。
