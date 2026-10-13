# 完整计划执行记录

目标：完成docs/next-steps.md和产品需求中的进一步计划，不把已完成的基础版本等同于完整目标。日期2026-10-13。该记录跟随代码和实际测试更新；GitHub/Packagist发布仍需单独授权，独立审查及真实旧站验收不能以本地测试代替。

| 范围 | 当前权威证据 | 剩余工作 |
| --- | --- | --- |
| 原基础候选及演示 | src、demo/public、原验证记录 | 保持回归和演示随新功能更新 |
| 不可变配置与错误分类 | Policy/Change私有字段及getter、Exception类、Config验证、hardening.php/configuration.php（当前39项） | 随后续模块补齐对应错误代码和文档 |
| 文件锁/清理/编码 | FileStore有界非阻塞等待、pruneBatch、JSON原语与复杂度限制；真实小型tmpfs磁盘耗尽测试 | 更多驱动/平台的故障矩阵、容量运维说明 |
| Redis CAS/预算 | 原子Lua CAS、socket及重试总预算、冲突/暂停/OOM测试；phpredis4.3和当前PHP8.5客户端测试 | 已加入run_id/epoch检查、CLI显式初始化、旧RDB受控恢复拒绝测试；仍需更多驱动/服务端版本矩阵 |
| 密码重置业务边界 | examples/password-reset.php、SQLite真实SQL版本比较/宿主事务/写库失败/后置清理失败测试 | MySQL24进程/4令牌业务版本比较已通过；仍需生产宿主流程试点 |
| 配置工厂/Session兼容/诊断 | Security::fromArray、Config、Inspector、CLI、原生登录示例、Cookie path/domain/lifetime保留测试 | CLI与当前配置演示Chromium已通过，六个本地PHP版本检查已补齐；仍需全部目标PHP版本、扩展缺失场景与更多文档示例验收 |
| MySQL与输入验证 | MySqlStore/InnoDB/有界清理、配置与只读诊断；41项驱动检查及24进程竞争；Validator52项检查，实际演示MySQL与验证页 | 更多数据库版本/客户端矩阵、URL/IP格式已补齐；更多真实宿主试点；稳定API尚未冻结 |
| 上传 | Policy/Validator/Saver、类型/预算/快照与图片重新编码、扫描/文件管理器接口；83/84项检查、20项multipart、32项隔离演示、24进程保存及真实部分写/ENOSPC；实际入口和Chromium | 真实扫描服务、更多图像库/系统版本、Windows ACL和生产宿主流程；扫描/CDR不冒充已完成 |
| HTTP/SSRF/API | URI/Redirects/Cors/Permissions、精确目标/公开地址/DoH与pin/预算客户端；Bearer摘要存储及轮换撤销、RFC 9421有界HMAC/原子Nonce，Python独立向量和真实HTTP，网页API演示；验收细节见verification.md | 更多传输/网络/生产宿主及独立复核；实际认证、密钥生命周期与恢复 |
| 无状态CSRF与路由策略 | SignedTokens/HmacKeys/RequestPolicy、PHP数组工厂及只读诊断；118项核心、独立Python向量、无Session真实HTTP/临时TLS、可操作Cookie演示 | 生产登录绑定/代理/密钥轮换传播；逐令牌撤销/单次操作继续有状态方案；缺失平台与独立复核 |
| 富文本HTML清理 | HTML Purifier 4.19.1可选适配、固定基础允许列表、DOM/字节/树/属性/输出预算及故障拒绝；正常/攻击/拒绝/故障演示及实际浏览器结构变异检查 | 复杂编辑器/图片/样式及自定义策略另行复核；缺失平台/生产渲染和独立审计 |
| 发布验收 | 本地Git提交、Composer安装/压缩包测试、部分PHP及浏览器证据 | 全版本实际运行及Composer安装；Linux/Windows证据；真实旧站和独立复核；授权后GitHub CI及公开包安装 |

代码测试不能证明未执行的环境；本机PHP7.2无POSIX扩展，部分写故障测试会明确跳过，但通过独立小型tmpfs完成真实ENOSPC测试。PHP8.5有POSIX扩展，实际部分写故障已执行。CI要求测试扩展完整，不能用跳过取得相应验收。

目前目标保持进行中。Redis重启恢复、MySQL和基础输入验证已推进并交付演示；上传已交付私有演示；HTTP策略、受限请求和API Key/HMAC/Nonce已交付候选实现与演示；无状态CSRF已提供HMAC绑定、双重提交/精确路由策略、HTTP/HTTPS及浏览器证据；成熟HTML清理基础适配已交付；下一步继续跨版本/真实宿主/独立复核验收；不因单个阶段可用而标记完整计划完成。
