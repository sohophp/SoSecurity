# 默认签发去除调试扩展的隔离对照

当前PHP8.5.9加载Xdebug，但ini_get及xdebug_info显示没有启用模式。为验证移除扩展能否解决已知默认签发失败，本批仅创建临时INI扫描目录：链接原有其他INI，排除15-xdebug.ini和99-xdebug-switch.ini。先核对这两个文件只包含Xdebug设置／扩展指令，再检查临时运行时确实未加载Xdebug且Sodium、pdo_mysql存在。没有改动系统INI、PHP二进制或仓库运行时代码。

执行一次私有MySQL的--native-audit-defaults，使用全新账号及初始因子，原3000毫秒凭据预算、全部授权检查和默认策略保持。退出1，首个实际签发在CredentialRegistry::issueInternal第二次actor的会话复核后tick（当前第103行）触发明确Security operation exceeded its time budget，最终由LocalStateWitness保持completion_unknown。后续列表／轮换等未执行。运行器总耗时约32.76秒含数据库启动、预设环境和清理，不是签发耗时。

结论限定为：移除Xdebug不能解决这次默认预算失败；本次有明确的耗时超限栈，不属于时钟倒退。没有计算调试扩展的精确性能差异，没有以此次结果解释其他历史失败，也没有触碰旧pending续办。本批不再重试该场景。

[环境及终态](native-clean-runtime-evidence-2026-10-23/result.json)、[完整失败日志](native-clean-runtime-evidence-2026-10-23/defaults.log)、[准确源码摘要](native-clean-runtime-evidence-2026-10-23/inputs.json)、[可复核驱动](native-clean-runtime-evidence-2026-10-23/run.py)保留。初次预检误以为只有一份Xdebug INI而停止，未启动产品测试；setup-failure.log保留。修正预检后仅执行上述一次产品场景，输入摘要未改变，临时配置与自有数据库已清理。

本轮没有产品代码修复、公开接口或兼容变化，不代表任何完整候选通过。默认受保护MySQL签发仍是未解决的本地产品问题；PHP7.2时钟倒退、其余未齐门禁以及暂缓／外部项目分别保留，goal保持active。无提交、推送、部署或生产访问。
