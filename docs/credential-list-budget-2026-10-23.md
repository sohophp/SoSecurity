# 凭据嵌套列表的分配前预算

检查默认签发路径时发现独立输入缺陷：CredentialEncoding::scopes及CredentialPolicy的methods列表在数量检查前先调用array_values，超大稀疏数组会复制全部元素。已有schema-option-budget只覆盖顶层未知配置键，没有覆盖这两类嵌套列表。

三个低内存隔离场景（直接权限列表、策略权限白名单、认证方式）均先复现PHP进程内存耗尽：已存在的输入占用约6MiB，额外1MiB空间内array_values试图分配约4MiB。见before-scopes.log、before-allowlist.log、before-methods.log。随后仅调整两处条件顺序，先判断数量上限，再校验连续键；异常类、原因码、32项权限／4项认证方式上限及合法值排序保持。

新增tests/credential-list-budget.php，覆盖低内存拒绝、最大合法列表、空列表、重复值和稀疏键；已接入bin/check.sh，但未运行包含暂缓项的完整脚本。原始复现后修正了测试异常捕获类型；生成验证脚本的一次定位错误及未启动日志也保留于setup-*，不记为产品验证。

已执行并通过：PHP7.2—8.5九版，每版3条新增测试（各13项断言）及既有credentials、credential-management-scope，共45条命令；每版既有两程序分别5400、1932项断言。实际发行归档、离线全新消费者安装、来源定位和PHP7.2／8.5消费者回归合计14步骤通过，vendor源码摘要与仓库一致，临时消费者已清理。PHPStan及277类／接口契约通过；保留既有可选turbo扩展GLIBC警告。

[汇总](credential-list-budget-evidence-2026-10-23/summary.json)、[输入摘要](credential-list-budget-evidence-2026-10-23/changed-inputs.json)、[完整输入](credential-list-budget-evidence-2026-10-23/inputs.json)、[归档结果](credential-list-budget-evidence-2026-10-23/archive.json)及各版本日志均已保存。未更改SQL逻辑，本批不声称真实MySQL后端或全项目验收。

兼容性：合法输入和公开签名不变；超大列表现在能按既定异常拒绝，避免先耗尽内存。此前855项普通组件快照早于本修复，应按其原摘要解释；本批只对影响范围复验，没有无依据重跑整批。

这项修复不解决默认受保护MySQL签发总预算失败。默认预算、PHP7.2时钟倒退及其他未关闭事项保持；暂缓能力未执行，goal保持active。没有提交、推送、部署或外部投递。
