# 当前代际账号及因子通知维护复验

本批没有修改运行时代码，补齐近期SessionRegistry变化后的原生组合证据。所有src文件与[普通组件候选](ordinary-candidate-2026-10-23.md)摘要一致；测试输入在运行前后保持一致。

已执行并通过：PHP7.2—8.5九版SQLite，共27条命令。每版覆盖正常注册／地址变更维护、错误账号映射拒绝、因子通知维护；涉及权限拒绝、批量上限、重入、角色变化、最终失权后保持pending及账号／队列不被无关修改。每版三个程序分别77、77、102项断言。只创建全新账号及初始因子，不续办pending。

真实私有MySQL：PHP8.5普通维护和映射2条通过；PHP7.2、8.5的因子通知完成校验及原生维护各2条通过（每端分别95、102项断言）。PHP7.2普通维护1条失败，日志明确报告持续时间时钟倒退，位置为CompositeStateSnapshot／LocalStateWitness读取；后续PHP7.2映射未执行。失败原样保留，未重跑，也没有替换默认时钟或调整预算。

[汇总](native-maintenance-current-evidence-2026-10-23/summary.json)、[SQLite逐条结果](native-maintenance-current-evidence-2026-10-23/results.json)、[源码及范围](native-maintenance-current-evidence-2026-10-23/scope.json)、[MySQL失败](native-maintenance-current-evidence-2026-10-23/mysql-maintenance.log)、[MySQL8.5](native-maintenance-current-evidence-2026-10-23/mysql-maintenance85.log)、[因子通知](native-maintenance-current-evidence-2026-10-23/mysql-notices.log)保留于本地。自有进程、数据库和临时文件已由测试运行框架清理。

历史业务HTTP503的初始化链为state_http.py → http-setup.php → entryPromote() → rotateWorkers()，命中暂缓交接。没有运行、裁剪或替换其预设环境，旧失败保持未关闭；它不阻断本批独立维护验证。

本批只覆盖上述维护子项，不证明R2.7整个注册／双地址／恢复／通知工作流完成，不证明所有用途容量、全部后端或完整候选通过。公开API及兼容性无新增变化，无提交／推送／部署／外部投递。默认受保护MySQL签发预算、PHP7.2时钟与其他缺口仍开放，goal保持active。
