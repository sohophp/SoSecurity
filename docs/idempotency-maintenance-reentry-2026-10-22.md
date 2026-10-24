# 幂等维护最终回调重入修复（2026-10-22）

确认的问题：初始化／维护的独立见证完成后，连接的 `maintenanceBusy` 已释放，但最终宿主管理权限回调尚未执行。同实例执行器的保护仍有效，另一执行器却能通过同一连接重入 `maintainFor()` 并推进状态，导致外层结果尚未返回就产生另一笔维护。

修复仅涉及 `StateAccountConnection::idempotencyMaintenance()`：最终管理回调、期限检查及真实会话权限复核期间保持连接级忙状态，以finally释放。与首次执行／查询的既有最终保护一致，没有放宽权限、修改SQL或引入续办。成功后独立调用仍可执行；公开签名和275类型清单保持。

测试新增 `final-reentry` 模式：在见证最终阶段仅安排回调，待见证退出后通过另一个执行器尝试维护；要求配置异常、已完成见证完全保持，并验证后续独立维护成功。首个测试版本在见证锁内inspect而被正确拒绝，其日志保留为测试构造错误；调整检查位置后确认修前未拦截重入的失败，见 `reproduced.log`。没有对任何pending进行恢复或续办。

证据目录：[idempotency-maintenance-reentry-evidence-2026-10-22](idempotency-maintenance-reentry-evidence-2026-10-22/)，包含修前失败、九版SQLite专项、两端私有禁TCP MySQL、原有最终撤权／到期场景、语法、API、静态分析与源码摘要。MySQL PHP7.2沿用已有单调时钟包装；不能据此关闭默认时钟历史超时。

本批不涉及归档行为，未重复上一批归档／消费者测试，也不把上一批归档的源码摘要算作当前修后摘要。非全项目验收；历史失败、其他范围的最终核对、暂缓能力及外部验收保持开放。未提交、推送、部署或接触生产数据库，保留既有环境、数据和未提交改动。

结果：九版SQLite 9/9、私有MySQL 2/2、两端最终拒绝／到期4/4、语法4/4通过；全量PHPStan及API检查退出0。见[result.json](idempotency-maintenance-reentry-evidence-2026-10-22/result.json)。
