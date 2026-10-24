# SQL事务元数据锁等待（2026-10-24）

本批修复 `SqlTransaction` 的 MySQL 元数据锁等待缺口，覆盖 `run`、`enlist`、`inContext` 和 `readIn`。进入业务前新读 `@@SESSION.lock_wait_timeout`，完整验证一行一列有效整数并关闭游标，再按原配置与剩余预算的较小值收紧；退出时恢复原值。宿主事务、只读借用、权限校验、失败连接隔离和 SQLite 原路径保持。固定查询语句池仍只复用已关闭的语句，不保存配置值。

私有服务器原复现：1000ms预算，行锁已为1秒、元数据锁仍4秒，实际等待4.011秒并失败。修复后同一复现约1.015秒返回失败，未提交。MySQL该参数最小1秒且逐次加锁计时，不能视为严格整条语句截止时间；参考[官方说明](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_lock_wait_timeout)。

专项源码快照下，PHP7.2、7.3、7.4、8.0—8.5：新增MySQL648场景、相关作用域预算180场景、SQLite396场景均已执行并通过。覆盖真实元数据锁、宿主事务保持、借用后外层配置恢复、回调拒绝、会话配置改变、畸形数据、游标关闭失败及SET前后失败。九版公开契约检查通过，实际278类型，未修改候选契约。PHPStan无错误，保留可选扩展GLIBC警告。

ZIP归档、离线全新非符号链接消费者安装、两端来源校验和专项共8步骤通过，367个源码／SQL文件摘要一致，临时资源已清理。该消费者包含两端各72项MySQL场景和20项SQLite预算场景。

原失败均保留：预修复等待断言；API启动器误加8MiB导致的九版反射内存不足（随后按项目原命令检查）；补充启动器在PHP7.2新增24场景通过后拒绝下一条命令（其余八版仅补未执行场景）。未删除断言、提高产品预算或改动时钟。证据：[结果](sql-metadata-wait-evidence-2026-10-24/delivery.json)、[输入](sql-metadata-wait-evidence-2026-10-24/inputs.json)、[本批源码差异](sql-metadata-wait-evidence-2026-10-24/scope.diff)、[消费者](sql-metadata-wait-evidence-2026-10-24/consumer/consumer.json)。

上述结果绑定本批快照；后续 `MySqlStore` 的独立修改另行记录。默认原生凭据签发预算、历史时钟／原生集成失败、最终非暂缓候选核对仍开放。Webhook独立SQL实现尚未由本批关闭。没有执行暂缓链路或外部验收，不是全项目验收，goal保持active；未提交、推送或部署。
