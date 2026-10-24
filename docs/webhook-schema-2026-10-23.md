# Webhook 表结构、元数据预算与权限可见性修复（2026-10-23）

本批修复 InboxSchema／ProcessingSchema，保留此前全部未提交改动。只验证独立接收、首次领取及已知完成结果；不涉及未知回执续办、跨安全代际交接、最终账号恢复或完整 F01。goal 保持 active，本记录不是完整稳定版验收。

## 已确认问题与修复

原实现允许私有表触发器，实际接收提交了额外副作用；允许部分索引、错误唯一性及无界列元数据读取。新增固定表名白名单、列／索引元数据的行数和字段字节上限、索引所属表及完整覆盖校验，并拒绝主库／临时库触发器和 SQLite 元数据模块遮蔽。MySQL 必须使用完整 BTREE 索引，不允许前缀索引。

MySQL 数据账号没有 TRIGGER 可见权限时，information_schema 返回空集不能证明没有触发器。原行为已复现为 visible=0、receipt=1、effect=1。初版独立权限证明与触发器查询之间仍存在表级撤权窗口，已复现 RACE_ACCEPT effects=1。最终将权限证明与触发器存在状态放入同一 SELECT，库级／表级撤权回归均拒绝且没有副作用。此结论限于已复现窗口，不构成对任意并发管理员 DDL 的原子性保证。

## 兼容变化

规范 DDL、数据格式、公开 API（277 类／接口）和默认时间预算保持。新增结构与元数据预算限制会拒绝此前被误接受的结构。

MySQL 当前账号须有该表或该库的直接 TRIGGER 权限，或在 partial_revokes=OFF 时具有可证明的全局直接 TRIGGER 权限。仅角色授予、无法解析的账号标识、启用 partial_revokes 且仅有全局证明时均默认拒绝。SDK 不授予权限、不迁移表；测试只操作私有服务器的合成账号。实测 MySQL 8.0.46，其他 MySQL／MariaDB 版本未验证。

## 测试证据及边界

证据目录：[webhook-schema-evidence-2026-10-23](webhook-schema-evidence-2026-10-23/)。最终源码摘要由 joint-inputs.json、sqlite-joint-inputs.json 与 archive-joint.json 绑定。

- 最终代码：PHP7.2、7.3、7.4、8.0—8.5，SQLite 36 项程序／3591 项断言通过；MySQL 权限可见性及规范表结构 18 项程序／450 项断言通过。对应 sqlite-joint-results.json、joint-mysql.json 及 joint-mysql-*.log。
- 最终代码：归档、离线全新消费者安装、两端 PHP 源码来源与 SQLite 测试共 8 步通过；两份运行时代码在消费者中的 SHA256 与源码相同，临时消费者已清理。见 archive-joint.json。
- 最终代码：PHPStan 通过，API 清单 277 通过，bin/check.sh 语法检查通过。PHPStan 可选 turbo 扩展因系统 GLIBC 不匹配加载失败，普通分析仍完成；日志原样保留。
- 合并权限查询之前：PHP7.3—8.5 MySQL 完整专项 40 项程序／3048 项断言通过（mysql-complete-results.json）；这是历史阶段证据，不替代最终快照完整矩阵。
- 已执行但失败：此前 PHP7.2 完整 MySQL 结构专项发生真实墙钟倒退（mysql-matrix.log），该轮后续程序未执行。最终定向 PHP7.2 通过不证明宿主时钟已修复，也不覆盖这项完整矩阵缺口。
- 初轮 ENUM 测试数据、旧版 PHP fetchAll 签名及控制器认证／默认库问题分别保留在 mysql-first.log、早期矩阵和 mysql-final.log／mysql-verified.log；修复测试运行框架后重新取得相应证据，没有删除拒绝用例或放宽产品保护。

PHP8.5 原生工厂正常路径最终 SQLite／MySQL 各129项断言通过，共2项程序／258项断言，见 joint-native.json 与 joint-native-*.log；仅使用新建测试数据、首次领取和已知完成结果。

## 未关闭事项

默认 MySQL 凭据签发 3000ms 预算问题仍开放，未提高预算或续办 completion_unknown。PHP7.2 宿主墙钟不稳定仍开放。真实提供器、外部投递、其他数据库版本、暂缓恢复链及全项目验收未执行。本批没有提交、推送或部署。
