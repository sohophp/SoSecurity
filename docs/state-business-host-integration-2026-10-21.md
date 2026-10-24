# 格式 3 业务宿主、浏览器与真实中断

2026-10-21 周期，余项检查继续到 2026-10-22；继续既定 P1／G5、R4.5，31 项／80 个有效工作小时上限不变。本组把上一组的业务 PDO 入口接入原生宿主，并补格式 3、真实进程死亡和并发等待后的拒绝；不以此关闭完整 F01／R1—R6。

## 产品接入

`examples/managed-authentication.php` 保留原 Security 对象及严格的 security／state_policy 二字段引导包，可再增加第三字段 `business_connection`，其值必须是当前完整 SQL 来源使用的准确 PDO。源中须在可信初始化前声明 `StateDocuments::definition()` 的完整业务表，所有相关写入者共用见证与围栏；请求不创建表、不初始化或采用权威状态。

新增固定 `POST ?api=document`，表单严格限制为 `action=rename`、`id`、`version`、`title`，要求 `Accept: application/json`，仅使用 Authorization Bearer 和 `records:write`。服务器加载实际文档、核对当前 editor／所有者／title 字段权限，再按版本比较更新。该路由不启动 PHP 会话，Cookie 不代替 Bearer，不签发 CSRF 或 Cookie；客户端显式提交 Origin 时必须匹配配置的固定来源。普通会话管理路由继续使用真实 CSRF 与 Cookie，不与业务入口混用。

方法错误返回 405，形状／整数错误 400，不接受的响应格式 406，Bearer 准入失败 401，对象／字段／版本拒绝统一 403；未知效果或覆盖配置错误返回 503。原生 SDK 的异常语义仍保留：进入效果阶段后的 SQL 回滚不等于认证文件已回滚，未知提交不自动重放。

## 准确测试图

私有 CLI 设置脚本在首次见证初始化前创建固定业务表并置入 editor 账号；测试专用格式 3 使用固定代际标识，运行时通过全新 PDO／服务图重建相同来源。设置／控制脚本保持 CLI 限制，实际 Web 请求仍验证 404 且状态不变。产品示例不包含这些测试维护路由。

业务 HTTP 检查覆盖准确 SDK 工厂、实际 PDO／Intent、文档版本更新、所有者／范围／版本拒绝、Cookie 不能代替 Bearer、额外 owner／CSRF 字段拒绝、Origin／Accept／方法限制、响应无 Set-Cookie／CSRF，以及业务请求前后 PHP 会话文件不变。SQLite 使用原生 backup；MySQL 的类型标记／Base64 原始字节备份增加固定业务表。更新文档、撤销凭证和角色变更之后，联合恢复旧 SQL／认证文件／PHP 会话与 Cookie，旧 Bearer 的文档写入必须在效果前返回 503，完整来源和新见证不变。

Chromium 通过真实页面获取凭证，以 `credentials: omit` 执行业务写入，另查 Cookie-only 与旧版本拒绝、格式 3 实际业务回执及 Cookie 不变；既有表单、恢复因子、CSRF、跨 Origin 带 Cookie 请求和注销同时复验。TLS 使用受控本地桥接和临时 CA，浏览器仅对该证书忽略校验，不宣称生产证书或源站隔离已通过。

## 真实中断与并发

三个固定 SIGKILL 点：durable pending 后尚未调用业务；实际 UPDATE 后 SQL 尚未 COMMIT；实际 COMMIT 完成而 current 尚未写入。生产者由控制器真实 SIGKILL，读取者重新启动并建立新 PDO／服务图；核对格式 3 原始授权意图、来源摘要、revision、实际文档行和调用计数。前两点观察原版本，提交后观察新版本。所有情形保持 pending，原业务回调不再运行。

第二点增加独立并发进程：在原进程持有见证锁时发起同一业务操作，准备标记后仍保持运行等待；原进程被杀后它接手锁，因 pending 拒绝，认证守卫和业务回调计数均为零。随后再由第三个新进程复查。这证明本测试图的并发等待与拒绝，不代表全部历史写入者已完成停机交接，也不代表真实掉电耐久性。

## 有限验收与停止条件

固定 12 条命令见 [execution.json](state-business-host-evidence-2026-10-21/execution.json)：两端各执行 SQLite TLS／Chromium＋三个强杀点、私有 MySQL 同组、原二字段保护宿主 HTTP、格式 2 业务及受影响 API 检查、公开契约；最后执行库 src 静态分析和变更脚本／宿主语法检查。源码、示例、测试及门禁在执行前冻结，成功后只核对证据与清理，不启动九版整轮。

PHP7.2 为既有私有 sodium／posix／原生单调时钟解释器，不声明系统原版完整门禁通过。浏览器使用已存在的 `/var/www/node/sodialog/node_modules/playwright`；最初预检因未显式指定该路径而失败，未安装新依赖。该失败在执行 JSON 中如实保留摘要，原始工具输出留在会话，不冒充完整落盘日志。

**初轮已执行但失败：** 前六条命令退出 0；第七条 PHP8.5／MySQL 的外部文档所有者拒绝预期 403，实际 503，后五条因停止规则未执行。原始日志与冻结清单保留在 execution.json／check-07.log；该次失败后的完整来源对比未取得，不能推断它只是时钟／环境拒绝，也不能宣称无业务效果。

**单次定向诊断：** 测试路由增加只在私有审计域记录的异常类型／reason 链，公共响应继续脱敏。一次 PHP8.5／MySQL HTTP／TLS／Chromium 复验退出 0、489 项通过，原 503 未复现；根因未明，不登记为已修复。记录见 [diagnostic-execution.json](state-business-host-evidence-2026-10-21/diagnostic-execution.json)。测试程序同时补上非预期状态时的前后来源比较与权威摘要输出，避免再次在状态码断言前丢失这些证据。

**余项：** 只执行此前尚未执行的六项：PHP8.5／MySQL 三个强杀点、旧二字段宿主 HTTP、格式 2 业务与受影响 API、公开契约、静态分析及语法检查，见 [completion-execution.json](state-business-host-evidence-2026-10-21/completion-execution.json)。产品示例、库 src 与公开契约保持初轮字节；测试观察代码有明确差异，不能把分组记录说成同一测试源码下十二条整轮通过。余下六项全部退出 0，执行前后内容一致；合并核对见[交付证据核对](state-business-host-evidence-2026-10-21/delivery-check.json)，该核对明确 `group_accepted=false`，不是通过证明。

本组诊断止于一次定向复验，保留原始 503 未解释项；**整组验收保持未通过**，不重复整组碰运气。

已取得的有限通过记录：四组业务 TLS／Chromium，SQLite 各 488 项、MySQL 各 489 项；十二个真实 SIGKILL 点、四次并发等待后拒绝；两端原二字段宿主各 329 项、格式 2 业务／既有 API／意图／格式检查，以及 261 类公开契约、库静态分析和脚本语法检查。初轮与观察代码修正后的记录明确分开，产品示例、SDK src 与公开契约跨组字节一致；库 src／公开契约／StateDocuments 与上一业务组合组也逐字节相同。

已核对并清理：四次私有 MySQL（包含失败及诊断实例）、七个正式／诊断 HTTP 临时根、十二个正式强杀临时根和六个预备根；没有关联存活进程。准确名称见 delivery-check.json，不把既有业务 MySQL 纳入清理。PHPStan 保留既有可选 turbo 扩展 GLIBC 启动警告，分析退出 0。

## 未关闭要求

其他授权／一次性证明／所有启用写入者、完整旧进程交接、最终账号恢复启用及新密码／MFA 登录、见证／审计自身故障与维护、通知队列、外部服务／实体设备／生产 WAF、远端 CI、独立复核和最终同源码九版整轮仍开放。本组业务中断仅拒绝，不执行最终恢复激活。未提交、推送或发布。
