# 可选认证集成当前消费者收口

2026-10-24。本批冻结SDK与适配器源码，补齐当前OIDC／WebAuthn的本地消费者证据，没有新增功能、升级依赖或修改公开API。

## 真实支持范围与结果

OIDC包声明PHP>=7.2且<8.4，锁定jumbojett/openid-connect-php v1.0.2；实际执行PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3，七版各16个功能程序，共112个程序通过；加归档、安装、依赖清单共122/122检查通过。覆盖声明边界、签名回调、证明导出、关联解除／批量解除、登出栅栏、当前会话绑定、普通MFA登录及绝对／空闲期限与返回复核。回调及密钥响应在本地模拟，没有连接真实IdP。

WebAuthn包声明PHP>=8.2且<8.6，实际固定web-auth/webauthn-lib 5.3.9；执行PHP8.2、8.3、8.4、8.5。四版各34个独立功能程序，共136个程序通过；另各7个MySQL设备授权边界程序，共28个通过，包含事前／当前／返回／通知／时钟变化拒绝。加归档、安装、清单及SQL控制步骤共147/147检查通过。包含真实库验证、挑战竞争、持久状态、SQLite设备撤销竞争、设备管理、当前会话授权及权限／期限变化；没有实体设备或浏览器验收。

支持范围外的OIDC 8.4—8.5、WebAuthn 7.2—8.1未运行，不扩张包声明。已执行范围内无NOT RUN／SKIP或PHP Warning／Deprecated日志。

[OIDC原始检查](optional-current-evidence-2026-10-24/oidc/result.json)、[WebAuthn原始检查](optional-current-evidence-2026-10-24/webauthn/result.json)、[独立终态核对](optional-current-evidence-2026-10-24/verification-final.log)、[范围统计](optional-current-evidence-2026-10-24/summary.json)。执行前登记1295个输入；除收口时同步修复的消费者测试工具一处外，其余1294份保持，SDK与适配器源码全部保持。实际执行使用保留的同逻辑运行器副本；归档后离线新装，核心与适配器所有PHP文件摘要一致，实际类来源为消费者vendor，路径包禁用符号链接，锁定版本及依赖清单逐项留存。Composer插件和脚本禁用，没有改动原安装环境。

## 消费者工具可靠性修复

同步修复[消费者测试工具](../tests/optional_nondeferred_consumer.py)：已有非空输出目录在执行产品前拒绝，原结果不再被覆盖；新输出目录以排他所有权文件防止两个进程同时写入；归档显式禁用Composer脚本／插件；临时目录实际退出后才记录cleaned，失败时不提前声称清理成功。兼容变化仅限测试CLI：复用旧输出目录会拒绝，应使用新目录，SDK和公开API不变。

本批全矩阵使用保存的同逻辑副本，末尾才同步工具改动。对已有OIDC结果目录的拒绝检查确认所有123份文件完全不变，且未执行任何产品程序；修改后的原工具再执行一个PHP8.5 authority-time专项，5/5准备和验证步骤通过，目录实际清理。该功能程序仅为验证修改后工具而重复一次，未重跑整套已通过功能。

[工具源码增量](optional-current-evidence-2026-10-24/tooling-change.diff)、[唯一登记输入变更](optional-current-evidence-2026-10-24/tooling-input-change.json)、[旧输出保护](optional-current-evidence-2026-10-24/output-preservation.json)、[原工具正常路径](optional-current-evidence-2026-10-24/tooling-positive/result.json)。初始输入摘要未改写，核对器只允许这一项已说明的工具变更。

## 仓库SQL补充与预设失败

另在相同四版执行SqlCredentialRepository的SQLite／MySQL直接程序，各4个，共8个程序取得通过。SQLite每程序34项检查、MySQL每程序27项；SQLite多出的7项是NUL TEXT、超大字段／代际／修订／设备数量等专门拒绝断言，不是降低MySQL标准。

初次MySQL补充只在PHP8.2完成断言，后三版因运行器没有按原测试前提重置自建表，以table already exists在建表阶段失败，未执行对应仓库断言。原控制步骤11/12，原三条失败均保留。修正的补充运行器只在自己的带所有权标记、无TCP实例中按原顺序重置两张测试表，并仅执行PHP8.3—8.5漏项；3个程序、7/7准备及控制步骤通过。未更改SDK、仓库测试或断言，没有重复已通过SQLite／设备流程。

仓库程序包含设备凭据撤销及独立generation原语，SqlCredentialRepository只操作自己的两张设备表；它不创建或启用业务账号，不调用StateWorkerHandoff、账号最终恢复或完整F01。这些独立原语不作为恢复链路验收。

[首轮仓库记录](optional-current-evidence-2026-10-24/webauthn-repository/result.json)、[首轮MySQL逐程序](optional-current-evidence-2026-10-24/webauthn-repository/mysql-rows.json)、[建表错误原日志](optional-current-evidence-2026-10-24/webauthn-repository/mysql-repositories.log)、[补充仓库](optional-current-evidence-2026-10-24/webauthn-repository-remaining/result.json)、[补充逐程序](optional-current-evidence-2026-10-24/webauthn-repository-remaining/mysql-rows.json)。按OIDC112、WebAuthn136、MySQL授权28及仓库8，共284个功能程序范围取得通过覆盖；仍不把原三次初始化失败或原控制器退出1写成全绿。

核对器初稿误把SQLite的通过汇总写为MySQL的27项，核查源文件中的7项SQLite专门断言后修正为34；同时识别挑战／撤销竞争的专门正向输出。只修正证据核对，没有更改测试或复跑功能。

## 发行资源核对

原消费者运行器会将工作区SQL预设复制到测试目录，不能仅据此认定发行SQL齐全。本批追加独立归档与安装资源核对，不重复功能程序：核心／OIDC／WebAuthn三个ZIP均检查路径、测试与vendor／证据排除、无符号链接及源码摘要；核心新安装后核对368个文件（含composer.json及27份SQL），WebAuthn核对16个文件（含4份SQL）。新消费者的依赖版本与已测WebAuthn消费者完全一致。

4份WebAuthn SQL包含两个建表和两个迁移文件；仅核对实际归档／安装字节，没有执行迁移。各项均通过，见[实际资产核对](optional-current-evidence-2026-10-24/assets/result.json)。所有本批自建消费者目录和私有MySQL控制器已正常结束并清理；既有Sodium包装器保留。

## 尚未完成

本批未修改SDK、适配器、默认预算或公开契约，未重复默认正常管理流程。此前第二次签发的未知结果及另一次最终审计超时、历史时钟失败仍保留，不能用本批消费者通过关闭。普通组件、可选集成和私有SQL各专项不是一次全项目验收。

真实IdP、实体设备、浏览器／目标宿主及最新在线公告审计未执行；未定义OIDC关联迁移按用户许可跳过。跨安全代际worker交接、未知回执续办、最终账号恢复启用、依赖完整F01及完整check.sh均未运行。默认稳定预算及最终非暂缓整合验收仍开放，goal保持active。未提交、推送、部署或修改内部任务数据库，原有环境、数据、未提交改动与失败证据保持。
