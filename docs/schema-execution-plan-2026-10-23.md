# MySQL结构检查中的重复外键查询修复

实际执行计划确认：原SqlSchema列投影中的外键子查询被MySQL标为`uncacheable`，两列样例执行两次。改为带LIMIT 1的单行派生结果，在同一条SQL内计算外键依赖；不跨语句缓存，不改变外键条件、触发器限制、字段预算、事务边界或权限检查。精确本轮改动见[补丁](schema-execution-plan-evidence-2026-10-23/runtime.patch)。

PHP8.5／私有MySQL8.0.46的三轮交替顺序对照中，每轮30次查询，所有返回行一致。13列合计耗时减少约21.95%，64列约46.27%；两列小表增加约8.84%。这些是特定结构查询的结果，不是整体签发吞吐量承诺。另一个拆成两条SQL的方案在13列场景收益不稳定，未采用。见[原始执行计划](schema-execution-plan-evidence-2026-10-23/baseline-explain.txt)、[修改后计划](schema-execution-plan-evidence-2026-10-23/candidate-explain.txt)和[性能数据](schema-execution-plan-evidence-2026-10-23/performance.json)。

本地验证覆盖PHP7.2、7.3、7.4、8.0—8.5，SQLite和MySQL8.0.46：结构检查、同批复核、回调／写入／事务边界后的重新检查、真实DDL拒绝、入向／出向外键、关闭外键执行时的拒绝、业务数据保留及回滚，共54项程序取得通过证据、6534项断言。静态分析通过，实际公开API仍为277类／接口。没有运行完整项目脚本或暂缓流程。

初轮SQLite复核测试九版均失败，原因是测试计数器仍匹配旧PRAGMA语句，未匹配现行表值函数。修改前产品源码同样复现；仅修正tests/sql-schema-reuse.php的匹配后，九版原有7项断言全部通过。初轮汇总退出码1和失败日志保留，不改成全绿。首轮诊断中的EXPLAIN也被计入结构查询数，造成一次测试计数失败；后续诊断在计时／解释期间隔离计数钩子，保留原始日志。

归档及全新消费者首轮10步骤中8通过、2因同一测试计数问题失败。修正后重新打包、离线安装、核对加载来源并在PHP7.2／8.5补验复核测试，6步骤通过；消费者SqlSchema摘要与工作树一致。初轮驱动未汇总失败退出状态的问题也已修正，初轮结果按逐项退出码解释。见[初轮](schema-execution-plan-evidence-2026-10-23/archive.json)、[补验](schema-execution-plan-evidence-2026-10-23/archive-fixed.json)和[专项汇总](schema-execution-plan-evidence-2026-10-23/closeout.json)。

随后在没有其他本批测试负载时，以新建账号执行PHP8.5默认MySQL委托流程，保留3000ms凭据预算及全部原有授权。首次实际签发仍失败，调用耗时3.069208263秒，PHP用户态／内核态CPU分别约0.408436／0.331527秒，最终为account.completion_unknown；栈在CredentialRegistry::actor的第111行期限检查。计时包括错误传播和清理，不能据此断言恰好超出预算69ms或量化整体稳定加速。后续列表、轮换、替换和撤销断言未执行，没有续办未知结果。[失败日志](schema-execution-plan-evidence-2026-10-23/default-run.log)、[计时](schema-execution-plan-evidence-2026-10-23/default-timing.json)、[终态](schema-execution-plan-evidence-2026-10-23/default-result.json)均保留。

没有公开API、配置默认值、存储格式或数据迁移变化；其他MySQL版本和MariaDB未验证。自有临时数据库、包装器及消费者目录均由运行器清理，没有提交、推送、部署或外部投递。默认签发超时、PHP7.2原生时钟问题及其余未齐门禁继续开放；暂缓能力及外部验收未完成，goal保持active。
