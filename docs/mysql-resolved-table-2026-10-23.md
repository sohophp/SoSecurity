# MySQL 实际表解析与临时表遮蔽

本批确认并修复一个独立产品缺陷。连接中存在与安全状态永久表同名的临时表时，原校验读取information_schema中的永久InnoDB结构，实际SQL却访问临时表。自建MySQL8.0.46反例中，临时MyISAM表被接受，回调执行1次、临时表新增1行、永久表保持0行。[严格建表反例](mysql-resolved-table-evidence-2026-10-23/before-strict.log)保留；前两次建表预设错误单独保留，不计作产品缺陷证据。

## 修复行为

内部SqlSchema使用有界零行双重引用探测实际解析的表：同一条查询以两个别名引用准确的表名，ON 1=0且LIMIT 0，不返回数据行。MySQL8.0明确规定临时表不能在同一查询中重复引用，同名临时表会遮蔽永久表，见[官方限制说明](https://dev.mysql.com/doc/refman/8.0/en/temporary-table-problems.html)。在实际8.0.46中已验证临时InnoDB／MyISAM均被拒绝，合法永久表通过。

MySqlStore在构造校验和每次事务／清理入口复核实际表；私有单表、双表结构校验及SqlStateSnapshot的前后结构观察也使用该探测。快照先拒绝目录中不符合类型的表和视图，再确认实际表解析，之后才读取数据。所有原有列、索引、外键、触发器、权限和持久性检查保持；不缓存授权或取消当前状态读取。

仅修改三个运行时文件：Support/SqlSchema.php、Storage/MySqlStore.php、Account/SqlStateSnapshot.php。不新增公开候选类／接口或签名；当前277清单保持。内部新增查询构造方法严格限制64字符以内的小写ASCII标识符，引用表名以保留原来支持的SQL保留字表名。SQLite维持原main前缀探测。默认预算、SQL DDL、持久格式及合法快照摘要不变。

新增探测不读取无界SHOW CREATE TABLE文本，不增加数据库权限、改变会话配置或执行产品DDL，既有事务设置保持。MySqlStore沿用原错误归一化和模拟／原生预处理兼容性；SqlTransaction与快照仍要求原生预处理。已存在同名临时表的组合现在拒绝，调用者须先修正连接环境。原有纯回调契约保持，本批不提供PHP沙箱。

## 验证

修前反例、预设失败和初步修复日志分开保留。扩展预设曾误用模拟预处理进入SqlTransaction，触发既有配置拒绝；修正测试分支，保留该限制并增加拒绝断言，没有放宽产品检查。冻结源码及测试输入为[inputs.json](mysql-resolved-table-evidence-2026-10-23/inputs.json)，最终逐项命令、退出码及结果以[verification.json](mysql-resolved-table-evidence-2026-10-23/verification.json)为准；39项外层定向调用全部通过，已通过场景共4104项断言。两端覆盖MySqlStore规范结构、事务归属、结构变化、索引／唯一约束、私有双表及权限、真实Outbox／幂等／审计消费者、SQL事务边界、SQLite影响回归和MySQL快照；PHPStan及两端API277通过。保留PHPStan可选turbo扩展GLIBC加载警告，未执行完整门禁。

新测试每版20种组合：两种临时引擎，构造／复用事务／清理，私有单表和双表任一侧，完整SQL快照；MySqlStore两种预处理及事务原生预处理限制、真实永久行保持、零回调／零临时写入、拒绝后无遗留事务、移除临时表后的正常请求，以及保留字表名和非法标识符。测试严格创建自有表后才记录清理权限，不使用IF NOT EXISTS借用已有表。

本批不宣称全项目验收。完整门禁、暂缓恢复／工作进程交接／未知续办／最终恢复启用及外部投递均未执行。新SQL路径已单次复验默认3000ms首次签发：约3.168616305秒失败，account.completion_unknown、pending，见[准确记录](mysql-resolved-table-evidence-2026-10-23/default-timing.json)。没有all／rotate或未知续办，也未延长期限。该失败与39项定向调用分开记录，默认签发仍未验收。旧PHP7.2时钟及未定位sql.timeout、地址内部自定义策略接入等余项保持开放。goal继续active，未提交、推送或部署。

冻结矩阵之后仅调整门禁接线：测试通过控制器另建私有数据库，避免整轮门禁预置状态表与反例严格建表冲突。[嵌套隔离](mysql-resolved-table-evidence-2026-10-23/gate-isolation.json)通过，外层原状态行保持；[门禁差异](mysql-resolved-table-evidence-2026-10-23/gate-delta.json)单独保留，运行时和PHP测试输入未变，完整门禁未运行。

## 发行消费者与代表性原生请求

实际Composer ZIP及离线全新path包安装、两端vendor加载来源验证全部通过。三个运行时文件及15个包内SQL资源摘要一致，消费者使用包内resources／examples；两端运行MySqlStore临时表拒绝／复用恢复、规范MySQL存储及事务归属、SQLite结构及捕获检查，共12个外层步骤全部通过、598项断言。[消费者汇总](mysql-resolved-table-evidence-2026-10-23/consumer-summary.json)和[归档／锁定依赖记录](mysql-resolved-table-evidence-2026-10-23/archive.json)保留。临时资源清理完成，源码保持冻结。

新MySQL路径还执行一次原有normal测试配置的原生首次签发：显式30000ms配置、约6.483653714秒成功、见证current，随后立即停止，没有all／rotate。它仅证明该显式配置的正常SDK路径，不能替代默认3000ms失败；[配置及结果](mysql-resolved-table-evidence-2026-10-23/configured-timing.json)与默认失败分开。没有修改产品默认配置、时钟或预算。完整候选与稳定版验收仍未完成。
