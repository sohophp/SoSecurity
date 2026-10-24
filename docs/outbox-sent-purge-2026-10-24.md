# 已确认消息的普通到期清理

2026-10-24。本批在[数据库身份探测诊断](database-probe-cost-2026-10-24.md)没有采用原型后，继续修复独立的已确认消息到期清理问题；没有实现或测试未知回执续办。

## 复现与最小修复

PHP7.2和8.5均通过正常首次入队、准确首次领取及明确acknowledge形成sent消息，未进行外部发送。到期后两项原始问题均实际复现：关闭返回false仍报告purged=1并删除记录；在同事务测试回调先删除记录后，SDK实际DELETE影响0行，仍报告purged=1并重新签名根状态。

证据：[7.2关闭失败](outbox-sent-purge-evidence-2026-10-24/before72.log)、[8.5关闭失败](outbox-sent-purge-evidence-2026-10-24/before85.log)、[7.2零行](outbox-sent-purge-evidence-2026-10-24/before72-zero.log)、[8.5零行](outbox-sent-purge-evidence-2026-10-24/before85-zero.log)。

仅修改SqlOutbox::maintain的sent到期分支一处：使用已有内部execute检查行数及关闭，并要求实际删除恰好1行才增加purged。关闭／行数读取不确定令SQL单元不可复用；删除0行以outbox.corrupt拒绝，事务回滚，根和记录保持。SQL、绑定、事务归属、权限回调、存储格式、输入／时间／内存预算保持，API仍为278类／接口，候选契约未改。resolved／未知处置分支源码未动。

修后[关闭失败](outbox-sent-purge-evidence-2026-10-24/after85-close.log)和[零行](outbox-sent-purge-evidence-2026-10-24/after85-zero.log)均拒绝返回且记录恢复为1条。

## 实际测试

PHP7.2、7.3、7.4、8.0—8.5九版本，SQLite／API27/27、MySQL18/18通过。每后端每版12场景、147断言，共216个新增场景，覆盖关闭false／异常、行数异常／负数、组合故障、零行、有效字段签名篡改、正常清理、未到期及请求／提交／返回三阶段撤权。正常清理验证容量释放、顺序号持续增加及过期标识不能重新入队；测试预设时钟只用于原有TTL边界，不是默认性能验收。

事务边界分别验证：故障和提交前撤权回滚；提交后撤权拒绝输出，但已完成的删除保持提交，不宣称已经回滚。五种清理／行数不确定还核对完整SDK异常链、私有消息不泄露、同一SQL单元拒绝继续。零行及数据篡改保留原状态，避免以合法根签名归一化异常数据。

实际ZIP、离线全新消费者安装且不使用符号链接；两端两后端8个功能程序、源码来源及367份SDK／SQL摘要核对通过。SQL旧输入边界回归、九版API278、PHP语法、Shell／Python语法和静态分析通过。静态工具保留可选turbo扩展要求GLIBC_2.32的启动警告，最终No errors，没有修改环境。

证据：[SQLite／API](outbox-sent-purge-evidence-2026-10-24/local-result.json)、[MySQL](outbox-sent-purge-evidence-2026-10-24/mysql-result.json)、[全新消费者](outbox-sent-purge-evidence-2026-10-24/consumer/consumer.json)、[消费者MySQL逐程序](outbox-sent-purge-evidence-2026-10-24/consumer/test-rows.json)、[静态](outbox-sent-purge-evidence-2026-10-24/static.log)、[源码增量](outbox-sent-purge-evidence-2026-10-24/source-change.diff)、[最终输入](outbox-sent-purge-evidence-2026-10-24/final-inputs.json)。SDK仅该一类改变，其余366份输入保持；只使用自建无TCP MySQL、私有SQLite和自身临时资源。

本批未运行完整check.sh或默认九版整轮，不把这些专项称为全项目或稳定版验收。默认性能、PHP7.2时钟与未解释依赖错误、最终非暂缓整合仍开放；真实IdP／设备、生产代理／WAF及外部投递未验收。跨代交接、未知回执续办、最终恢复启用和依赖它们的完整F01继续暂缓，goal保持active。没有提交、推送、部署或访问生产数据库。
