# 当前 Outbox 租约的原生权限核验

源码核对确认，SqlOutbox 原有 currentClaim 只能在已激活的 SQL 状态边界内使用；保护模式公开工厂没有对应的独立原生权限入口。首次认领返回的 Claim 也不能替代发送前的当前权限和租约检查。缺失 API 的现场证据见 [api-before.json](native-current-claim-evidence-2026-10-22/api-before.json)。

新增 currentClaimTarget／currentClaimFor，使用同一个实际 StateAccountConnection。目标绑定来源边界、站点、scope、代际、当前策略和密钥配置、生产者、工作进程及完整令牌的摘要；动作固定为 outbox.current_claim。令牌必须是准确132字节的规范格式，先限长再解析，意图中不保存令牌或消息正文。

```php
$target = $queue->currentClaimTarget($scope, $producer, $worker, $originalToken);
// 使用实际当前会话、角色及上述 target 构造 outbox.current_claim 权限。
$current = $queue->currentClaimFor($policy, $permission, $scope, $producer, $worker, $originalToken);
```

只读准入检查当前签名账本、正文完整性、令牌摘要、工作进程和租约期限；admission／admitted 授权回调在观察事务之外执行，参数和元数据为局部副本。不具备当前角色、工作进程授权拒绝、错令牌或租约失效时，不进入 pending。与首次认领相同，整个入口共用队列预算，并在 pending 之前检查已耗尽的预算。

准入成功后在准确原生权限边界内复用 currentClaim，保留当前／提交／返回的授权和期限检查，以及实际账号最终权限检查。该操作会更新账本根的观察修订及见证，但消息记录、正文、租约期限、工作进程、令牌、尝试次数均不变。它不续租、不接管、不重新排队、不发送、不结算回执。完成时失权或到期不返回令牌；已经开始的操作保留 pending，不自动恢复。

原始 currentClaim 的保护模式限制保留；不能使用新增入口绕过不同 PDO、来源或代际的边界。StateAccountConnection 新增 outboxCurrentTarget／outboxCurrent，LocalStateWitness 仅增加准确动作的准入白名单。公开类型保持272，四个新增方法和既有签名逐项复核见 [api-review.json](native-current-claim-evidence-2026-10-22/api-review.json)。

## 本地验证

测试使用实际新账号、会话、角色、公开工厂、完整 SQL／文件来源及第一次认领的租约。覆盖缺少角色、不合法／错误令牌、错生产者／工作进程、私密授权异常脱敏、原始入口拒绝、嵌套调用、按引用修改授权参数、当前读不延长租约和不修改消息记录、意图不含令牌正文、准入期间到期、完成期间到期及角色撤销。完成失败只检查未决状态保留，不执行续办。初轮测试文件漏写命名空间别名，initial.log 保留，修复测试后继续验证。

[证据目录](native-current-claim-evidence-2026-10-22/)包含九版矩阵、两端私有 MySQL、离线非链接 Composer 全新消费者、静态分析及 API 审核。MySQL使用产品既有10秒默认预算；此前独立1秒配置失败仍保留，不由本次默认配置通过覆盖。没有外部投递、生产数据库、提交、推送或部署。

本批只补齐当前原租约核验；Dispatcher 的完整原生发送／结算与其他剩余产品入口未因此关闭。历史未解释超时、暂缓能力和外部验收继续保留，goal保持active，不宣称全项目验收。

本批源码矩阵另有一项未关闭失败：PHP7.2的current正常场景在约1.923秒时由LocalStatePersistence抛出account.persistence_timeout，未执行完成；见php72-native-current.log和matrix.json。没有重复该场景来覆盖失败，也未放宽持久化预算。两端消费者、MySQL以及其他运行时通过不能作为该次失败已解释或修复的证据。

最终本批结果：九版源码定向矩阵44/45通过，唯一失败为上述PHP7.2持久化超时；其余当前租约正常场景每版94断言、准入到期及完成到期各64断言通过。两端私有MySQL六套全部通过；归档／安装／来源及两端三场景共10/10通过；语法和入口检查13/13通过；PHPStan无错误，可选turbo扩展GLIBC警告保留。归档中四个核对文件与最终源码SHA256逐项一致。精确结果见result.json，不把定向检查称为完整项目验收。
