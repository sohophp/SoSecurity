# Webhook 固定本地配置来源

本批补齐完整保护模式接入的一项缺失能力：原有完整来源支持 API KeyRing，却没有覆盖 Webhook 提供器密钥、回执封存密钥及处理策略的具体来源。新增 `Account\WebhookStateSnapshot`，接入 `CompositeStateSnapshot` 的具体类型检查；未接受任意插件回调，也未连接在线密钥提供器。

## 实际实现

来源绑定显式PDO和稳定profile，覆盖Endpoint完整指纹、KeySet材料／ID／顺序、HmacKeys当前ID及全部保留密钥，以及可选ProcessingPolicy。profile决定来源身份，配置内容决定摘要；换密钥不能通过自动更换来源身份掩盖内容变化。

新增 `KeySet::stateDigest()` 和 `HmacKeys::stateDigest()`，使用各自用途隔离的HMAC材料摘要，再组合为固定长度配置摘要，不返回原始密钥。KeySet顺序会影响多签名验证选中的key ID，故保留顺序；HmacKeys按ID查找，与排列无关，故排序后取摘要。来源不读取网络、不调用提供器、不写SQL、不初始化或重置见证、不批准任何密钥更换。

`uses()` 要求确切KeySet及HmacKeys对象，端点配置及处理策略内容一致。它是后续准确工厂绑定的检查手段，不能单独授权请求。来源调试／导出隐藏依赖，拒绝序列化与反序列化。

## API审查

实际原清单为268类／接口。新公开类型使其变为269，并为两个已有类各新增一个无参数 `stateDigest(): string` 方法。没有既有方法删除、参数变化或返回类型变化。

先生成独立提案至本批证据目录，逐项查看反射签名和差异；再通过脚本断言除新类型及这两个方法外，每一个既有类型、成员和签名都与修改前候选相同，才应用提案。没有直接对候选运行自动 `--write`，也没有重置既有未提交契约。原候选摘要、提案、差异和审查结果均在 `api-before-sha256.txt`、`api-proposal.json`、`api-diff.json`、`api-review.json`。这不是发行API最终冻结。

## 实际测试

证据目录：[webhook-state-source-evidence-2026-10-22](webhook-state-source-evidence-2026-10-22/)。

- `before.log`：新增功能实现前，测试因缺少WebhookStateSnapshot类型失败；这是缺失功能证据，不能描述成已有逻辑安全回归的复现。
- `matrix.json`：PHP7.2、7.3、7.4、8.0—8.5共54条命令通过。每版含新来源93断言、通用私钥导出77断言、Webhook密钥导出10断言、既有组合快照视图和引用隔离测试，以及269类／接口API检查。
- 新来源测试覆盖四种Webhook协议；相同配置摘要稳定；更换提供器密钥、调整其顺序、移除密钥、改变封存当前密钥、移除或替换保留封存材料、改变处理策略、改变端点均在独立见证检查时拒绝，操作回调为零，原见证记录保持。没有对这些拒绝状态进行续办或重新初始化。
- 实际语义捕获仍覆盖SQL与固定配置；原有任意插件回调拒绝测试通过，未放宽来源类型要求。端点与密钥不匹配时配置拒绝，密钥不出现在普通调试／导出中。
- `mysql.log`：私有无TCP MySQL，PHP7.2原生单调时钟运行时／PHP8.5分别通过新来源93断言和既有完整组合捕获39断言。实例及资源由自建控制器清理。
- `archive.json`：实际ZIP归档、离线全新Composer消费者安装，反射确认新来源及密钥类来自vendor副本；两端各运行新来源和两套密钥导出测试，10条命令退出0。归档排除本地测试／证据，记录四份运行时代码摘要。验证本批代码的发行包，不代表整项目发布冻结。
- `static.log`：项目PHPStan退出0，既有turbo扩展GLIBC加载警告保留。shell／Python入口语法检查通过。

新增测试接入 `bin/check.sh` 的SQLite／MySQL分支和独立 `tests/mysql_check.py --webhook-state-source`，没有运行含暂缓流程的完整门禁。

## 兼容及剩余工作

新增API，不改变原密钥签名／验签方法及已有来源摘要格式。现有Composite未添加该来源时保持原行为。为已有部署增添来源会改变完整来源身份，不能通过重新初始化见证跳过已有状态与审批；当前测试只从自建全新环境开始。

尚未完成：公开Webhook工厂对确切来源和完整SQL范围的验证、锁内正常拒绝准入、实际接收／处理端到端原生编排；在线提供器另有外部权威依赖。该来源不能自动把现有Verifier或SqlInbox变成完整受保护入口。旧ApiKeys、维护等计划余项及历史超时仍开放；暂缓的交接、未知回执续办和最终恢复没有实现或测试。goal保持active。没有提交、推送、部署、生产访问或撤销用户已有改动。

English compatibility: one public class and two read-only digest methods are added, bringing the reviewed public manifest to269 classes/interfaces. Existing member signatures are unchanged. The new source covers immutable local Webhook configuration only. It neither authorizes requests nor supplies complete SQL coverage, online key authority, migration approval or recovery.
