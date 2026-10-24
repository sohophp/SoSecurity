# 旧 ApiKeys 原生保护接入（2026-10-22）

本批补齐已确认的产品缺口：旧 ApiKeys 在保护模式下只有工厂拒绝，不能原生签发、只读认证、轮换或撤销。现在通过显式 StateApiKeyConnection 接入完整文件来源与宿主权限来源，普通路径和既有拒绝保持。不是完整稳定版或 F01 验收。

## 实现与边界

- 新声明绑定准确的 StateBoundary、LocalStateWitness、CompositeStateSnapshot、FileStateSnapshot、FileStore、站点、作用域、代际及同一时钟。完整物理文件覆盖必须成立，旧对象及另建原始 FileStore 不能绕过边界。
- `Security::apiKeys($state)` 和 `new ApiKeys($store,$clock,$state)` 增加末尾可选声明。工厂使用明确声明的文件存储，不搬迁原数据，也不把限流等共享预算存储并入保护域；工厂命名空间必须是同站点的 `site:shared`。
- 准入只读捕获完整来源，核对记录、永久 epoch、当前调用者、权限、期限和物理容量；正常拒绝及认证不写 pending。写操作通过准确的 api.keys.issue／rotate／revoke 意图进入原边界；随机秘密在准入回调外生成，碰撞重试最多四次并共享时间预算。
- 写前及写后复核当前调用者、期限、epoch 和准确记录。写入后撤权或过期保留 account.completion_unknown 与 pending；未添加续办、清除 pending 或恢复旧秘密。默认预算 1000ms 未放宽。
- 认证不改变过期文件；显式获准撤销可清理过期物理凭据并释放容量。来源恢复成旧备份时，在调用宿主权限回调前拒绝。
- 同一账号／Webhook 边界可显式组合这套独立服务凭据。宿主必须提供当前不透明调用者标识，不推断账号或会话身份。权限回调返回有界 UTF-8 字符串才允许，null／false 拒绝，异常与非法返回脱敏为 api.authority_unavailable。回调必须只读、可重复，参与授权的可变状态须完整纳入来源；不承诺任意外部在线权限系统的原子性。
- 当前原生凭据后端是 FileStore，宿主完整状态来源验证了 SQLite／MySQL。没有新增原生 MySqlStore／Redis 凭据适配，也不声称拦截所有宿主原始 SQL 写入者。

## 验证证据

证据目录：[api-key-native-evidence-2026-10-22](api-key-native-evidence-2026-10-22/)。

- `matrix.json`：PHP7.2、7.3、7.4、8.0—8.5，共90条专项命令全部退出0。每版原生正常72、epoch36、写后撤权30、写后过期30、预算31、普通时间边界130、原API200、原epoch10、共享账号／Webhook／ApiKeys25断言，以及271类型API反射通过。
- `mysql.log`：仅自建无TCP私有MySQL；PHP7.2原生单调时钟运行时与PHP8.5各八条专项通过。原生五模式、共享边界、普通MySqlStore时间65及原API281断言通过。
- `archive.json`：ZIP归档、离线全新Composer非链接安装、vendor来源反射、两端八套运行时检查，共20条命令通过。记录六份运行时源码摘要，并核对安装副本相同。
- `race.json`：九版SQLite和两端已安装消费者共11条四进程竞争通过，每条37断言，物理容量二只产生两份凭据；所有进程仅使用同一当前代际。并发新增测试不改变归档运行时，摘要再次匹配。
- `mysql-race.log`：PHP7.2同项通过；PHP8.5执行失败，一个竞争请求触发 api.timeout，未达到恰好两次成功的测试预期。保留失败，不提升默认预算、不减少竞争者、不删除断言。`mysql-race85-diagnostic.log` 在源码、预算和四进程断言不变的情况下定向复跑通过37断言；首次超时根因未确定，不能用后来的通过抹去失败。
- `completion.json`：两端18份PHP语法检查通过，运行时摘要与已安装归档保持一致；shell／Python入口语法及相关差异空白检查通过。
- `static.log`：PHPStan退出0，保留环境已有可选turbo扩展的GLIBC加载警告。
- `api-review.json`、`api-diff.json`：实际清单270增至271，唯一新增类型StateApiKeyConnection；既有类新增StateOperation::legacyApi与FileStore::usesClock，ApiKeys构造和Security::apiKeys增加末尾可选参数。逐项审查后更新候选，未盲目以新反射覆盖旧契约。

## 兼容与未完成

普通调用无需传新参数，原存储和token格式保持。选择原生模式需显式声明完整来源、当前调用者和文件域；不能直接外包一层边界来代替声明，不能将普通存储的过期清理语义当作原生只读认证语义。

本批未运行包含暂缓能力的全量脚本。跨代际工作进程交接、回执未知续办、最终账号恢复启用和依赖它们的完整F01仍暂缓。未定义OIDC关联迁移继续跳过。全入口／写入者清单、维护与通知／队列对账、其他提供器适配及既有未解释超时仍需后续核对；目标宿主、外部服务、远端CI及独立审查未验收。goal保持active，没有提交、推送、部署或生产访问。
