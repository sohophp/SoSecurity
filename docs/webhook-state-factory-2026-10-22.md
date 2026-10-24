# Webhook 完整声明与公开工厂绑定

> 后续：原生处理入口已补齐并完成专项验证，见[处理专项](webhook-native-processing-2026-10-22.md)。本记录保留原阶段的源码与验证范围，不代替后续结果。

> 后续进展：配置状态声明的 SqlInbox 已新增原生接收准入，直接调用 accept；本记录保留上一阶段状态和证据。处理入口仍需显式边界，见[原生接收专项](webhook-native-receive-2026-10-22.md)。

本批继续原计划的非暂缓接入工作，新增StateWebhookConnection并接通Security工厂配置。本阶段完成确切依赖和完整接收／处理SQL范围的声明核对，**未完成原生只读准入及失败结果编排**，不把显式boundary.run包装当作完整保护模式。

## 实际实现

- `Account\StateWebhookConnection` 核对同一语义边界、见证、CompositeStateSnapshot中的确切SQL／Webhook配置来源、PDO、站点、scope、epoch、端点、本地KeySet、回执HmacKeys和可选处理策略。要求接收表完整列及完整行范围；声明处理策略时还要求处理表完整列及完整行范围。构造不查询SQL、不创建表、不初始化见证、不调用权限或提供器。
- 独立声明通过现有SqlStateAccess注册PDO；如果PDO已绑定StateAccountConnection，必须显式提供该同边界／同见证的账号声明。没有改变注册表的重复绑定拒绝规则，不以新Webhook声明替换旧账号权限。
- `webhooks.<name>.state_connection` 指向上述声明。保护模式的key_provider服务是确切不可变KeySet；普通模式仍为原可调用提供器。Verifier、SqlInbox及SqlProcessor工厂分别验证自身实际依赖。已配置认证状态边界但缺少匹配Webhook声明时默认拒绝。
- Inspector识别本地KeySet和声明，纯检查配置一致性；返回manual或fail，不调用SQL、密钥提供器或业务权限。结构匹配不等于当前状态或真实宿主验收。
- API新增一个公开类型，实际清单从269变为270。先生成独立反射提案并审查构造器、可选账号／处理绑定及校验方法，再断言所有原有类型和成员签名完整保持，才应用提案；没有直接重写候选。见 `api-before-sha256.txt`、`api-proposal.json`、`api-diff.json`、`api-review.json`。原有未提交契约保留，不是发行冻结。

## 测试证据

目录：[webhook-state-factory-evidence-2026-10-22](webhook-state-factory-evidence-2026-10-22/)。

- 新工厂测试71断言：缺正文、缺处理表、过滤行范围、错密钥、错封存密钥、错声明、错站点／端点／处理策略拒绝；工厂及诊断不调用SQL或宿主回调；边界外有效接收／处理调用拒绝；边界内接收、领取、执行及业务SQL成功，见证一致；改动覆盖状态后再次处理拒绝。
- 共享账号测试21断言：使用全新空资源、真实账号示例及完整账号／账本／Outbox／Webhook SQL声明，先建立账号PDO注册；不提供账号声明时重复绑定拒绝，提供准确账号声明后Webhook接收和账号登录、会话验证及撤销成功。没有运行代际交接、未知回执续办或最终账号恢复。
- `matrix.json`：PHP7.2、7.3、7.4、8.0—8.5，初轮每版新工厂、共享账号、原有处理工厂120断言、270类／接口API检查均通过，共36条。另9条预设配置命令误写为不存在的 `tests/config-presets.php`，退出1且未执行测试，原日志保留。
- `configuration.json`：改用实际 `tests/configuration-presets.php` 后九版各57断言通过，并补查 `tests/configuration.php` 各42断言，18条通过。没有无依据重复已通过的36条。
- `mysql.log`：私有无TCP MySQL，PHP7.2原生单调时钟运行时／PHP8.5分别通过新工厂71、共享账号21及原有处理工厂120断言，控制器退出0并清理自己的实例。
- `static-final.log`：最终运行时代码按项目配置PHPStan分析退出0，既有turbo扩展GLIBC加载警告保留。原初静态日志不替代最终结果。
- `archive.json`：实际ZIP归档、离线全新Composer安装，反射确认StateWebhookConnection／Security／Inspector来自vendor副本；两端各执行三套工厂／共享账号检查，10条命令全部退出0。测试样例、SQL资源及SQL账号示例在消费者测试目录中使用，组件代码来自安装包，非源码软链接。归档未包含测试／本地证据，记录四个运行时文件摘要。这不是整项目最终发布候选冻结。
- shell／Python入口语法及本批运行时空白差异检查通过。新增检查接入 `bin/check.sh` 和独立 `tests/mysql_check.py --webhook-state-factory`。未运行含暂缓套件的全项目脚本。

本批是新增缺失能力，未伪称有旧实现的修复前失败断言；具体接收／处理绕过的原始复现仍见上一批记录。

## 兼容及仍需推进

普通未保护模式的可调用提供器、历史处理工厂和诊断用法通过回归。已启用认证状态边界的SDK配置现在必须提供匹配Webhook声明；以前静默构建独立Webhook服务的行为被收紧。新保护模式Verifier在边界外的拒绝由请求保护异常边界封装为依赖错误，接收／处理入口仍直接返回状态边界错误，不泄露原始异常。

工厂不会自动进入边界，调用者仍需显式协调受保护操作。固定配置来源不包含任意宿主业务权限规则；宿主实际业务表仍须明确列入完整来源。普通业务拒绝、无效请求及容量拒绝如何在pending之前结束，仍需原生准入设计和验证；目前不能宣称完整受保护Webhook已验收。未注册的其他PDO／其他进程写入者也不能仅靠本次进程内声明视为已覆盖，原跨代际限制保持。

在线提供器、旧ApiKeys、维护等余项、历史PHP7.2维护超时、暂缓能力及外部验收继续开放。goal保持active。没有提交、推送、部署、生产访问或撤销用户已有改动。
