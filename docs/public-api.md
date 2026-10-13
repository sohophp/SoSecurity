# 1.0 公开 API 候选清单

`resources/api/classes.json` 列出拟稳定的78个类/接口，`candidate.json` 保存构造/公开方法、参数名称/类型/默认值、返回类型、继承/接口关系、公开常量及属性默认值。名称、参数顺序与PHP8命名参数均是兼容性的一部分。现在是提案基线，尚未经过独立复核并冻结，不等同于已发布1.0。

```sh
php72 bin/api-contract.php
php85 bin/api-contract.php
# 只有有意修订并审核接口时更新；不能通过自动重写基线掩盖变化。
php72 bin/api-contract.php --write
```

检查只使用Reflection，不调用模块构造器，不启动Session/发头/连接存储或初始化可选清理库。PHP8.5会把self解析为类名，旧运行时返回self拼写，工具按声明类规范化语义后比较，避免将反射差异错报成产品接口变化。源码路径分隔符统一后比较，Linux及原生Windows复用同一候选清单。继承关系记录父类及本库接口；PHP引擎自动追加的Stringable等内置接口不作为本库签名变化。遇到未支持的类型结构会失败，不能默默放宽PHP7.2要求。

`Api\SignatureProfile`、`Http\Outbound\PublicAddress/RequestHeaders`、`Storage\Codec`、`Support\Guard/Deadline` 为内部实现辅助，不在稳定合同中；其他类即使公开仍须遵守其文档用途，例如MemoryStore仅用于测试。所有安全默认值/副作用/错误分类也属于行为承诺，需要功能与负面路径检查，签名相等不能证明行为安全。

可选适配器和示例不要求框架；examples为可调用接入示例，宿主认证/权限/请求解析仍由真实应用承担。ABI清单和生成器用于源码开发审核，核心压缩包排除该开发清单，保留MySQL运行时schema。正式冻结须有全目标版本实际运行/Composer证据、独立迁移示例、独立复核和发布审核。
