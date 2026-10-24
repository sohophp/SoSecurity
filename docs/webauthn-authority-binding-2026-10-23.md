# WebAuthn宿主绑定与直接授权错误边界（2026-10-23）

## 复现及修复

SessionDeviceAuthority原先跨before／current／return保存账号、设备、注册会话ID与证明摘要，漏掉实际宿主会话binding。已有两个明确反例：before后改变binding，current仍允许；current后改变binding，return仍允许。现把经过处理的宿主binding一起保存和比较。失败时清除阶段状态，恢复旧binding也不能继续完成或重用已消费证明。

另外，直接调用issueRemovalProof／allow时，宿主会话回调、身份提供器、自身时钟及CSRF存储的原始异常可透出。现相应依赖边界返回固定文本、无previous的异常：webauthn.authority_unavailable、webauthn.clock或webauthn.request_unavailable。自身时钟还检查非负及整数上界。核心的StorageException／csrf.clock拒绝保持，不改成成功或false来掩盖失败，已消费证明不恢复。会话服务内部时钟失败按会话依赖边界归类，不能据此推断其底层根因。

没有修改SQL格式、核心源码、恢复流程或默认预算。SessionDeviceAuthority三个公开方法的反射签名与本批修改前一致。兼容变化为绑定改变时更严格拒绝，以及直接调用者不能依赖原始异常类型、详情或异常链。

## 证据与测试范围

- 修复前两个绑定反例、六个会话／身份／时钟异常反例失败，正常对照通过；补充两个CSRF存储异常反例也失败。原始日志保留。
- 初步四版40项定向检查通过，但该阶段尚未包含最后的CSRF异常边界，不作为最终源码验证。
- 最终PHP8.2、8.3、8.4、8.5独立归档消费者143/143步骤通过，包含每版11个新场景、原授权期限／CSRF倒退及普通组件检查。核心与适配器均非软链接安装，实际vendor来源及全部运行时源码摘要校验通过，消费者已清理。仅按可选包声明的8.2—8.5范围验证，不声称适配器支持7.2。
- 针对修改类及接口的PHPStan检查通过；三个公开方法反射契约一致。新测试接入原消费者入口与非暂缓入口；原全量入口包含恢复套件，本轮没有执行。
- 本轮没有SQL实现变更，未重复上轮已通过的私有MySQL设备场景；本轮SQLite普通删除及会话授权组合由消费者执行。未进行浏览器／实体设备或外部宿主验收。

## 剩余关口

本修复不关闭核心默认MySQL凭据预算失败、PHP7.2不稳定失败、完整候选核对或外部验收。最终恢复启用、跨安全代际交接、未知结果续办及依赖F01仍暂缓，goal保持active。未提交、推送、部署或访问生产数据库。

[汇总](webauthn-authority-binding-evidence-2026-10-23/summary.json)、[修复前结果](webauthn-authority-binding-evidence-2026-10-23/before.json)、[本批源码差异](webauthn-authority-binding-evidence-2026-10-23/runtime.patch)、[最终消费者](webauthn-authority-binding-evidence-2026-10-23/final-consumer/result.json)、[最终静态检查](webauthn-authority-binding-evidence-2026-10-23/static-final.log)、[公开签名](webauthn-authority-binding-evidence-2026-10-23/signatures-current.json)。
