# 反向代理与 WAF 接入

本指南用于把 SoSecurity 接到已有的 CDN、负载均衡器、Nginx、Apache 或 Web 应用防火墙（WAF）。组件不配置网络入口，也不自动信任代理头。先画出实际请求路径，标出每一跳的来源地址、TLS 终止点、转发头处理者和 PHP 收到的 `REMOTE_ADDR`；只有控制这些边界后，才能把客户端地址用于预算、审计或访问规则。

## 入口与客户端地址

1. 在网络层限制 PHP／源站只能由预期代理访问。为健康检查、内部调用保留的直达路径要有单独的身份与预算策略；不能让公网绕过 WAF 直连同一业务入口。
2. 在最外层受信任入口删除客户端自带的 `X-Forwarded-For`、`Forwarded`、`X-Real-IP`、`X-Forwarded-Proto` 及供应商地址头，再按部署策略写入或追加实际上一跳。多层代理逐跳确认这个规则和允许的来源网段，不把“经过 CDN”当作可信来源证明。
3. 选择**一处**解析真实地址。如果 Web 服务器用 Nginx `realip` 或 Apache `mod_remoteip` 改写了 `REMOTE_ADDR`，应用侧的 `ClientIp` 不再解析同一条 `X-Forwarded-For` 链；如果在应用侧解析，则 `REMOTE_ADDR` 应保持实际连接的代理地址，并仅把精确代理 CIDR 交给 `IpRules`。避免两层各自改写后再按错误链条计算一次。
4. `ClientIp` 默认只返回有效的 `REMOTE_ADDR`。仅当这个地址属于显式可信网段时，它才读取 `HTTP_X_FORWARDED_FOR`，从靠近应用的一端向外回溯。链长度上限为 32 跳、文本最多 2048 字节，任一地址格式错误即拒绝；不接受 `Forwarded` 或供应商专属头。若代理没有可靠地覆盖或追加实际上一跳，不应启用应用侧代理信任。

Nginx 的 `set_real_ip_from`／`real_ip_header`／`real_ip_recursive` 和 Apache 的 `RemoteIPHeader`／`RemoteIPTrustedProxy` 应按实际拓扑设置，网段只填受控代理；它们改变 Web 服务器认定的地址，不会替宿主验证业务身份。配置语义以 [Nginx realip 官方文档](https://nginx.org/en/docs/http/ngx_http_realip_module.html)和 [Apache mod_remoteip 官方文档](https://httpd.apache.org/docs/2.4/en/mod/mod_remoteip.html)为准。

## TLS、来源与响应

- 代理负责验证外部 HTTPS，并以受控服务器配置向 PHP 提供实际 HTTPS 状态。SoSecurity 原生示例不会因为请求自带 `X-Forwarded-Proto: https` 就将明文回源视为 HTTPS。固定来源和允许的 Host 由部署配置确定，不从任意 Host／转发头拼接重定向或签名 URL。
- 保留应用发出的 `Set-Cookie`、`Secure`、`HttpOnly`、`SameSite`、`Vary`、`Cache-Control` 和 `Retry-After`；确认代理不会合并多个 `Set-Cookie` 或公开缓存登录、令牌、一次性链接及个性化响应。HSTS 只在全部适用域名的 HTTPS 已验收后由明确的一层发出。
- 对请求体大小、连接数、超时、上传速率和响应缓冲设置基础设施预算，并按上传、Webhook、签名请求、流式下载的真实路径分别验证。代理上限不能替代组件的原始字节、字段或存储读取上限；组件的 429／503 等拒绝也不能被代理改写成业务成功。
- 在 PHP SAPI 合并同名字段前，由可信入口拒绝重复的认证、签名、幂等及互斥分帧头，包括大小写变体。只设置示例的“已验证”服务器属性而未实际检查原始请求，不满足[原生幂等接入契约](idempotency-native.md)。

## WAF 的职责

WAF 可在入口识别通用攻击模式、限制异常流量和协助应急；账号授权、CSRF、签名验真、请求预算、重放保护、Outbox 事务及上传隔离仍在应用或宿主权威层执行。先记录正常业务的请求方法、路径、正文类型、编码和拒绝率，再启用阻断；误报只按具体规则、字段、路径和期限调整，保留复核与撤销记录，避免对登录／管理／上传入口整体关闭检查。OWASP CRS 的[官方调优说明](https://coreruleset.org/docs/)解释了异常分数、阻断阈值和误报调优；具体阈值要依据所用引擎及流量验证。

WAF 日志、代理访问日志和应用审计分别控制权限与保留期。不要记录 Cookie、Authorization、TOTP、恢复码、完整上传内容或原始签名秘密；应用审计的固定结构化事件也不证明 WAF 已落盘或告警。

## 上线前按路径验证

| 测试请求／故障 | 应取得的结果 |
| --- | --- |
| 公网直连源站；从非可信来源伪造代理头 | 源站被网络层拒绝；应用预算／审计地址不采纳伪造值 |
| 经各级代理发送伪造最左侧 IP、畸形／超长链 | 最终地址按受信任上一跳计算，或在格式异常时拒绝 |
| 明文回源加 `X-Forwarded-Proto: https`；错误 Host | 不绕过 HTTPS 与固定来源校验 |
| 重复认证／签名／幂等头、冲突的分帧头 | 在 SAPI 合并之前被可信入口拒绝 |
| 登录／登出、CSRF、上传、Webhook、流式下载 | Cookie 与缓存头保留；WAF 不误伤正常请求；各层大小／超时预算产生预期拒绝 |
| WAF 故障、代理重试或绕行 | 敏感入口仍执行应用认证、授权、幂等和审计；不能因 WAF 放行而跳过它们 |

以上是部署验收步骤，不表示本仓库已配置任何生产代理或 WAF。实际网段、证书、回源隔离、规则版本、误报与运营告警都需由宿主在目标环境验证。
