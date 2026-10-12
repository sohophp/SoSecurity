# 受限外部 HTTP 请求

`Http\Outbound\Client` 在每次请求/每次重定向检查URI、精确主机/端口、全部最终A/AAAA地址，绑定一个已经检查的IP后连接，保持Host/SNI及TLS验证。默认不使用环境代理、netrc、Cookie或自动重定向。依据 [OWASP SSRF 指南](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) 与 [cURL CURLOPT_RESOLVE](https://curl.se/libcurl/c/CURLOPT_RESOLVE.html)；不能把“验证URL一次”当永久安全。

## 最小调用

```php
require 'vendor/autoload.php';
$client = new SoSecurity\Http\Outbound\Client(new SoSecurity\Http\Outbound\Policy([
    'hosts' => ['api.example.com'],
]));
try {
    $response = $client->request('GET', 'https://api.example.com/public/status', ['Accept' => 'application/json']);
    $status = $response->status(); $body = $response->body();
    // 宿主按业务检查状态/内容，输出或日志前处理敏感数据。
} catch (SoSecurity\Exception\ValidationException $e) {
    // 目标/输入不符合策略，不能直接用另一客户端绕过后继续请求。
} catch (SoSecurity\Exception\SecurityException $e) {
    // DNS、TLS、连接、响应或预算故障，结束本次操作。
}
```

工厂也可用：

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'shop', 'outbound' => ['hosts' => ['api.example.com'], 'response_bytes' => 1048576],
]);
$client = $security->outbound();
```

工厂创建时不连接外部网络；outbound未配置不影响其他模块。默认客户端需ext-curl及libcurl>=7.57；PHP7.2代码兼容不表示任意古老cURL都具备同样安全选项。TLS验证始终开启，最低TLS1.2，没有关闭证书验证的配置。CA来源是宿主cURL配置，不自动安装证书或修改系统信任库。

## 策略默认值

| 项 | 默认 | 限制与单位 |
| --- | --- | --- |
| hosts | 必填 | 1–64个精确ASCII FQDN或正规IP；无`*`或后缀匹配，localhost等特殊来源拒绝 |
| ports | [443] | 1–16个整数端口，1–65535 |
| allow_http | false | 明确true才允许HTTP，仍要批准相应端口；只适合明确评估的非敏感数据 |
| budget_ms | 5000 | 1–30000毫秒，DNS/全部跳转/连接/传输共用实时预算 |
| redirects | 3 | 0–5；额外跳转超过即拒绝，0不自动跟随 |
| request_bytes | 65536 | POST body最多0–1MiB；GET/HEAD不能有body |
| response_bytes | 1048576 | 0–20MiB，全部跳转累计的已解压响应body；HEAD可设0 |
| header_bytes | 16384 | 256–65536，全部跳转累计；传输还在读取时限制原始头字节 |
| resolver/transport | 默认实现 | 工厂可注入服务名称，必须满足Resolver/Transport接口与有界安全契约 |

URL/Location最多2048字节，明确HTTP(S)、ASCII域名/正规IPv4/IPv6、合法端口；拒绝userinfo、尾点、旧十进制/八进制/十六进制IP缩写、zone ID、反斜杠和控制字符。国际化域名需要可信IDNA转换。路径点段规范化，保留查询串顺序；cURL按已经检查的路径发送。初始URL不接收fragment，重定向fragment移除后继续检查；相对/协议相对重定向按原URI解析后仍须通过目标策略。

主机白名单不是业务路径授权：宿主还要控制允许访问的路由、查询、请求内容与凭据用途。不能把用户提供的任意URL/Host/头原样放进公开代理。

## DNS 与地址绑定

为避免原生阻塞DNS查询脱离总预算，默认使用显式Google兼容JSON DoH实现：固定HTTPS dns.google/resolve，bootstrap IP8.8.8.8，TLS身份校验与响应大小/时间限制。查询A和AAAA，验证Question、最终CNAME链（最多8层）、最多64记录/16最终地址，不把客户端验证后交给另一个未检查的DNS解析。DNS名称会发送给该服务；默认使用0.0.0.0/0 EDNS子网，仍需要运营者评估第三方DNS隐私/可用性。协议说明见 [Google JSON DoH](https://developers.google.com/speed/public-dns/docs/doh/json)。

可显式构造DohResolver指定经过审核的HTTPS JSON端点及公开bootstrap IP，或注入有界企业解析适配器；不自动读取OS DNS、服务密码或未知环境代理。DNS故障没有降级到不受预算控制的系统查询。

全部解析地址都必须通过保守地址检查，一条内网结果也拒绝；每跳重新解析，不因主机已出现就省略。IPv4排除回环、私网、链路本地/元数据、共享地址、文档/基准/协议保留、组播等范围；IPv6仅接受2000::/3中的普通全球单播并排除相关特殊网段，阻止mapped IPv4、NAT64、6to4、Teredo等转换/保留范围。基线来源：[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)、[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/)。部分全球可路由但特殊的地址也会保守拒绝，范围会随发布维护。

选择第一条已批准地址，不自动重试其他地址。每跳使用全新cURL句柄和CURLOPT_RESOLVE，禁用代理/自动跳转，验证实际PRIMARY_IP与pin一致。URL本身是IP时不能与pin不一致；不会通过一个公开pin访问另一条URI私有字面量。安全地址字节分类不能证明部署的真实路由/透明代理拓扑，基础设施还须配置出口限制。

## 请求、重定向与故障

方法只支持GET/HEAD/POST。应用头最多32个/8192字节，禁止控制字节、重复大小写字段、Host/Cookie/代理或Forwarded转发头、Content-Length/Transfer-Encoding/Connection/Expect/Accept-Encoding等保留项。库生成自己的Host及传输头，不承接宿主Session Cookie。

只自动跟随GET/HEAD的301/302/303/307/308；POST收到这些状态抛http.redirect_method，已经发出的POST可能已产生业务效果，不能把异常当作业务未执行并盲目重试。HTTPS不降级HTTP；循环、多个Location、超跳数和累计预算超限拒绝。跨来源时丢弃全部应用头/凭据；同来源保留。重定向链每跳重新做白名单、地址与pin检查。

响应body在读取/解压时截断拒绝，头在回调时计数，格式错误或旧折行头拒绝，不把trailers当Location。得到Response仅表示受限请求完成，4xx/5xx仍是实际服务状态，业务需处理；不能把它当认证或内容安全验证。不要把远端body/headers直接当HTML或同源响应转发。

正常输入拒绝为ValidationException（url.*、http.target/address/downgrade/request/request_headers）；依赖缺失为DependencyException(dependency.curl)；运行故障为RequestException(SecurityException)，包括http.timeout/dns/transport/peer/response_limit/header_limit/redirect*。异常信息/previous不用于公共响应，稳定reason可分类；不包含URL秘密或外部响应正文。

## 替换适配与验证边界

Resolver返回全部最终地址并执行传入Deadline；Transport只连接pin、保留TLS/Host/SNI、禁用代理和自动跳转，并在读取时限制资源。Client在调用前后及每跳检查结果，不接受伪造计数掩盖有界headers/body，但无法抢占任意宿主阻塞代码。自定义适配器能否遵守硬时间/传输契约需要真实验收；diagnose只读检查选择与依赖，网络/自定义契约标记manual，不自动发请求。

默认实现已在独立Linux网络命名空间实际验证：IPv4/IPv6公开地址字节绑定、专用TLS测试CA、真实DoH、TLS失败、DNS变更内网、重定向/凭据隔离、压缩响应/头超限、总超时。不修改宿主路由/证书库；命名空间退出即消失。真实公网固定目标及本机Apache/FPM也另有验证，不把模拟对象当公网成功。

[受控演示](http://72.rocky.wsl/SoSecurity/?module=network)只真实访问固定www.php.net/robots.txt，所有访客共用8次/分钟、3秒/16KiB预算；拒绝场景使用明确标记的测试适配器。没有任意URL/Host输入代理或无限下载。生产旧站、更多cURL/CA/网络环境、Windows及独立安全复核仍待验收。
