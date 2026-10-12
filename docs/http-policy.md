# 跳转、CORS 与浏览器权限策略

这些组件不发送响应头、不接管路由或认证，宿主在正确的处理阶段显式使用。新Header默认不自动启用，不改变已有第三方脚本/摄像头等功能。

## 固定来源的跳转

```php
require 'vendor/autoload.php';
$redirects = new SoSecurity\Http\Redirects('https://shop.example', ['https://checkout.example']);
try {
    $location = $redirects->target($_POST['return_to'] ?? '/account');
    // 宿主先完成本次授权和业务，选择合适的303/302等状态。
    header('Location: ' . $location, true, 303);
    return;
} catch (SoSecurity\Exception\ValidationException $e) {
    // 拒绝非法目标，返回稳定url.redirect/url.invalid等原因；不要跟随原输入。
}
```

主来源和附加来源由可信配置给出，禁止从Host/Referer或请求参数生成白名单。仅接收以单个`/`开始的站内路径，或完整HTTP(S) URL；返回规范的绝对Location。协议相对`//evil`、userinfo、反斜杠、控制/编码控制字符、非批准scheme/host/port拒绝。片段可用于站内锚点；普通相对路径`account`需要宿主先改成`/account`。来源匹配包含协议和实际端口，不做主机后缀匹配。

内部路径和额外来源仍需要业务授权；白名单不能替代OAuth精确回调URI或按路由的权限检查。它不会把用户输入目标应用到演示站点，只显示检查后的Location。

## CORS

```php
$cors = new SoSecurity\Http\Cors(
    ['https://client.example'], ['GET', 'POST'], ['content-type', 'x-csrf-token'],
    true, 600, ['retry-after']
);
$decision = $cors->evaluate(
    $_SERVER['REQUEST_METHOD'], $_SERVER['HTTP_ORIGIN'] ?? null,
    $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'] ?? null,
    $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'] ?? null,
    $alreadyConfiguredVary // 没有已有Vary时用空字符串
);
foreach ($decision->headers() as $name => $value) { header($name . ': ' . $value); }
if (!$decision->allowed()) { http_response_code(403); return; }
if ($decision->status() === 204) { http_response_code(204); return; }
// 然后由宿主处理认证、CSRF、方法/路由及业务授权。
```

来源按浏览器规范的完整Origin精确匹配；不接受null、路径、逗号拼接或任意反射来源。配置来源可规范化大小写/默认端口，请求来源必须已经是规范序列。methods默认GET/POST，requestHeaders默认content-type，credentials默认false，maxAge默认600秒（0–86400），exposed默认空。最长64来源、8方法、32头名；预检请求头文本最多2048字节，超限拒绝。

允许公开资源时可以显式origins=`['*']`，但不能同时credentials=true，也不能混合其他来源。header名称不提供`*`通配；Set-Cookie不能被配置为可暴露头。请求头大小写归一为小写，预检校验方法及头名子集，成功返回204。没有Origin的普通请求不属于CORS，allowed不能当路由或认证授权；OPTIONS预检缺Origin拒绝。

Vary保留已有头名并合并Origin；预检再合并Access-Control-Request-Method/Headers。宿主需要把自己的已有Vary传入，避免覆写缓存行为。失败响应不提供Access-Control-Allow-Origin。

CORS控制浏览器读取权限，不能代替CSRF、凭据验证、限流或服务端方法检查。浏览器可能发送一个最后无法读取响应的简单/凭据请求，服务端不能把“没有通过CORS”当业务不会执行的证明。参见 [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)。

## Permissions-Policy

```php
$value = SoSecurity\Http\PermissionsPolicy::build([
    'camera' => [], 'microphone' => [], 'geolocation' => ['self', 'https://maps.example'],
]);
// camera=(), microphone=(), geolocation=(self "https://maps.example")
// 可以单独显式header，也可以传给SecurityHeaders的第四参数：
$headers = SoSecurity\Http\SecurityHeaders::build($csp, true, null, ['camera' => []]);
```

空列表表示不授予该功能，self表示自身来源，明确HTTP(S)来源加引号；仅`['*']`表示全来源，不能混合。最多32功能、每项32来源，结果最多8192字节。功能名只校验有界语法，不承诺所有浏览器支持它；未识别功能可能被浏览器忽略，不作为服务器授权措施。SDK不自动发送旧Feature-Policy，也不自动关闭现有站点能力。

## URL/IP 输入格式与演示

`Validation\Validator`增加string的format=url/ip。url使用共享严格HTTP(S) URI语法，最多2048字节，不接收userinfo/非ASCII主机/原始空格与反斜杠；国际化域名先使用受审核的IDNA转换，路径字符由宿主百分号编码。ip接收正常IPv4/IPv6，不接收CIDR、旧数字缩写、zone ID。**格式有效不代表访问目标安全**；例如正常私有IP作为业务输入可通过format=ip，外部请求还须经过outbound的白名单和地址检查。

[HTTP 演示](http://72.rocky.wsl/SoSecurity/?module=http)包含跳转、CORS预检和权限头。真实静态CORS端点cors.php只读固定公开演示数据，不读取Session/业务账号；默认允许http://72.rocky.wsl:3000，可由可信部署环境设置SOSECURITY_DEMO_CORS_ORIGIN。页面输入只做策略模拟，不动态改变端点的白名单。
