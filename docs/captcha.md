# 多种验证码与第三方适配

[实际演示](http://72.rocky.wsl/SoSecurity/?module=captcha)提供传统表单和AJAX。核心不要求框架，不启动Session、不接管路由。算术不需要GD；所有PNG及交互题图需要 `ext-gd`，第三方默认HTTPS传输需要 `ext-curl`，也可显式传入可信HTTP适配器。

## 选择形式

| 形式 | 调用 | 提交的答案 |
| --- | --- | --- |
| 文字算术 | `arithmetic($scope, $binding, $operation)` | 十进制整数字符串 |
| 混合字符图片 | `image($scope, $binding)` | 图片中的字符，不区分大小写 |
| 纯数字图片 | `imageDigits($scope, $binding, $renderer, $length)` | 字符串，保留前导零 |
| 纯字母图片 | `imageLetters($scope, $binding, $renderer, $length)` | 图片中的字母，不区分大小写 |
| 图片算术 | `imageArithmetic($scope, $binding, $operation, $renderer)` | 十进制整数字符串 |
| 滑块拼图 | `slider($scope, $binding)` | 原图像素中的水平偏移，如 `"137"` |
| 顺序点选 | `click($scope, $binding)` | 按顺序的三个格子编号，如 `"0,4,8"` |
| Cloudflare Turnstile | `Turnstile::verify($token, $clientIp)` | `cf-turnstile-response` |
| hCaptcha | `HCaptcha::verify($token, $clientIp)` | `h-captcha-response` |
| Google reCAPTCHA v2/v3 | `Recaptcha::verify($token, $clientIp)` | `g-recaptcha-response` |

`$operation` 为 `add`、`subtract`、`multiply`、`divide` 或 `mixed`。默认文字算术仍为加法；图片算术默认为随机运算。减法结果非负，除法保证整除，不使用eval或执行题目字符串。图片算术不附带可直接读取的明文算式。字符长度4–8；图片字符集允许8–32个不同的ASCII大写字母/数字，默认混合字符集仍排除容易混淆的0/1/I/O。

## 初始化和生命周期

```php
// 由宿主按自己的会话策略启动Session；不要用用户名或客户端传来的标识作会话绑定。
if (!isset($_SESSION['captcha_binding'])) {
    $_SESSION['captcha_binding'] = bin2hex(random_bytes(32));
}
$binding = $_SESSION['captcha_binding']; // 登录身份改变时由宿主更新绑定
$captcha = new SoSecurity\Captcha\Captcha(
    new SoSecurity\Storage\SessionStore('my-site-captcha'),
    300, // 有效期，秒
    3,   // 每题最多失败次数
    4    // 同场景/绑定同时保留的题目，支持多个标签页
);
$challenge = $captcha->imageDigits('login', $binding);
// POST必须使用固定的业务scope和服务端binding。
$valid = $captcha->verify('login', $binding, $_POST['challenge_id'] ?? null, $_POST['answer'] ?? null);
if (!$valid) { /* 拒绝业务操作 */ }
```

所有本地形式共用同一原子存储路径：场景/绑定隔离、到期拒绝、错误次数耗尽、容量淘汰和成功后一次消费。`revoke($scope, $binding)` 撤销该绑定/场景全部题目；需要刷新替换旧题时先撤销再生成。单纯生成新题会保留容量内的其他题目。SessionStore要求会话锁仍持有；跨进程可选FileStore、RedisStore或MySqlStore，参见[存储配置](configuration.md)。MemoryStore仅用于测试。

存储异常、GD不可用和第三方服务故障都抛异常，由宿主拒绝敏感操作并返回可重试错误；不得catch后当作验证成功。先对生成图片和提交答案两条路由实施[请求限流](usage.md)，验证码错误预算不能限制攻击者持续生成新题。

## 公共数据与前端交互

`Challenge` 仅含 `id`、`prompt`、原始PNG `image`、`expiresAt` 和 `presentation`；不返回答案、摘要或滑块目标坐标。直接JSON编码原始PNG会失败，先转换为数据URI或通过宿主的受限图片接口提供：

```php
$presentation = $challenge->presentation;
if (isset($presentation['piece'])) {
    $presentation['piece'] = 'data:image/png;base64,' . base64_encode($presentation['piece']);
}
$public = [
    'id' => $challenge->id,
    'prompt' => $challenge->prompt,
    'image' => $challenge->image === null ? null : 'data:image/png;base64,' . base64_encode($challenge->image),
    'expires_at' => $challenge->expiresAt,
    'presentation' => $presentation,
];
```

滑块原图300×150，拼图片段40×40。`presentation` 包含 `kind=slider`、宽高、`piece_width`、`piece_y` 和片段PNG。水平提交范围0–260，整数步长1，服务端容差±3原图像素。缩放显示时按原图比例换算，不能直接提交页面CSS像素或百分比；例如鼠标位置 `x * 原图宽度 / 显示宽度` 后取整。客户端提交偏移，不能提交“已经通过”的布尔值。方向键同样可操作。

点选原图300×180，3×3格子，编号按行从0到8，题目要求依次点击三个不同字母。`presentation` 只含格子行列数和数量；没有字母与格子的对应表。客户端从点击位置换算行列，或提供键盘格子按钮，依次拼接编号后提交。重复编号、错误顺序、坐标数组和越界字符串都不会匹配答案。示范DOM、缩放布局、键盘/重新点选及AJAX刷新在 [app.js](../demo/public/app.js) 和 [styles.css](../demo/public/styles.css)；这些是仓库演示资源，Composer发行包不包含demo目录。

验证码图片不应以明文答案作为alt、URL、文件名或隐藏字段。提供文字算术或宿主独立的无障碍流程作为备用方案，并保持同等业务限流策略；不要把图形答案放进读屏标签。

## 第三方最小配置

密钥只能来自可信服务端配置；以下变量由宿主注入，不使用请求参数决定secret、sitekey、hostname、action或阈值。客户端IP应来自已配置可信代理的 `ClientIp`，不能直接信任转发头。

```php
$turnstile = new SoSecurity\Captcha\Turnstile($secret, 'accounts.example.com', 'login');
$hcaptcha = new SoSecurity\Captcha\HCaptcha($secret, $expectedSiteKey);
$v2 = new SoSecurity\Captcha\Recaptcha($secret, 'accounts.example.com');
$v3 = new SoSecurity\Captcha\Recaptcha($secret, 'accounts.example.com', 'login', 0.5);
// 只实例化当前业务选择的服务；示例中的$secret分别来自对应服务配置。
$valid = $hcaptcha->verify($_POST['h-captcha-response'] ?? null, $clientIp);
```

Turnstile要求success为布尔true，hostname/action与可信配置精确相同。[Cloudflare服务端验证规则](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)管理令牌过期和一次使用。

hCaptcha每次将预期sitekey一起发送到固定Siteverify端点，由服务端验证所属挑战。其hostname是浏览器提供的统计字段，可能返回 `not-provided`，不能用来认证；这些边界遵循[hCaptcha官方指南](https://docs.hcaptcha.com/#verify-the-user-response-server-side)。宿主需要区分注册/登录难度时，应分别配置sitekey，而不是仅看客户端给出的场景名字。

reCAPTCHA v2校验success和精确hostname，并拒绝含v3评分/action的响应，避免无意混用两种策略；v3还要求action相同、评分为有限数值且处于阈值至1之间。缺评分、字符串评分、action不符均拒绝。最低评分应根据真实业务观察确定，0.5仅为起始默认值。参考[服务端验证](https://developers.google.com/recaptcha/docs/verify)与[v3规则](https://developers.google.com/recaptcha/docs/v3)。v3应在提交时通过 `grecaptcha.execute(siteKey, {action: 'login'})` 获取令牌；不要页面加载时提前取得后长期保留。v2/v3前端SDK在独立页面加载，hCaptcha设置 `recaptchacompat=off`，避免争用 `grecaptcha` 全局对象。

默认传输仅向固定官方HTTPS地址POST表单，连接3秒/总计8秒超时、响应头/正文各16KiB、无重定向、校验TLS证书/主机、不读取环境代理或netrc。有效字符串令牌必须有界（Turnstile 2048字节，hCaptcha/reCAPTCHA 8192字节）。格式错误返回false；HTTP故障、格式错误响应、非布尔success或超限抛DependencyException。不要记录完整POST载荷/令牌或密钥。可信适配器注入位置分别是Turnstile第四参数、HCaptcha第三参数、Recaptcha第五参数；接收载荷数组，返回有限JSON字符串，必须自己保证同等TLS、固定端点、响应/超时预算和日志脱敏。

## 演示配置与安全边界

环境变量仅在服务器设置：

| 服务 | 必填 | 附加 |
| --- | --- | --- |
| Turnstile | `SOSECURITY_DEMO_TURNSTILE_SECRET` / `_SITE_KEY` | `_HOST`，默认72.rocky.wsl，action固定demo |
| hCaptcha | `SOSECURITY_DEMO_HCAPTCHA_SECRET` / `_SITE_KEY` | sitekey必须属于配置的secret |
| reCAPTCHA v2 | `SOSECURITY_DEMO_RECAPTCHA_SECRET` / `_SITE_KEY` | `_HOST`，默认72.rocky.wsl |
| reCAPTCHA v3 | `SOSECURITY_DEMO_RECAPTCHA_V3_SECRET` / `_SITE_KEY` | `_HOST`，默认72.rocky.wsl，action固定demo，评分0.5 |

演示按配置才加载外部SDK并加入对应CSP来源；未配置返回503，无默认测试密钥。v3在 `?module=captcha&provider=recaptcha_v3` 的独立SDK页面操作。真实服务要求配置允许的域名及可达性；本机HTTP演示并不证明生产HTTPS、真实用户令牌或网络部署已经验收。服务端外部验证每IP另限8次/分钟，共享入口100次/分钟；故障不会切换其他服务放行。

本地文字算术、字符图片、合成滑块和点选属于交互门槛；题图能被图像算法识别，答案空间小，不能承诺阻止自动化或替代登录失败限制。对于高风险业务应结合可信风险策略、限流和合适的第三方验证。OWASP把验证码定位为[认证中的辅助防护](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#captcha)，仍须保护账号、会话和业务授权。

自动检查分别覆盖私有存储生命周期、模拟服务响应契约、原生TLS传输（隔离网络/挂载/测试CA）、HTTP拒绝路径、并发消费及实际Chromium公共题图求解。官方hCaptcha公开测试密钥仅用于开发时验证真实HTTPS成功/拒绝，不具备反机器人能力，也没有配置到演示站。
