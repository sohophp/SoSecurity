# 功能演示

统一入口：[http://72.rocky.wsl/SoSecurity/](http://72.rocky.wsl/SoSecurity/)。该入口为本地开发环境，演示通过 Apache/PHP-FPM PHP7.2运行，不依赖框架。

## 可以实际操作的内容

| 页面 | 演示内容 |
| --- | --- |
| 配置与诊断 | 工厂初始化、只读检查、配置拼错、策略不可变、隔离存储故障和文件锁超时 |
| 验证码 | 加减乘除/图片算术/数字/字母图片、滑块/顺序点选，正确/错误答案，错误次数耗尽，成功后重放，刷新撤销和过期 |
| CSRF | 生成、普通验证、篡改、跨场景、单次消费、重放、撤销和过期 |
| 限流与封禁 | 3次额度、5秒/15秒阶梯封禁、人工临时/永久封禁、解除和剩余等待时间 |
| 上传安全 | 原生multipart、JPEG/PNG私有保存、正常/伪装/大小/路径/图片预算、隔离扫描与目录故障；当前访客清理 |
| 输入验证 | 严格类型、Unicode长度、枚举、格式、嵌套字段与本地化错误；正常/错误/未知字段及可编辑JSON |
| 密码安全 | bcrypt哈希及验证、长度/编码策略、显式已知MD5格式迁移 |
| 重置令牌 | 单次消费、重复消费、密码版本变更后旧令牌失效 |
| 会话安全 | Session ID更新（只显示摘要指纹）、空闲/绝对过期和显式失效 |
| HTTP与代理 | 可信CIDR、代理链、Report-Only/Cookie、跳转白名单、CORS预检、Permissions-Policy |
| 富文本HTML清理 | 基础排版/攻击输入/协议链接源码、树/大小拒绝、固定服务故障、sandbox预览 |
| 无状态CSRF | 签名与真实Cookie双重提交、登录/场景绑定、可重用/期限、密钥轮换、精确豁免预览 |
| API凭据与签名 | 测试凭据签发/轮换/撤销/权限/访客隔离；内部签名、篡改/重放/过期/Nonce故障 |
| 受限外部请求 | 固定公网目标真实HTTPS/DoH/pin；隔离内网、重定向、DNS变更、peer和响应超限拒绝 |
| 输出编码 | HTML、JSON数据、URL组件编码；输入作为文本显示 |
| 审计日志 | 结构化记录、字段白名单、主体假名化、清空当前访客日志 |
| 存储与隔离 | Session/文件/测试内存的原子计数、跨请求保存、命名空间隔离；Redis和MySQL配置后可操作 |

页面提供传统表单按钮，以及选择操作后使用的AJAX提交。API片段可在“接入时的核心调用”展开查看；完整初始化和安全边界仍参考usage.md。AJAX返回HTTP状态与当前结果，不会把请求输入当作HTML执行。

“模拟过期”通过当前访客专用的Clock推进时间，实际调用核心验证器；不会修改系统时间，也不将时钟模拟冒充等待真实时间的环境测试。验证码/CSRF演示有效期30秒，重置令牌120秒；也可以正常等待后验证。

限流页使用持锁Session，人工永久封禁只影响当前访客，不留下无限期文件记录。入口另有共享文件按真实REMOTE_ADDR的100次/60秒总预算，防止换Session绕过入口预算。真正跨Session业务限流应使用文件/Redis等共享后端，不能照抄互动页的Session选型。

只输入测试数据，不使用生产密码。密码明文不保存、不回填；原始Session ID不显示；日志只保存在当前访客Session、最多20条。这里不访问真实用户数据库，不执行真实找回密码或发送邮件。

## 本地入口映射

实际仓库是 `/var/www/php/7.2/soSecurity`；Linux区分大小写，演示入口采用独立链接：

```text
/var/www/php/7.2/SoSecurity -> /var/www/php/7.2/soSecurity/demo/public
```

只将demo/public作为公开目录。仓库根.htaccess拒绝HTTP访问，demo/public单独放行；已验证.git、Composer、demo/app.php等源码路径返回403。PHP内部require仍可加载库。不要将整个仓库作为不受保护的公开目录。

私有文件存储是 `/var/lib/sosecurity-demo`，由实际PHP-FPM用户apache拥有，权限0700，位于Web根目录之外。设置 `SOSECURITY_DEMO_STORAGE` 可替换该路径；设置必须传入实际PHP-FPM环境，不能假定终端环境变量自动传给服务。

清理只对演示私有目录操作，保留永久锁文件：

```sh
sudo -u apache php72 /var/www/php/7.2/soSecurity/bin/demo-cleanup.php
```

按访问规模定期运行；本次没有新增系统级定时任务。演示HTTP连接下Cookie为HttpOnly/SameSite=Lax，路径限定当前入口；HTTPS访问时启用Secure，不自动信任转发头判断HTTPS。当前验证入口是HTTP，没有证明HTTPS及证书信任已完成验收。

## 可选服务

- `SOSECURITY_DEMO_REDIS_SOCKET`：配置独立可连接的本地Redis UNIX socket后，存储页增加Redis选项。未配置则标记“未执行”；默认不连接宿主已有Redis。
- `SOSECURITY_DEMO_TURNSTILE_SITE_KEY` 与 `SOSECURITY_DEMO_TURNSTILE_SECRET`：同时配置后显示真实widget，后端调用Siteverify。
- `SOSECURITY_DEMO_TURNSTILE_HOST`：固定的预期hostname，默认72.rocky.wsl；widget action固定demo。应确认服务是否支持配置的本地域名，不能关闭hostname/action校验来让演示显示通过。

密钥只在服务端配置，不通过演示表单保存。没有实际配置与服务响应前，不把外部能力标记为已验收。当前MySQL已接入存储页，输入验证有独立页面；API签名已提供固定内部测试页面，真实HTTP及独立签名互操作见api.md。

## 自动化与浏览器验收

```sh
python3 tests/demo.py php72
python3 tests/demo.py php85
# 只对明确指定的演示入口执行测试数据操作：
python3 tests/demo.py --url http://72.rocky.wsl/SoSecurity/
```

每次本地测试启动独立PHP服务器、临时存储和Session目录；未配置外部服务时验证明确拒绝。当前83项基础断言之外，已增加畸形action数组拒绝检查（共84项）。演示测试已纳入bin/check.sh和全目标版本CI执行路径。

当前本机真实Chromium验证通过：AJAX生成/正常验证/拒绝、输出输入不执行脚本、移动宽度无页面横向溢出和无脚本异常。桌面/手机截图已检查。库之前的“未执行真实浏览器/PHP-FPM”记录仍代表此前基础里程碑；本次演示增加的验收不等于生产旧站、真实Turnstile或独立安全审计完成。

配置与加固演示新增后，演示HTTP验收现为95项断言；源码阶段的完整进度见execution-status.md。

## 私有 MySQL 演示库

本机已启动独立MySQL8.0.46演示实例，仅绑定 `/var/lib/sosecurity-demo-mysql/mysql.sock`，无TCP/mysqlx监听，不接触现有网站MySQL。私有数据目录由apache拥有且0700；应用配置 `/var/lib/sosecurity-demo/mysql.php` 为0600，返回固定UNIX socket DSN和独立随机密码。应用账号仅有演示表DML权限，Web页面不能建表、改连接或输入SQL。

存储页选择“MySQL（私有演示库）”，支持真实递增、跨请求读取与命名空间隔离；同名逻辑键按访客服务器绑定分别隔离。记录60秒过期，每次MySQL演示操作最多清理100条，入口共享预算仍有效。未配置时不显示选项且直接请求该后端返回503；配置存在但连接失败时也真实返回故障，不切换到内存假装成功。

仅在这个本地演示环境中使用以下命令；脚本要求空目录或自己的专用标记，拒绝普通已有数据目录：

```sh
sudo install -d -m 0700 -o apache -g apache /var/lib/sosecurity-demo-mysql
sudo -u apache python3 /var/www/php/7.2/soSecurity/bin/demo-mysql.py start
# 停止独立演示实例，保留演示数据供下次启动；不会停止宿主MySQL：
sudo -u apache python3 /var/www/php/7.2/soSecurity/bin/demo-mysql.py stop
```

该脚本针对本机MySQL8.0/Python3.6+；私有实例初始化使用本地无密码root，再创建演示DML账号，不适合作为生产数据库部署脚本。脚本不新增systemd服务/定时任务；WSL或机器重启后需显式start。PHP7.2认证兼容边界见mysql.md。不要复制演示凭据到生产站点。

Redis演示命名空间是demo-storage与demo-storage-other，需要提前在可信CLI中分别initialize；不要在HTTP handler自动初始化。重启恢复见redis-recovery.md。

本阶段隔离HTTP演示测试为108项，实际入口含MySQL为110项。可选Chromium验收脚本 `tests/browser.cjs` 使用已安装的Playwright，不为PHP核心引入Node依赖：

```sh
SOSECURITY_PLAYWRIGHT_MODULE=/absolute/path/to/playwright node tests/browser.cjs http://72.rocky.wsl/SoSecurity/
```

已实际验证新增验证页AJAX/422/本地化、HTML字符串不执行、MySQL真实计数/命名空间/访客隔离及390像素手机宽度。脚本只在MySQL已配置时验收该后端，否则明确输出未执行。

## 上传演示与清理

上传页面使用真实组件和原生multipart。单个JPEG/PNG最多1MiB、100万像素，每访客最多3个；全局最多32个/16MiB，10分钟保留。私有payload在 `/var/lib/sosecurity-demo/uploads`，0700目录/0600文件；没有公开下载或执行路由，页面不返回绝对路径。Apache入口声明2MiB请求体限制；本机旧版proxy_fcgi实测未执行普通LimitRequestBody，已用mod_rewrite在请求头阶段拒绝超限（413）及chunked/无长度POST（411），不更改其他网站限制。浏览器表单和FormData使用已知长度。

“我的文件”与清理范围来自服务器Session记录，不接受文件名/目录请求参数。全局容量检查与过期清理受300ms有界锁保护，不通过换Session绕过整体容量。CLI `bin/demo-cleanup.php` 同时清理过期payload，保留静态锁；不删除私有MySQL配置或数据库。已保存文件只在成功写入后登记。

固定故障按钮使用私有测试源或隔离目录，不清空共享存储，也不连接真实恶意文件扫描服务。MIME/重编码通过不能等同于AV通过；状态明确标记未配置真实扫描服务。

```sh
python3 tests/upload_demo.py php72
python3 tests/upload_demo.py php85
python3 tests/upload_demo.py --url http://72.rocky.wsl/SoSecurity/
python3 tests/upload_http.py php72
```

完整demo.py与upload_demo.py针对实际入口执行时应分开请求窗口，保留100次/60秒入口预算，不能为测试关闭限流。隔离服务器各用自己的私有目录，不共享预算。当前新增页面Chromium已验证实际文件选择/AJAX保存、伪装拒绝、扫描故障和手机宽度；没有把固定测试扫描器当真实AV服务。

## HTTP策略与受控外部请求

http页显示审核后的Location/CORS/权限头，不把表单配置应用到站点。cors.php仅提供固定公开JSON测试数据、GET/OPTIONS，不读取Session或业务；固定Origin由服务端配置，默认http://72.rocky.wsl:3000。真正预检/读权限已由独立前端来源和Chromium验收。

network页真实请求仅限www.php.net/robots.txt，使用Google JSON DoH与公开bootstrap pin；所有访客共用8次/分钟，总预算3秒、响应16KiB，只显示状态/字节/digest。失败测试明确标记隔离适配器，不发送内网请求，不提供任意URL/Host代理。第三方DNS隐私/可用性与自定义适配契约见outbound.md。

```sh
python3 tests/network_demo.py php72
python3 tests/network_demo.py --url http://72.rocky.wsl/SoSecurity/ --live
SOSECURITY_PLAYWRIGHT_MODULE=/path/to/playwright python3 tests/cors_http.py php72 --browser
python3 tests/native_outbound.py php72 php85
```

后一个命令需要Linux sudo/unshare/ip/OpenSSL，使用临时网络命名空间与每进程测试CA，既不修改宿主路由也不安装系统CA。SDK默认实现已在六个本地PHP版本执行真实pin/TLS/DoH/重定向/预算验收；缺失版本仍未验证。

## API 演示

`?module=api` 提供短期 Bearer 凭据与 RFC 9421 有界 HMAC 签名。token 只在签发/轮换结果显示，不进入状态 JSON；输入验证同时检查当前访客归属。HMAC 密钥仅保留在私有服务器 Session，固定示例 URI 不发网络请求。先生成签名，测试篡改，再验证并消费 Nonce，最后重复验证；存储故障用固定独立故障对象，不破坏共享演示存储。所有操作仍通过控制表单 CSRF 和入口预算，分配/消费另有全站 30 次/分钟额度。

核心、默认值、正常拒绝/故障及迁移边界见 [api.md](api.md)。`python3 tests/api_demo.py php72` 是隔离演示，`--url http://72.rocky.wsl/SoSecurity/` 验证实际 Apache/FPM 入口；不能把内部网页签名样例当成外部业务客户端验收。

当前主演示测试为117项隔离/119项实际入口，API独立演示24项。对实际入口应按请求窗口分批运行测试；入口100次/分钟及API分配30次/分钟保持启用，不因验收临时降低保护。

## 无状态 CSRF 演示

`?module=stateless` 同步提供实际组件与独立Cookie测试。默认30秒，核心允许有效期内重用；单次消费继续有状态页。密钥轮换只修改本访客服务器Session内测试密钥，身份变更/时间推进仅模拟本访客上下文。所有网页操作仍有控制CSRF；固定豁免预览不应用到真实入口。HTTP入口不等于生产HTTPS；独立TLS/Chromium的__Host/Secure/HttpOnly及同站跨来源攻击证据见 [signed-csrf.md](signed-csrf.md)。

独立演示 `python3 tests/signed_csrf_demo.py php72` 为30项；实际入口使用 `--url http://72.rocky.wsl/SoSecurity/`，按入口请求窗口分批执行，不修改100次/分钟额度。

## HTML 清理演示

`?module=html` 使用独立安装的HTML Purifier 4.19.1，默认严格基础标签/无链接预览，链接策略结果只显示源码。原始输入不执行，sandbox预览没有脚本权限，清理服务故障用固定模拟实现而非破坏真实依赖。每访客仅在Session保存最近一次8KiB输入/16KiB输出用于显示；CSRF和入口100次/分钟保持启用，未配置可选依赖时明确显示未执行并拒绝清理。

依赖安装、预算/渲染边界和浏览器六组结构变异XSS检查见 [html-cleaning.md](html-cleaning.md)。`python3 tests/html_demo.py php72` 为19项隔离检查；实际入口用--url，--browser另调用已安装Playwright，不给核心包增加Node依赖。

最新主演示为123项隔离/125项实际入口；HTML独立19项，真实浏览器检查另行记录。

## 扩展验证码演示

[验证码页](http://72.rocky.wsl/SoSecurity/?module=captcha)新增本地类型、可缩放滑块、键盘顺序点选、重新选择和AJAX切换。第三方增加hCaptcha及reCAPTCHA v2/v3；环境变量、固定hostname/sitekey/action、评分和SDK隔离规则见[验证码指南](captcha.md)。未配置仍返回503；本地挑战复用过期/错误次数/一次消费及场景绑定。独立HTTP检查 `python3 tests/captcha-demo.py php72`，可选现有Playwright运行 `node tests/captcha-browser.cjs`；原生传输故障通过隔离网络/挂载/TLS检查 `python3 tests/native_captcha.py php72 php85`，不修改宿主hosts。
