# 0.1 基础候选验证记录

日期：2026-10-13。交付性质：**本地 0.1.0-dev 候选里程碑**，不是GitHub/Packagist正式发布，也不是独立安全审计。最初本地目录及公开GitHub仓库为空，本次没有覆盖宿主网站代码或连接生产数据。

## 已执行并通过

| PHP 运行时 | 功能/边界断言 | Session 集成 | 文件24进程并发 | Redis真实驱动及24进程并发 | 真实HTTP登录 |
| --- | --- | --- | --- | --- | --- |
| 7.2.34 | 13组，184断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 7.4.33 | 13组，184断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 8.1.34 | 13组，186断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 8.2.32 | 13组，186断言 | 19断言 | 通过 | **未执行：本机缺ext-redis** | 20断言 |
| 8.4.23 | 13组，186断言 | 19断言 | 通过 | **未执行：本机缺ext-redis** | 20断言 |
| 8.5.9 | 13组，186断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |

每个可用运行时均检查38个PHP文件的语法。Argon2id是否可用影响功能断言数量；不可用时验证明确拒绝该配置，不降级。Redis实例只监听新建私有UNIX socket，TCP关闭，无生产实例连接。文件并发也使用新建0700临时目录。

并发情形每个启动24个独立PHP进程：5次额度只成功5次，单次CSRF只成功1次，验证码只成功1次。不是仅顺序循环模拟并发。

HTTP测试通过隔离PHP内置服务器与真实CookieJar执行：跨Session令牌拒绝、数组字段拒绝、多标签页、正确/错误密码、验证码重放拒绝、登录Session ID变化、请求预算429/Retry-After、非允许方法405、存储权限异常503。没有打开真实浏览器，也没有证明生产PHP-FPM/Nginx/代理的行为。

其他验证：

- PHP7.2及PHP8.5独立消费者通过Composer路径仓库真实安装、PSR-4自动加载和公开API调用。
- 核心composer.json与开发工具composer.json通过严格格式检查。核心没有第三方运行时依赖，依赖审计没有可扫描的运行时包；独立开发工具PHPStan 2.3.1的Composer漏洞公告检查未发现公告。
- PHPStan level5、目标PHP7.2，核心src无错误；无忽略基线。工具实际在PHP8.1运行。早期PHP8.5工具尝试加载Turbo因本机glibc太旧发出警告，随后采用PHP8.1运行并通过；这不是核心运行时问题。
- `composer archive`内容检查通过：排除vendor、tools、tests、CI、缓存、私有配置文件名及lock；保留Composer元数据、源码、许可证和使用文档。
- GitHub工作流YAML语法解析通过；Action使用检查时解析到的固定提交SHA。
- 内部审查检查原子生命周期、代理链、密码截断/降级、会话超时和故障策略；不是独立审计结论。

## 已执行但初次失败，现已修复并复测

- 老版phpredis无前缀时返回null，新版/配置可能返回空字符串；适配器明确接受两种无前缀返回，不接受实际前缀。
- 关闭Redis客户端不总能模拟服务故障，旧扩展会重连；测试改成隔离socket不可达并恢复，验证异常拒绝业务。
- Redis错误数据类型GET失败时不能当缺失记录；检查协议错误并抛StorageException，已有回归测试。
- 发布压缩包最初包含本地vendor；显式Composer/Git导出排除规则修复，压缩包内容检查已通过。

## 未执行与发布前验收

- PHP7.3、8.0、8.3本地没有运行时，**未执行**。完整7.2–8.5 GitHub CI已定义，**未在GitHub实际运行**；CI运行前不宣称完整版本矩阵验证通过。
- PHP8.2/8.4 Redis驱动本地未执行，CI要求扩展齐全且缺失则失败。
- 真实Cloudflare Turnstile网络/widget验证未执行；本次只验证适配器响应绑定和异常路径，不将模拟传输结果当成第三方服务验收。
- 真实浏览器、PHP-FPM/Apache/Nginx、HTTPS及可信代理链、旧站认证业务验收未执行。
- 独立安全审计、ASVS逐项验收、负载/持久性故障测试未执行。24进程正确性测试不替代生产容量评估。
- GitHub推送、标签、Packagist注册及正式Composer公开安装未执行。当前仅本地提交与路径仓库安装。
- Docker安装可见，但守护进程不可连接；本次使用现有原生CLI运行时，没有通过容器补齐缺失版本。

下一里程碑依照roadmap.md推进PDO MySQL存储、输入验证和上传能力；先补齐上述发布前验收，再将候选声明为稳定可公开发布版本。

## 复现

```sh
composer install
bin/check.sh php72
bin/check.sh php74
bin/check.sh php81
bin/check.sh php82
bin/check.sh php84
bin/check.sh php85
python3 tests/install.py php72 /path/to/composer
python3 tests/install.py php85 /path/to/composer
python3 tests/archive.py php72 /path/to/composer
php81 /path/to/composer install --working-dir=tools
php81 tools/vendor/bin/phpstan analyse -c phpstan.neon --no-progress
php81 /path/to/composer audit --working-dir=tools --locked
```

## 互动演示追加验收（2026-10-13）

基础里程碑后增加demo/public公开入口和源码目录保护。PHP7.2、PHP8.5隔离演示服务器的HTTP验收通过；最终演示测试84项断言，涵盖十类能力、JSON/表单、畸形操作字段、跨访客隔离、过期和重放。

实际 `http://72.rocky.wsl/SoSecurity/` 在Apache/PHP-FPM PHP7.2上HTTP验收通过。真实Chromium验证AJAX生成/正常验证/篡改拒绝、输入不执行脚本、移动宽度无页面横向溢出、无脚本异常；桌面和手机截图已检查。

`.git/HEAD`、composer.json、demo/app.php、src、tests、bin和tools等仓库路径拒绝HTTP访问；演示首页及静态资源正常。私有数据位于Web根之外；只有demo/public映射为大小写明确的入口。原有基础里程碑的“未执行浏览器/PHP-FPM”是此前状态，此次追加不代表真实旧站生产业务已验收。

演示Redis和Turnstile未配置，真实外部服务未执行；页面不宣称通过。上传、MySQL、SSRF等后续功能仍未实现。部署和复现见demo.md。

## 核心加固与配置候选追加验收（2026-10-13）

Policy/Change不可变、稳定异常reason、有界文件锁、分批清理、状态编码预算、Redis原子Lua CAS和网络等待预算已实现。工厂、只读诊断、Session原有Cookie策略保留和宿主重置版本比较已加入源码与演示。

- PHP7.2与PHP8.5功能回归通过；加固29项、配置/诊断33项、Session24项、宿主SQL重置16项；演示现为95项。
- Redis真实冲突、网络暂停、内存耗尽和诊断/配置变更测试已加入；保留原有24进程并发。Redis重启恢复边界尚待完成，不能据此宣称恢复后仍满足全部保护状态保证。
- 两个PHP版本在独立16KiB tmpfs上实际验证ENOSPC写入失败与原记录保留，各4项；测试结束卸载并移除临时挂载点，不填满共享磁盘。
- PHP8.5实际限制独立测试进程文件大小，验证OS部分写失败4项；PHP7.2缺POSIX扩展，此项未执行，不能当作通过。
- CLI只读诊断退出状态及无状态文件写入已验证；PHPStan level5/目标PHP7.2通过。
- 当前Web入口上的配置/诊断与故障页面HTTP测试通过，真实Chromium已验证工厂成功、配置拒绝、隔离锁超时、移动布局且无脚本异常。

完整目标仍进行中，逐项剩余工作见execution-status.md。

## MySQL、输入验证与Redis恢复追加验收（2026-10-13）

本段是上述历史里程碑之后的最新状态；已实现MySQL与输入验证，不能继续按旧段落的“尚未实现”解读。

已执行并通过：

- `bin/check.sh` 在PHP7.2.34、7.4.33、8.1.34、8.2.32、8.4.23、8.5.9上执行；13套基础测试分别184/186项，Session24、加固29、宿主SQLite重置16、HTTP20和隔离演示108。本阶段追加单项复测：配置/诊断39、输入验证52、MySQL41，六个运行时均通过相关已执行检查。
- 独立MySQL8.0.46无TCP实例：驱动契约、namespace隔离、TTL、损坏/超大载荷、索引/引擎、过期清理、真实默认1秒锁等待、PDO错误模式/会话锁等待恢复、宿主事务不提交/不回滚、真实断连接提交失败拒绝。每次只操作独立测试库。
- MySQL24进程分别竞争限流/CSRF/验证码，精确放行5/1/1；24进程使用4个重置令牌，业务账号密码版本只更新一次。竞争测试显式采用5秒锁等待，不代表默认1秒能承受相同磁盘吞吐。
- MySQL隔离生命周期脚本在PHP8.5实际完成创建/运行/停止/删除；现有网站MySQL未修改。PHP7.2兼容测试账号只在独立实例使用mysql_native_password。
- PHP7.2/7.4/8.1/8.5执行Redis30项驱动集成、24进程竞争和真实旧快照重启：seed1/consume1/reject6项，显式审核恢复后旧令牌仍拒绝。ready/run_id/epoch与Lua内复核已实现；没有宣称恢复所有计数或封禁。
- PHP8.1/8.5 OS部分写故障各4项通过；测试改为输出经管道的子进程，文件大小限制不再连带破坏调用者重定向日志。PHP8.1最初重定向测试失败已修复并复测。
- 实际Apache/PHP-FPM7.2入口演示110项通过，含真实私有MySQL计数/隔离。新增验证与存储页面Chromium手机宽度390px：AJAX正常/422/未知字段、中文错误定位、HTML测试字符串不执行、真实MySQL计数/namespace/陌生访客隔离、无脚本异常及无页面横向溢出。截图已检查。
- PHP7.2/8.5各67个PHP文件语法检查通过；PHPStan level5/目标70200通过；Composer validate严格模式通过。两个运行时新消费者安装和归档验证通过，SQL与验证类实际随包交付；69个包文件不含demo/bin/tests/tools/vendor/private配置。
- 开发工具锁定依赖的Composer审计通过，没有漏洞公告。核心没有第三方运行时包，Composer2.10.2直接audit空锁文件返回非零“No installed packages”，不计为审计通过；CI现显式区分空依赖不适用与存在依赖需审计，不能吞掉真实审计失败。
- 新的SQL资源和演示数据库脚本HTTP路径返回403，私有配置/数据在Web根之外；演示MySQL无TCP监听、应用仅演示表DML权限。

已执行但初次失败，现已修复并复测：MySQL初始1秒竞争等待超时（保留默认拒绝并明确竞争验收5秒）；独立实例初始化45秒超时（有界延长并减少测试实例内存/日志资源，完整生命周期后通过）；apache环境Python3.6不支持capture_output参数（演示管理脚本兼容改正）；配置可选数值null不能作为默认值，新增拒绝检查；上述日志大小限制问题。

未执行/不能宣称：PHP7.3/8.0/8.3实际运行；PHP8.2/8.4 Redis（本机缺扩展）；PHP7.2/7.4/8.2/8.4 POSIX部分写故障（本机缺扩展）；MySQL5.7/8.4/MariaDB/更多客户端；Windows；真实Turnstile、HTTPS部署、生产旧站、独立审计、GitHub CI运行及公开发布。新的CI定义仍不等于远端执行。

演示私有MySQL实例为可操作页面保留运行，管理/停止命令见demo.md；临时测试实例与它互不共享。完整计划仍在执行，上传、HTTP/API和发布验收继续按next-steps.md推进。

## 上传阶段追加验收（2026-10-13）

已执行并通过：

- 本机PHP7.2.34/7.4.33/8.1.34/8.2.32/8.4.23/8.5.9：上传83项检查，PHP7.2另有旧WebP无私有临时目录拒绝检查（84项）；实际原生multipart20项、隔离上传演示32项。配置/诊断39项仍通过。
- JPEG/PNG/WebP实际GD解码及重新编码，扩展/MIME匹配、恶意复合文件名、符号链接/流包装器、截断图片、巨大PNG头、源/编码大小与工作预算、扫描拒绝/故障、私有权限与factory/diagnose、可复用管理器调用。原始附加PHP测试片段不进入重编码结果；源在扫描阶段改变时保存仍使用已经验证的快照。
- PHP7.2 WebP最初有效样例解码失败，证实该版本字符串API缺此能力；专用私有临时快照路径修复并复测，不使用远程/数据URL，不重读原始源。PHP8.5首次测试的imagedestroy废弃警告已修复为仅销毁旧版资源。
- 24进程并发上传：24个独立随机文件，逐文件确认0600和PNG MIME，不覆盖源或其他文件。PHP7.2/8.5执行；同时保持文件/Redis/MySQL原有限流与单次令牌竞争。本阶段bin/check.sh两版本均执行通过，PHP7.2的最新WebP/拒绝分支另行单项复测通过。
- 独立16KiB tmpfs真实ENOSPC：PHP7.2/8.5各7项，含上传拒绝、不完整文件清理和旧文件hash保留。测试新增空专用目录/小文件系统护栏，拒绝指向普通磁盘。PHP8.5 POSIX部分写故障7项通过；PHP7.2缺POSIX，未执行该种部分写测试。
- PHP7.2/8.5 `-n`缺fileinfo时各1项依赖拒绝；仅加载fileinfo而缺GD时各2项，图片拒绝且显式txt可用。没有把跳过GD图片检查当成功。
- 实际Apache/FPM7.2入口：整体演示113项，上传专页31项（正常multipart/CSRF/访客/额度/故障28项加前置请求长度3项）。Chromium验证文件选择与AJAX真实保存、固定正常样例、伪装/扫描故障拒绝、390像素手机宽度和无脚本异常，截图已检查。
- Apache2.4.37/proxy_fcgi初次实测普通LimitRequestBody未按预期阻止大请求，已在演示.htaccess加入请求头阶段规则；只发送超过2MiB的Content-Length头、尚未发送body时收到413；chunked及无长度POST为411。正常FormData与表单继续通过，不修改其他网站配置。PHP内的事后大小检查不能冒充该前置控制。
- CLI清理实际执行，过期安全记录与payload分别有界清理；隔离演示通过修改自己的测试文件mtime验证保留到期后的删除，访客清理只作用于自身记录。未配置真实AV，扫描按钮清楚标记测试实现。
- PHP7.2/8.5语法检查78个文件、PHPStan level5/目标70200、Composer严格校验、两个运行时消费者安装和77文件归档检查通过；开发工具Composer审计没有漏洞公告。Source/Upload及demo/uploads.php HTTP路径403。

未执行：真实扫描服务及恶意样本独立验收、PDF内容重建、Windows ACL/网络文件系统、更多GD构建、缺失PHP7.3/8.0/8.3、生产宿主/HTTPS/独立审计。SDK没有宣称PDF语义解析或所有文件无恶意，不自动公开下载/内嵌执行，宿主仍负责授权/CSRF/请求与总容量预算/保留和安全下载。

完整目标仍进行中：下一阶段按next-steps.md推进安全跳转、CORS/Permissions-Policy、受限外部HTTP、API Key/HMAC/原子Nonce及受控演示。URL/IP验证格式和全版本/真实宿主/独立复核仍保留，不以阶段通过缩小完成标准。

## HTTP策略与受限请求追加验收（2026-10-13）

已执行并通过：

- 本机PHP7.2/7.4/8.1/8.2/8.4/8.5：HTTP策略66项（共享URI、数字IP/反斜杠/userinfo/头注入、固定Origin跳转、CORS预检/缓存Vary/凭据限制、Permissions-Policy、url/ip输入格式）；受限策略/适配80项（全部地址拒绝、逐跳DNS变更、peer、POST不重放、累计限额、factory/诊断、DoH解析、伪造计数不能掩盖过大头、调用示例）。
- 六个PHP版本各23项实际cURL/TLS/DoH测试：全新Linux网络命名空间内设置独立公开IPv4/IPv6地址字节、固定测试服务/每进程CA，验证Host/SNI/证书与实际连接pin、跨来源头清除、私有/变更DNS目标未连接、循环/POST拒绝、真正压缩后body/原始头超限、旧折行头拒绝、不自动携带服务Cookie、慢DNS及慢HTTP共用总预算、URI私有字面量不能借公开pin连接。无宿主路由或系统信任库修改；临时环境结束已回收。
- CORS实际HTTP12项在六个本地运行时执行；真实Chromium跨端口前端触发预检并读取固定JSON，另一来源/方法拒绝，credentials模式不被错误授予。静态端点没有Session Cookie或业务数据。
- 隔离网络演示20项在六个本地运行时执行；真实Apache/FPM7.2入口24项包括实际固定www.php.net/robots.txt请求（200/字节数/hash），初步CLI7.2/8.5公网请求也实际成功。Google JSON DoH端点bootstrap pin、TLS和查询返回已实际核对。
- 整体demo.py隔离114项；实际入口含私有MySQL116项。Chromium确认新增跳转/CORS/网络拒绝AJAX与移动宽度，无脚本异常；截图已检查。拒绝按钮使用固定适配器样例，不冒充公网或内网连接成功。
- PHP7.2/8.5缺cURL最小ini各3项，HTTP策略仍可用，默认外部请求明确DependencyException；原基础功能/Session/加固/配置/验证/上传/Redis/MySQL/并发/HTTP回归保持通过。bin/check.sh两版本已执行；最新HTTP策略小项追加复测单独通过。
- 两运行时100个PHP文件语法检查、PHPStan level5/目标70200、Composer严格校验、消费者安装及95文件归档通过；开发工具依赖审计没有漏洞公告。新demo/network.php及Http/Outbound源码HTTP路径返回403。

初次已执行但失败并修复：PHP7.2不提供新XFERINFO回调常量，改用兼容的PROGRESS回调并通过实际DNS/传输超时；NETRC禁用值按PHP绑定使用false（忽略），通过实际代理/凭据环境隔离测试；DNS数据类型及响应计数增加边界检查。未把最初失败或模拟对象当真实传输证据。

未执行/未完成：API Key/HMAC/Nonce与跨实现向量/并发重放仍待实现；缺失PHP7.3/8.0/8.3、更多cURL/CA/企业网络/Windows、生产宿主试点和独立复核；远端CI及公开发布。新增CI的命名空间步骤只是定义，未在GitHub运行。默认第三方DNS隐私和自定义适配硬预算/传输契约已在outbound.md说明；URL格式/公开地址字节不能保证真实基础设施路由或业务路径授权。

完整目标保持进行中，继续API与1.0逐项验收，不用阶段完成替代完整计划。
