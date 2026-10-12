# 功能演示

统一入口：[http://72.rocky.wsl/SoSecurity/](http://72.rocky.wsl/SoSecurity/)。该入口为本地开发环境，演示通过 Apache/PHP-FPM PHP7.2运行，不依赖框架。

## 可以实际操作的内容

| 页面 | 演示内容 |
| --- | --- |
| 配置与诊断 | 工厂初始化、只读检查、配置拼错、策略不可变、隔离存储故障和文件锁超时 |
| 验证码 | 算术/PNG图片生成，正确/错误答案，错误次数耗尽，成功后重放，刷新撤销和过期 |
| CSRF | 生成、普通验证、篡改、跨场景、单次消费、重放、撤销和过期 |
| 限流与封禁 | 3次额度、5秒/15秒阶梯封禁、人工临时/永久封禁、解除和剩余等待时间 |
| 输入验证 | 严格类型、Unicode长度、枚举、格式、嵌套字段与本地化错误；正常/错误/未知字段及可编辑JSON |
| 密码安全 | bcrypt哈希及验证、长度/编码策略、显式已知MD5格式迁移 |
| 重置令牌 | 单次消费、重复消费、密码版本变更后旧令牌失效 |
| 会话安全 | Session ID更新（只显示摘要指纹）、空闲/绝对过期和显式失效 |
| HTTP与代理 | 可信CIDR、从右向左代理链解析、Report-Only/Cookie响应头示例 |
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

密钥只在服务端配置，不通过演示表单保存。没有实际配置与服务响应前，不把外部能力标记为已验收。当前MySQL已接入存储页，输入验证有独立页面；上传、SSRF和API签名将在各自实现后增加对应页面，不预先放置虚假成功按钮。

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
