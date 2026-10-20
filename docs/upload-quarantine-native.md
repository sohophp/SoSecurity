# 原生PHP上传隔离示例

此示例组合真实密码认证、服务器会话、隔离工厂和私有ClamAV。它不创建默认账号、目录、数据库表或扫描服务，也不自动注册路由。SDK仍可在任意PHP项目中独立使用；这里的SQLite业务索引由宿主维护。

| 交付物 | 用途 |
| --- | --- |
| [网页入口](../examples/upload-quarantine-http.php) | 登录、上传、查询、本人下载和管理员处置 |
| [业务组合](../examples/upload-quarantine-business.php) | 私有配置、当前账号、所有权及索引读取；导入不初始化 |
| [CLI工作进程](../examples/upload-quarantine-worker.php) | 显式处理1—64个到期任务；导入不执行 |
| [SQLite示例DDL](../resources/sql/upload-quarantine-example-sqlite.sql) | 宿主账号与文件索引，需显式安装 |

## 部署与配置

部署时先创建Web根外的规范私有目录：状态、隔离内容和原生Session目录均为0700。SQLite数据库和JSON配置文件为0600普通文件，不能为符号链接／硬链接。所有上级目录、服务账户及Web服务器别名也须保护。原生示例要求`session.save_handler=files`和私有平面`session.save_path`；其他Session后端请按宿主真实锁契约接入SDK，不通过此示例假定安全。

显式安装示例DDL，并由宿主填入真实账号。密码哈希与dummy hash均使用当前默认bcrypt成本12；dummy只用于未知账号验证，不是登录凭据。可以用`(new SoSecurity\Password\PasswordHasher())->hash(bin2hex(random_bytes(32)))`生成无对应用户的dummy hash。不得把测试脚本的账号用于实际部署。

将以下字段写入私有JSON，服务器环境变量`SOSECURITY_QUARANTINE_EXAMPLE_CONFIG`指向该文件：

```json
{
  "site": "my-site",
  "origin": "https://files.example.test",
  "database": "/private/uploads/business.sqlite",
  "state": "/private/uploads/state",
  "spool": "/private/uploads/spool",
  "document_root": "/srv/site/public",
  "socket": "/run/clamav/clamd.sock",
  "dummy_hash": "由宿主生成的成本12 bcrypt哈希"
}
```

`site`为固定ASCII标识，最多64字节；origin必须是没有路径、查询和尾斜杠的固定HTTPS来源。网页同时核对实际DOCUMENT_ROOT及HTTPS状态，不信任客户端的代理头。反向代理应通过受信任的服务器配置设置HTTPS环境。只有显式测试开关`SOSECURITY_QUARANTINE_EXAMPLE_ALLOW_HTTP=1`且来源为localhost／127.0.0.1时允许明文回环测试。

账号表按site及用户名／主体读取；角色必须为JSON数组。`uploader`可上传和读取本人文件，`upload-admin`可查看本站隔离状态及执行管理操作，不能因此下载别人的文件。账号启用、角色、版本及实际保存的密码哈希在请求时重新核对。此独立页面展示密码流程，不提供MFA证明页面；要求MFA的账号不能降级成仅密码登录，生产接入应使用宿主已有的[完整认证流程](authentication.md)。不要为使用示例清除MFA标志。

## 请求与权限

- 登录、重新认证、上传、退出、重扫、拒绝和删除都要求POST、准确Origin及一次性CSRF。不能用GET执行管理员操作。
- 登录／重新认证／退出轮换原生Session ID；凭据只在服务器会话内保存，Cookie为HttpOnly、SameSite=Lax，正式HTTPS部署带Secure。
- 管理操作还要求最近五分钟内至少完成一次因素认证，记住登录恢复不能直接管理。过期时先重新认证，不手工修改时间。
- GET列出当前用户文件；管理员可列本站元数据。下载只接受准确`?download=<32位ID>`的GET／HEAD，检查当前所有权和隔离可用状态，读取后再次核对当前身份与归属。
- 下载返回私有不可变内容快照、固定安全附件名、application/octet-stream及nosniff，不暴露隔离路径。此例不支持Range或公开分享链接。

成功的HTML表单提交通过303回到GET，刷新不会重交旧表单。JSON调用保留直接结果。页面使用`Referrer-Policy: same-origin`，并继续拒绝空／null／错误Origin；[MDN说明](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy#effect_on_the_origin_header)解释了no-referrer与普通表单Origin的相互影响。CSRF不能因此省略。

错误按固定代码分类：输入400、登录未通过401、权限／来源／CSRF403、本人文件尚不可用409、配额429、依赖或数据源异常503。错误不返回底层异常、哈希、服务器路径或会话凭据。所有响应禁止缓存；网页禁止外部脚本、嵌入与表单跨域提交。

## 扫描、预算与维护

网页只入队，不执行扫描。运维通过自己的受控调度调用：

```sh
php examples/upload-quarantine-worker.php /private/uploads/config.json 16
```

参数是固定私有配置及1—64的批量数。输出仅含处理ID和状态，失败返回非零及固定分类。服务不可用时内容保持隔离，按1秒间隔有限重试；恢复后再由工作进程处理。没有默认后台守护进程或系统服务修改。

示例只允许txt／png／pdf，每文件最多1MiB，全站队列最多64项／16MiB。每主体最多8条业务索引，配额查询最多读取8个有界ID；SQLite写事务串行化配额与索引写入。每直接来源IP每分钟最多240次请求，不采信转发IP头。图片继续经过类型／像素预算和重编码，ClamAV仍须按[扫描指南](upload-scanning.md)维护引擎与签名、限制展开成本。

业务索引与文件／隔离账本不是同一物理事务。索引写入失败会尝试拒绝并清理本次文件；提交确认不明、清理失败或崩溃可能留下不可用的孤立记录，需要运维核对私有队列和索引后明确处置，不能把未知结果直接标为可用。删除先处理隔离记录，再删除本站索引。不要在工作进程仍可运行时删除永久锁文件或回滚其中一个存储；完整备份恢复权威和全局磁盘配额由宿主负责。

示例代码是可审查的接入方式，不代表宿主全部入口、并发撤权、备份回滚或生产灾备已验收。实际业务应使用自己的迁移、账号／授权及通知机制；无需采用示例的表名或页面结构。

## 本地验证

```sh
python3 tests/upload_quarantine_http.py /path/to/php
python3 tests/upload_quarantine_http.py /path/to/php --tls
SOSECURITY_PLAYWRIGHT_MODULE=/path/to/playwright python3 tests/upload_quarantine_http.py /path/to/php --browser --tls
SOSECURITY_TEST_NATIVE_QUARANTINE=1 python3 tests/install.py /path/to/php
```

测试自己创建SQLite数据库、PHP进程和无TCP的clamd，使用合成数据与私有测试签名库，不下载病毒样本或修改系统签名。浏览器的证书例外仅限其私有测试上下文。测试结束停止自己的进程并删除自己的目录；测试签名不代表生产病毒覆盖。逐项结果、初次失败与完整R4.4剩余范围见[验证记录](verification.md)。
