# 平台兼容范围与验证

PHP版本兼容和操作系统/后端兼容分别记录。Linux本地PHP7.2–8.5九版本完整矩阵已通过；Windows原生PHP7.2.34、8.5.11已运行下述组件检查，不能据此声称所有模块、驱动或Windows PHP版本完全覆盖。

## 已验证的平台能力

| 能力 | Linux本地 | Windows原生7.2.34/8.5.11 |
| --- | --- | --- |
| 核心PHP语法/Composer/公开API | 九版本完整矩阵及消费者通过 | 独立消费者实际安装；78类/接口签名通过 |
| 签名CSRF、严格输入、HTTP策略 | 九版本完整矩阵通过 | 各118/52/66项检查通过 |
| Session兼容及SQLite重置流程 | 九版本实际驱动通过 | 各24/16项检查通过 |
| 可选HTML Purifier基础片段 | 九版本及浏览器通过 | 各58项及缺失/旧依赖拒绝通过；未验收Windows浏览器 |
| CAPTCHA/有状态CSRF/限流/密码/API/审计 | 实际多驱动/HTTP/并发通过 | 各48项组件组合检查，仅测试用MemoryStore；不证明生产共享后端 |
| 外部URL/解析/传输接口策略 | 九版本及真实命名空间cURL/TLS/DoH通过 | 各80项策略及模拟传输检查；实际网络/TLS/pin未执行 |
| FileStore私有文件存储 | 本地POSIX文件系统、锁/故障/并发通过 | 当前不支持；真实目录权限不可证明时拒绝初始化 |
| Upload\Saver私有上传保存 | 本地POSIX目录及实际multipart/故障/并发通过 | 当前不支持；拒绝无法证明0700/0600边界的目录 |
| Redis/MySQL共享存储 | Linux真实隔离驱动/并发通过 | 未执行Windows原生驱动；应单独验证，不用MemoryStore降级 |

Windows的`mkdir(...,0700)`实际返回目录模式0777；它不能证明NTFS访问控制列表（ACL）已经满足私有存储要求。当前FileStore、Saver和Validator私有临时目录保留严格权限检查，不提供跳过权限校验的便利开关。Windows需要复用宿主已验证的Session/共享后端，文件上传保存需宿主自行提供经过审查的存储方案；本库不能证明该宿主方案安全。WSL内Linux文件系统与Windows原生PHP、挂载Windows盘符是不同环境，不互相替代验收。

## 复现Windows组件检查

使用本机已有Windows PHP，或从[PHP官方Windows下载站](https://downloads.php.net/~windows/releases/)及[历史归档](https://downloads.php.net/~windows/releases/archives/)取得目标版本，放在专用测试目录。测试使用原生php.exe，不通过Linux PHP替代。没有要求修改Windows PATH、注册服务或安装到网站运行目录。

```powershell
composer install --no-interaction --no-progress
composer install --working-dir=integrations/htmlpurifier --no-interaction --no-progress
./tests/windows-check.ps1 -Php 'C:\path\to\php.exe'
```

测试需要JSON/hash/Session/DOM/ctype/fileinfo/PDO SQLite，后两者是测试前置条件，HTML扩展只约束可选清理模块；不增加核心强制依赖。在隔离PHP目录的php.ini启用目标版本自带fileinfo/pdo_sqlite扩展；Composer如需HTTPS则启用OpenSSL并使用有效CA信任，不能关闭TLS验证以获得通过。

脚本每一步检查退出码；含文件存储/上传保存拒绝测试，首次运行即要求真实WINNT环境。每版本472项断言及API签名检查是这个有明确范围的组件套件；不运行Linux命名空间、POSIX部分写、FileStore成功路径或三驱动竞争套件，也不把这些列为通过。

本次原生验证使用专用临时Windows目录，关闭Packagist的本地路径仓库安装新消费者（无第三方依赖）；HTML使用已锁定的4.19.1适配验证依赖。未修改全局PATH、注册表、现有PHP/FPM、系统CA或主机路由。新增GitHub windows-components任务只是定义，远端执行仍未完成。

## 当前限制

Windows其他PHP版本、IIS/Apache/FastCGI、原生浏览器、GD上传图片流程、NTFS/网络盘并发、Redis/MySQL连接及服务器版本、真实外部网络与代理仍未执行。原生Session存储锁、Cookie及HTTPS部署必须在实际宿主再次确认。操作系统及旧PHP上游维护与本库代码兼容是不同事项。
