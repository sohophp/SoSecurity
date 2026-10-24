# 可选 ZIP 归档只读检查

检查期限从首次文件I/O之前开始，摘要、目录预检、打开归档、内容读取及最终来源复核共用同一预算。支持时使用单调时钟；PHP7.2默认使用墙上时钟，倒退时拒绝。预算耗尽或时钟故障仍抛出`upload.archive`，不附带底层时钟异常。检查点不能抢占正在执行的系统调用，宿主仍须设置进程级超时。

`SoSecurity\Upload\ArchiveInspector` 为需要接收 ZIP 的宿主提供显式、只读的检查入口。宿主仍负责上传授权、私有临时文件、病毒扫描、最终文件用途和进程级超时；检查入口只接受本地文件路径，拒绝流包装器和含NUL的来源路径。普通上传与现有隔离模块不自动调用它，也不解压归档。未接入该检查的项目不应把“已扫描 ZIP 文件本身”当作“内部文件可安全使用”。

```php
$result = (new \SoSecurity\Upload\ArchiveInspector())->inspect($privateZipPath);
// sha256、entries（path/directory/bytes）和 uncompressed_bytes；不返回文件内容。
```

入口仅接受来源文件本身不是符号链接、硬链接数为1的本地普通文件；宿主必须提供不可由攻击者替换的私有父目录。检查后复核来源设备、inode、字节数及SHA-256。成功结果只证明该次读取符合本模块策略，不授予提取或后续重用同一路径的权限。默认上限：归档16 MiB、100条、路径1024字节／8段、单文件4 MiB、解压合计32 MiB、压缩比100、检查期限10秒；构造参数只能降低这些上限。缺少`ext-zip`抛出`dependency.archive`；配置错误为`configuration.archive`；内容不安全、损坏或超限为`upload.archive`。见[独立示例](../examples/archive-inspection.php)。

## 兼容与拒绝策略

- 扩展范围先限定 ZIP；缺少 `ext-zip` 时明确拒绝启用。PHP 7.2 可用 `ZipArchive::statIndex()` 和 `getStream()`；`getStreamIndex()` 从 PHP 8.2 才提供，不能成为基础接口。按名称打开流之前须拒绝重复条目名，避免索引元数据与实际读取对象不一致。`RDONLY` 也不能作为 PHP 7.2 的必需标志。
- 检查前固定归档本身的字节上限。在 `ZipArchive::open()` 前有界解析末尾目录、条目数、原始名称及对应本地文件头，拒绝多磁盘、ZIP64、目录计数／长度不一致、重复本地偏移、两个位置的名称不一致和超量元数据，避免扩展先为大量条目分配内存；扩展返回的条目数与名称也必须逐项一致。条目数、路径字节数、路径段数、单条目解压后字节数和全包解压后字节总数均有独立上限；再按受限块大小实际读完整个内容。声明长度与实读长度不一致、读取失败或预算用尽时拒绝，不把截断内容视为有效。
- 拒绝绝对路径、盘符／UNC 路径、反斜线、NUL、空段、`.`／`..`、隐藏路径段、尾随点、Windows保留设备名、大小写折叠后的重名及目录／文件冲突；限制路径深度。拒绝符号链接及非普通文件类型，禁止用归档条目直接写入宿主指定路径。嵌套归档须按文件名和内容特征拒绝，不能仅凭扩展名判断。
- 执行检查不产生解压文件或业务副作用。若后续提供提取接口，必须在同一经过认证的检查结果上执行，输出到新建的私有目录，并防止源文件替换与目录内符号链接竞态；该接口不能仅凭本设计文档宣称已具备。

## 验收样例

正常：小型 ZIP、目录与文件、合法二进制 NUL 内容，以及精确处于条目和正文上限的归档。拒绝：`../`、绝对路径、Windows 路径、重复名、链接、目录／文件冲突、过深路径、超量条目、伪造目录计数、篡改校验值、高压缩比、嵌套 ZIP／gzip／bzip2／xz 和隐藏扩展名的归档头。`ArchiveInspector` 没有提取目标或业务回调参数；测试确认它不创建目标目录。`ext-zip` 缺失的 PHP 运行时按明确拒绝验证，不记作实际 ZIP 内容检查通过。所有数据仅在本地测试目录生成。

兼容依据：[PHP ZipArchive::getStream](https://www.php.net/manual/en/ziparchive.getstream.php)、[getStreamIndex](https://www.php.net/manual/en/ziparchive.getstreamindex.php)、[ZIP 常量](https://www.php.net/manual/en/zip.constants.php)。解压后大小和压缩炸弹边界参照 [OWASP 文件上传清单](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)。当前源码 PHP7.2—8.5 九版 ZIP 专项均退出0：六个装有`ext-zip`的本地版本各通过47项定向断言，另三版各通过5项缺依赖拒绝；PHP7.2／8.5的442文件发行归档和全新Composer消费者通过。当前源码完整九版门禁、真实宿主及生产验收仍需单列。
