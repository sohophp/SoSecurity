# 上传校验与私有保存

上传模块可独立使用，不要求框架、ORM或替换现有文件管理器。默认仅接收JPEG/PNG，在大小、扩展名和真实MIME一致性检查后，限制图片尺寸/估算处理资源，实际解码并重新编码，再以随机名称保存到私有目录。

参考 [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)。MIME声明不可信；[getimagesize](https://www.php.net/getimagesize)只能辅助读取尺寸，不能单独证明图片有效。本模块随后真实GD解码，重新编码得到待保存快照。类型检查、重新编码和恶意文件扫描是不同能力，不能互相冒充。

## 最小完整接入

```php
require 'vendor/autoload.php';
// 部署提前创建应用拥有的0700目录；不是Web目录、静态别名或可执行目录。
$validator = new SoSecurity\Upload\Validator();
$saver = new SoSecurity\Upload\Saver($validator, '/private/shop/uploads', $actualDocumentRoot);
// 宿主先验证登录/业务授权、CSRF和请求预算；请求体限制配置在Web服务器/PHP层。
try {
    $saved = $saver->saveUpload($_FILES['photo'] ?? []);
    $privatePath = $saved->path(); // 只给服务端业务使用，不返回到浏览器
    $metadata = $saved->metadata(); // 随机filename、MIME、字节数、sha256、尺寸、scanner_passed
    // 宿主保存业务关联、配额、保留时间。公开响应按需只返回安全metadata。
} catch (SoSecurity\Exception\ValidationException $e) {
    // 正常拒绝：422，返回稳定reason，不显示原始文件名/路径/异常全文。
} catch (SoSecurity\Exception\DependencyException $e) {
    // 缺少实际需要的扩展，503并结束业务。
} catch (SoSecurity\Exception\SecurityException $e) {
    // 存储/扫描故障，503，敏感操作不放行。
}
```

`saveUpload()`检查单个原生`$_FILES`字段及`is_uploaded_file()`，不接受普通本地文件冒充上传。不使用用户文件名组成目标路径，不信任`type`，实际大小必须与PHP元数据一致。通过验证的内容快照被复制到排他创建的随机文件；源临时文件留给PHP生命周期清理，不使用可能覆盖目标的move_uploaded_file路径。保存失败不返回成功记录，移除自己的不完整文件，不覆盖以前文件。

目录必须存在、可写、0700，并经realpath证明不在给定Web根内；文件0600，名称128位随机数的32位十六进制字符串加规范扩展名。目录/服务器静态Alias、另一虚拟主机映射、符号链接、挂载点或同UID程序权限的整体隔离仍需运营者审核。当前验证为本地Linux文件系统，Windows ACL、网络文件系统和总体I/O时间上限尚未验证。

## 策略与工厂

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'shop',
    'upload' => ['directory' => '/private/shop/uploads', 'document_root' => '/var/www/shop/public',
        'extensions' => ['jpg', 'jpeg', 'png'], 'maximum_bytes' => 5242880],
]);
$saved = $security->uploader()->saveUpload($_FILES['photo'] ?? []);
```

工厂创建只校验配置，不创建目录或启动上传；首次调用uploader才检查环境。上传项不配置时其他模块仍可用。可选scanner字段是services中的Scanner对象名称，不是请求参数、URL或自动读取的密钥。diagnose只读检查权限、Web根一致性与实际需要的扩展；扫描器实现本身标记人工验收，不调用它上传任何数据。

| 配置 | 默认 | 范围/单位 |
| --- | --- | --- |
| extensions | jpg/jpeg/png | 非空、不重复小写列表；当前支持jpg/jpeg/png/webp/pdf/txt，其他类型拒绝 |
| maximum_bytes | 5242880 | 1–20971520字节；源文件和重新编码结果分别受限 |
| maximum_width/maximum_height | 4096 | 1–16384像素 |
| maximum_pixels | 4000000 | 1–16000000，宽×高 |
| working_bytes | 134217728 | 1MiB–512MiB估算处理预算；读取也检查PHP当前memory_limit |
| jpeg_quality | 85 | 1–95，同时用于JPEG/WebP重新编码 |
| require_scan | false | true时必须注入实际Scanner；缺少时配置拒绝 |

扩展名、未知项、数值类型及范围在Policy构造时拒绝，显式null不会被当默认值。Policy复制配置并保持不可变。

文件名必须是200字节以内的UTF-8展示名称，禁止控制/格式字符、路径分隔符、冒号/百分号等特殊字符、危险脚本复合扩展和Windows设备名。合法中文与普通多点名称可用。PHP可能先把浏览器传来的路径归一为basename；本库始终使用自己的随机目标名，因此不依赖原始路径字符串还能否被观察。jpeg保存为jpg。

文件读取只接收绝对本地路径的普通文件，拒绝最终符号链接、流包装器和设备，核对打开句柄与源inode/dev及读取期间大小/mtime。保存用已经检验的内容快照，不重新打开源来复制；同UID恶意代码、内核/扩展漏洞或不可信挂载点不在这些检查能证明的范围内。

图片估算为`16×像素 + 2×源字节 + 8MiB`，并检查当前PHP内存余量；读取估算`3×源字节+1MiB`。这不是所有图像库内部内存的精确保证。重新编码输出通过独立的有界缓冲捕获，不发送到宿主响应；超出字节数立即停止保留额外数据并拒绝保存。宿主仍应更新图像库，配置进程内存/CPU/请求时间和整体磁盘配额。

默认图片重新编码会去除原始附加数据、EXIF等元数据；JPEG/WebP有损重新压缩，EXIF方向不会自动旋转。需要业务图片方向/色彩处理时，在同样预算内明确实现，并重新检查最终存储内容。WebP需要实际GD构建支持。PHP7.2的字符串解码API尚未支持WebP（[PHP官方问题记录](https://bugs.php.net/bug.php?id=77825)）；Saver自动在已检查的私有目录中对已捕获快照进行临时解码，完成后移除临时文件，不重新读取原始路径。独立inspectFile使用WebP时可传 `new Validator($policy, $privateTemporaryDirectory)`；不提供该目录时报明确依赖错误，不开启远程URL读取或降低检查。没有GD时图片拒绝，显式txt/pdf策略仍可用；所有类型都需要fileinfo。

PDF仅检查MIME及1.0–1.7/2.0头与EOF边界，不是PDF语义解析、内容重建（CDR）或病毒扫描，可能包含活动内容。txt只允许合法UTF-8和普通换行/制表符，不等于所有脚本或危险文本都可识别。文档不是默认允许类型；需要它们时显式选型并评估扫描/CDR。不得把这些文件include为程序，或自动在主站同源内嵌执行/展示。

## 扫描适配与文件管理器

```php
final class HostScanner implements SoSecurity\Upload\Scanner
{
    private $client;
    public function __construct($boundedClient) { $this->client = $boundedClient; }
    public function scan(SoSecurity\Upload\Candidate $candidate): bool
    {
        // 宿主明确配置认证、请求/响应大小和总时间预算。只在服务明确判定通过时返回true。
        return $this->client->scan($candidate->contents(), $candidate->mime()) === true;
    }
}
$policy = new SoSecurity\Upload\Policy(['extensions' => ['pdf'], 'require_scan' => true]);
$saver = new SoSecurity\Upload\Saver(new SoSecurity\Upload\Validator($policy), $privateDirectory, $actualDocumentRoot, $hostScanner);
```

扫描返回false抛upload.scan_rejected；异常包装为upload.scan_failed，不当作通过。扫描成功才保存相同内容快照。SDK不自动向第三方发送文件，不加载任意URL或假定一个服务已配置；适配器的传输限制、恶意样本验收、隐私与服务策略由宿主负责。scanner_passed=true只表示注入适配器返回true，不代表库独立证明文件无恶意。

现有CKFinder/SoFinder等管理器可以调用 `inspectFile($authorizedLocalPath, $originalName)` 获取Candidate：类型、源/结果字节数、尺寸、digest以及重新编码后的contents。源文件不修改。需要由本库私有保存时调用 `saveFile()`；它也会重新真实校验，不接受调用者伪造的Candidate当授权凭证。管理器自己的鉴权、目录授权、事件钩子、缩略图和公开下载策略保留，不能将用户提交的任意服务器路径传入inspectFile/saveFile。示例见[upload-adapter.php](../examples/upload-adapter.php)。

## 故障、保留与演示

验证拒绝使用upload.filename/extension/mime/empty/too_large/source/image/image_budget/memory_budget/text/document/not_uploaded/partial等稳定代码；依赖故障使用dependency.fileinfo/gd/gd_webp；MIME服务故障为upload.inspection；写入失败为StorageException(upload.io)，无法清理自己的不完整文件时为upload.cleanup，扫描故障为SecurityException(upload.scan_failed)。HTTP状态和日志映射属于宿主。发生异常时不继续业务保存或登记“上传成功”。

库负责单文件预算，宿主负责请求体、总容量/数量、租户配额、并发、保留时间及过期清理。示例演示额外使用全局短等待锁，限制总32文件/16MiB，每访客3文件、单文件1MiB/百万像素、10分钟保留；过期由后续操作或CLI清理。公开目录声明Apache LimitRequestBody为2MiB；本机旧版FPM代理没有执行该普通限制，演示额外通过请求头阶段的mod_rewrite拒绝超长、chunked或未知长度POST，已验证在读取请求体前返回413/411。此策略只用于固定表单演示，流式API需要宿主配置并验收适合的前置请求体限制。没有下载/执行路由，只显示结果元数据。

[可操作上传演示](http://72.rocky.wsl/SoSecurity/?module=upload)包含真实文件选择/传统表单/AJAX，以及固定正常、伪装、超限、路径、图片尺寸和隔离扫描/存储故障样例。故障按钮不连接真实AV，不破坏共享存储。测试见upload.php、upload_http.py、upload_demo.py、concurrency.php、storage-failure.php和full-disk.php。
