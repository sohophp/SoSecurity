# 上传文件扫描

`Upload\ClamAvScanner`可注入现有`Scanner`接口。它只连接宿主显式配置的本地Unix socket，构造时不联系服务。扫描的是验证后不可变的内容快照，成功后Saver才把相同字节保存到Web根外的私有目录。

```php
$scanner = new SoSecurity\Upload\ClamAvScanner('/run/clamav/clamd.sock', 5000, 5242880);
$security = SoSecurity\Security::fromArray([
    'site' => 'example',
    'upload' => ['directory' => $privateDirectory, 'document_root' => $actualDocumentRoot,
        'maximum_bytes' => 5242880, 'require_scan' => true, 'scanner' => 'upload_scanner'],
], ['upload_scanner' => $scanner]);
$stored = $security->uploader()->saveUpload($_FILES['file']);
```

宿主在调用前完成身份、对象权限、CSRF、容量及频率预算；仅在保存成功后登记可用文件。也可引用[独立构造示例](../examples/clamav-scanner.php)。扫描服务部署、定义更新和资源隔离由宿主管理，SDK不会启动守护进程、下载签名或修改系统配置。

## 协议和预算

适配器依据[ClamD官方协议](https://docs.clamav.net/manual/Usage/ClamdProtocol.html)使用NUL封帧的INSTREAM命令、网络字节序长度和8192字节数据块，结束块长度为零。文件名、上传路径和请求参数不会作为命令传给服务。正文包含NUL或其他二进制字节时仍完整传输。

连接、发送、接收及最终检查共用1至30000毫秒的真实总期限。客户端默认最多5MiB，可显式设置1至20MiB。响应最多4096字节，必须完整读取至连接结束；只接受单个准确的`stream: OK`响应。感染返回false，其他不完整、多结果、错误、超限或超时均抛依赖异常，不从“OK”子串推断成功。

配置使用规范绝对路径，最多100字节；不接受TCP／HTTP地址、控制字符或点路径段。服务端socket及直接父目录在连接前后复核身份、权限和链接数，拒绝符号链接、可被其他用户写入的父目录、世界可写socket及运行期间替换。宿主仍须保护全部上级目录、服务账户和配置；这些检查不是服务端密码学认证。响应内容和私有socket路径不会进入适配器的普通导出或异常消息。

## 服务端策略

客户端不能通过该协议设置扫描引擎选项。根据[官方使用说明](https://docs.clamav.net/manual/Usage/Scanning.html)，服务端限额可能导致跳过扫描，不能将一次OK理解为文件绝对安全。宿主应使用受维护的引擎、更新官方签名，并明确配置：

- `StreamMaxLength`和`MaxFileSize`不低于客户端允许的内容大小。
- 为解压展开量、递归、文件数量及扫描时间设置有限预算。
- 启用`AlertExceedsMax yes`，使不完整的限额扫描产生明确拒绝；按实际文件策略配置加密内容告警。
- 仅给应用必要的socket访问权限，使用受保护的服务目录，隔离扫描进程的资源和文件系统权限。

`Heuristics.Limits.Exceeded`或INSTREAM限额响应按服务未完成处理；其他FOUND结果按拒绝文件处理。扫描不能替代类型验证、图片重编码、CDR、访问授权、安全下载或保留策略。

## 同步文件状态

| 阶段 | 保存结果 | 宿主行为 |
| --- | --- | --- |
| 验证／扫描进行中 | 尚无StoredFile | 不登记或公开 |
| 明确通过且私有保存成功 | `scanner_passed=true` | 完成授权登记后按安全下载策略提供 |
| 检出内容 | `upload.scan_rejected`，无目的文件 | 拒绝上传 |
| 服务／协议／期限／限额异常 | `upload.scan_failed`，无目的文件 | 不按成功处理，记录脱敏故障 |
| 策略允许不扫描且未提供扫描器 | `scanner_passed=false` | 不得标为已扫描 |

该适配器用于同步扫描。需要持久待扫、异步重试、管理员隔离处置或扫描后重检时，使用另行构造的[Quarantine工作流](upload-quarantine.md)；其核心已接入，完整R4.4验收继续。`StoredFile`及元数据是宿主数据，不是下载授权凭据；只能依据可信保存流程登记，不能采信客户端自报的扫描状态。诊断继续将扫描服务标为需人工验收，不自动上传数据探测。

## 本地验证

`python3 tests/upload_clamav.py /path/to/php`使用自己建立的Unix socket协议对端，覆盖全字节／NUL、分块、感染、错误、多余响应、限额、读写超时、端点变化和保存拒绝。`python3 tests/upload_clamav_real.py /path/to/php72 /path/to/php85`只启动私有无TCP的真实clamd，使用测试专用签名库与合成数据，结束后停止并删除自己的实例。缺少clamd时明确报告未执行，可用`SOSECURITY_REQUIRE_CLAMAV=1`要求必须运行。

测试签名库不代表官方病毒覆盖率或生产服务验收。当前正式验证结果见[验证记录](verification.md)，持久隔离工作流的完整接入与R4.4验收继续按规划实施。
