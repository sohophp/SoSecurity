# ZIP完整读取期限修复（2026-10-23）

## 已复现及修复

ArchiveInspector 原先在文件摘要、目录预检和 ZipArchive::open 之后才开始计时，最终来源摘要未纳入期限，并直接使用墙上时钟。独立进程中对真实ZIP的指定读取阶段推进测试时钟，首次摘要、目录预检及最终摘要耗时超过100ms仍成功返回；倒退和时钟故障场景也未拒绝。五个失败和正常对照保存在before记录，未删除。

现使用共享Deadline，从首次文件I/O之前开始，完整扫描、内容读取及返回前复核共用一份预算；没有延长或重启期限。目录尾部扫描每256字节及每条目录／本地头检查预算，内容读取仍按原受限块处理。打开成功后的失败仍经finally关闭归档／流。时钟故障和预算耗尽保持ValidationException及upload.archive，底层时钟异常不进入previous。

公共签名及277类／接口清单不变。只收紧此前遗漏的超时拒绝；不改变内容判定、文件数量／大小限制、来源复核和只读语义。PHP7.2仍在缺少hrtime时使用墙上时钟，倒退默认拒绝；本批没有解决环境时钟倒退。检查点无法中断正在执行的系统调用，宿主进程超时责任保持。

## 已执行结果

- 九版专项矩阵51/51条命令通过。PHP7.2、7.4、8.1、8.2、8.4、8.5各执行已有47项ZIP断言和新增七场景；PHP7.3、8.0、8.3缺ext-zip，各只验证5项依赖拒绝，不记作内容或期限测试通过。
- 新场景使用真实ZIP和命名空间时钟／I/O桩实现，覆盖正常、首次摘要、末次摘要、预检、正文、时钟倒退和时钟异常。各场景核对源文件摘要及目录清单未改变；8MiB内存上限。它们验证检查点与拒绝行为，不是系统调用可抢占性测试。
- PHPStan通过（既有可选turbo扩展GLIBC警告保留），API检查通过。
- 离线归档、新消费者安装、vendor反射、两端既有ZIP及新增期限场景通过，运行时源码摘要与消费者一致；临时消费者已清理。归档排除tests和证据目录。两端为PHP7.2 sodium包装器及PHP8.5；包装器不用于宣称默认时钟已修好。
- 新测试已加入tests/archive_inspection.py；入口在无zip版本明确列出未执行的期限场景。

本批没有SQL修改，不重跑SQL矩阵。没有执行暂缓链路、外部投递、生产数据库、提交、推送或部署。默认MySQL凭据预算失败及其他非暂缓候选核对继续开放，goal保持active，不能据此宣称完整稳定版验收。

## 证据

[汇总](archive-deadline-evidence-2026-10-23/summary.json)、[修复前](archive-deadline-evidence-2026-10-23/before.json)、[运行时代码差异](archive-deadline-evidence-2026-10-23/runtime.patch)、[九版矩阵](archive-deadline-evidence-2026-10-23/matrix.json)、[消费者](archive-deadline-evidence-2026-10-23/archive.json)、[静态检查](archive-deadline-evidence-2026-10-23/static.log)、[API](archive-deadline-evidence-2026-10-23/api.log)。
