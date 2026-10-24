# 下载传输回调重入修复（2026-10-23）

## 缺陷与修复

已复现：3072字节响应的输出回调再次调用同一Transfer::send，嵌套调用取走2048字节，外层仅确认1024字节却成功完成。修复前日志保留实际字节数，属于独立产品行为缺陷。

Transfer现在对read／send／status／headers使用同一操作进入保护。回调重入会使对象失败、关闭快照并拒绝；即使回调捕获嵌套异常，返回后的状态检查仍拒绝，不能恢复complete=true。内部send调用私有读取方法，普通按块输出不受影响。close保持幂等，观察计数的方法保持可用。没有回滚或重试已输出的内容。

公开签名及277类／接口清单不变。兼容变化：宿主必须在send之前读取状态／响应头，不在该对象回调中再次调用以上入口。直接重入原因码为download.reentrant；回调包装处仍使用既有download.output、download.io等固定错误码，失败后的再用为download.closed。不附带底层异常链。

## 最终源码验证

- PHP7.2—8.5九版216/216通过：每版14项重入／正常场景、9项既有最终返回场景及原downloads测试。原有需要sodium的版本使用现有运行包装器，没有安装或更改环境。
- 授权、元数据、读取、输出、关闭回调均有重入场景；授权／元数据／读取／输出／关闭的捕获异常场景均拒绝继续。验证无嵌套输出、失败状态、关闭一次、不可再读取。
- 本地私有HTTPS下载PHP7.2／8.5各733项通过，使用自建进程、私有SQLite／文件状态及测试CA；不是外部宿主或生产验收，没有恢复激活或未知回执续办。
- 离线归档及新Composer消费者36/36步骤通过。两端执行原下载、14个新场景及16MiB真实文件流式测试；8MiB限制下峰值2MiB，各263项流式断言通过。反射验证vendor来源，Transfer源码摘要一致，临时消费者已清理。
- PHPStan最终通过；首次检测到回调前后属性状态推断错误，提取独立状态检查方法后保留两次保护。首轮失败日志未删除，没有屏蔽诊断。既有可选turbo扩展GLIBC警告保持。API检查通过。
- 新测试加入bin/check.sh，但没有执行包含暂缓功能的完整检查脚本。

## 剩余范围

本批未修改SQL，未重复运行SQL矩阵。当前默认MySQL凭据预算失败、PHP7.2环境时钟问题及其他非暂缓候选核对仍未关闭。暂缓链路与外部验收未执行，goal保持active。没有提交、推送、部署或操作生产数据。

## 证据

[汇总](download-reentry-evidence-2026-10-23/summary.json)、[修复前复现](download-reentry-evidence-2026-10-23/before-writer-send.log)、[本批差异](download-reentry-evidence-2026-10-23/runtime.patch)、[最终矩阵](download-reentry-evidence-2026-10-23/matrix.json)、[PHP7.2 HTTPS](download-reentry-evidence-2026-10-23/http72.log)、[PHP8.5 HTTPS](download-reentry-evidence-2026-10-23/http85.log)、[归档消费者](download-reentry-evidence-2026-10-23/archive.json)、[最终静态检查](download-reentry-evidence-2026-10-23/static-final.log)、[API](download-reentry-evidence-2026-10-23/api-final.log)。
