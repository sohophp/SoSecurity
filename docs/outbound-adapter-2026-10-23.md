# 出站适配器异常与DoH返回预算（2026-10-23）

## 已确认缺陷

在进程内模拟Resolver／Transport中抛出带私有标记的异常，Client直接透出原始异常；带固定原因码的RequestException也透出私有正文及previous，任意原因字符串可原样返回。直接调用DohResolver同样透出传输异常。独立时钟样例还确认：最终AAAA结果超过期限后仍返回，以及自定义传输返回超过8192字节响应头仍被接受。修复前共七项失败，两个正常对照及第一跳超时对照通过；失败日志全部保留。

## 实际修改

Client的解析及传输边界、DohResolver的传输边界现在转为固定文本且无previous的RequestException。仅保留已定义的固定http原因码，其他原因归一为阶段对应http.dns／http.transport，避免自定义reason泄露。地址／输入检查、IP绑定、POST不重试和跨来源不转发应用头保持。

DohResolver每次传输返回后及最终返回前检查同一Deadline，同时检查响应头预算。没有扩大时间、正文或响应头上限，没有重试已经失败的传输。

公开签名及277类／接口清单不变。兼容变化：不能继续依赖自定义适配器原始异常类型、异常文本或previous；已知http原因码保持。传输仍负责中断阻塞I/O，本检查不宣称可抢占系统调用。

## 已执行验证

- PHP7.2—8.5九版99/99条专项命令通过：各版十个新场景及既有outbound测试，8MiB内存限制。
- PHP7.2／8.5真实cURL、TLS、DoH及重定向／预算各23项断言通过。运行在自建Linux网络命名空间，测试公网形式的IP只配置在该命名空间环回设备，没有公网请求、宿主路由或信任库修改。临时进程及证书由测试清理。
- Composer离线归档及新消费者26/26步骤通过：两端原测试及新场景、vendor反射和两份运行时源码摘要一致；临时消费者已清理，归档不含tests及证据目录。
- PHPStan与277类型API检查通过，现有可选turbo扩展GLIBC警告保留。新测试已加入bin/check.sh，但未运行含暂缓功能的完整脚本。

这是定向产品修复，不是完整计划或发行验收。当前MySQL默认凭据预算、PHP7.2环境时钟及其余非暂缓核对仍开放；暂缓恢复／交接／未知回执续办和外部宿主验收未执行，goal保持active。没有提交、推送、部署或访问生产数据库。

## 证据

[汇总](outbound-adapter-evidence-2026-10-23/summary.json)、[修复前结果](outbound-adapter-evidence-2026-10-23/before.json)、[源码差异](outbound-adapter-evidence-2026-10-23/runtime.patch)、[九版矩阵](outbound-adapter-evidence-2026-10-23/matrix.json)、[真实隔离网络](outbound-adapter-evidence-2026-10-23/native.log)、[消费者](outbound-adapter-evidence-2026-10-23/archive.json)、[静态检查](outbound-adapter-evidence-2026-10-23/static.log)、[API](outbound-adapter-evidence-2026-10-23/api.log)。
