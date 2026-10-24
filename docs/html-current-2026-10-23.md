# HTML 净化边界修复与当前消费者验证

本轮复现并修复两个独立问题：自定义净化器故障在 `html.provider` 的 previous 中携带原始异常及嵌套详情；净化器输出除NUL外的禁止控制字符仍被接受。修复移除原异常链，输出使用与输入一致的UTF-8／控制字符规则，正常中文和TAB／CR／LF保持允许。固定原因码、公开方法、允许标签及依赖范围不变。

原始反例见 [before-exception.log](html-current-evidence-2026-10-23/before-exception.log)、[before-output.log](html-current-evidence-2026-10-23/before-output.log)，其中仅含合成标记；runtime.patch 相对于本批开始时的源码，仅修改两处运行时判断。没有放宽保护或删除旧断言。

已执行并通过：

- PHP7.2—8.5：净化器故障／输出契约、原有HTML净化／预算／配置及缺失／旧依赖拒绝共45/45条命令。每版原有HTML测试58项断言，新异常3项、输出19项。
- 两端本地原生HTTP各19项断言；真实Chromium各6组DOM／变异XSS输入，验证无脚本执行、无外部请求、沙箱预览及移动布局。测试启动自己的服务和私有目录。新增外部请求拦截，同时保留原有不得产生外部请求的断言；不是靠拦截隐藏不安全输出。
- 核心真实ZIP、离线Composer、独立HTML Purifier 4.19.1依赖、非软链接全新消费者：九版47/47步骤，包括安装、vendor来源、净化／错误边界、已安装rich-text示例及依赖清单。不是47个独立业务场景，没有借用工作区demo依赖。
- PHPStan、核心277类型API、Python／shell／浏览器脚本语法及本批差异检查通过。消费者所有运行时摘要与当前源码一致。

[证据目录](html-current-evidence-2026-10-23/)包含命令、逐项结果、输入摘要、锁定版本、原始日志、源码差异及summary.json。测试新增 `tests/html-provider-errors.php`、`tests/html_archive_consumer.py`；原HTML测试增加显式消费者autoload参数，原命令保持兼容，错误边界测试已接入普通检查入口。没有执行整个bin/check.sh。

兼容变化：若宿主依赖底层净化器异常链，改为在自己的服务边界记录安全诊断，不能要求SDK回传原详情；自定义净化器必须返回不含禁止控制字符的输出。原HTML允许列表／正文上下文限制保持，外层编码检查不证明任意自定义实现的XSS策略安全。

本轮没有外部投递、生产访问、提交、推送或部署，没有执行暂缓链路。依赖公告的最新在线审计、目标宿主及完整稳定版验收未执行。默认MySQL原生凭据预算、PHP7.2时钟及其余候选关口仍开放，goal保持active。
