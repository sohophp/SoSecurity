# 设备风险：当前会话实现的本地 HTTP 与浏览器验证

R6.3 的原有 `tests/device_risk_http.py` 使用 Python HTTP 客户端，不能作为真实浏览器证据。本轮为同一测试增加显式 `--browser` 模式，由 `tests/device-risk-browser.cjs` 驱动本地 Chromium 导航、页面内 fetch 和浏览器 Cookie 存储。原有40项断言全部保留，普通 HTTP 模式仍可独立运行。

覆盖完整密码登录、持久登录授权、设备变化要求重新认证、清除 Cookie、撤销旧授权、重新登录后签发新授权、风险解除后旧令牌继续拒绝、高风险拒绝及关联会话失效。风险信号由本地测试服务端固定提供；这里的 restore 是普通持久登录，不是账号恢复启用或未知回执续办。

PHP 7.2 和 8.5 的 HTTP 模式各40项已执行并通过；Chromium 模式两端各40项已执行并通过。最终日志与源码摘要见 [证据目录](device-risk-current-evidence-2026-10-23/browser-results.json)。PHP运行时产品代码未修改，因此本轮不重复九版本组件、数据库及消费者门禁，不称全项目验收。

测试桥接器只允许 HTTP 127.0.0.1 请求，所有服务器、账号、Cookie、状态目录及浏览器上下文均为本轮创建，退出时清理。Playwright 使用环境中已有的本地模块，通过 `SOSECURITY_TEST_PLAYWRIGHT` 显式指定，不安装依赖、不外部投递。Python等待桥接响应最多45秒，POST fetch最多10秒。

保留最初请求返回HTML的失败，以及旧测试桥接器读取POST正文等待后被中止的日志。修正仅涉及测试请求的Accept头和页面内消费响应正文；没有放宽产品断言或修改认证保护。

这是浏览器HTTP与Cookie行为验证，不包含可视界面操作、真实设备信号、宿主误判申诉及通知接入；这些仍未验收。PHP8.5默认受保护MySQL签发超时和PHP7.2宿主时钟问题保持开放，暂缓项保持，goal为active。
