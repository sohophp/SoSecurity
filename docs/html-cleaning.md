# 基础富文本 HTML 清理

普通文本继续用 `Escaper` 或 Twig 自动转义。确实要保留用户输入的段落、强调、列表等 HTML 正文排版时，显式使用 `HtmlCleaner` 和成熟清理库。它返回经过允许列表处理的正文片段，不能放进 JavaScript/CSS、事件属性、URL、SVG/MathML、模板源码或可执行文件。

默认适配 `ezyang/htmlpurifier`，已在独立验证项目锁定并实际测试4.19.1。[上游版本声明](https://github.com/ezyang/htmlpurifier/blob/v4.19.1/composer.json)支持PHP7.2–8.5，许可证为LGPL-2.1-or-later；本项目没有复制或重新授权其实现。适配器允许稳定4.x且最低4.19.1，升级仍须核对依赖公告和本项目测试，不能把版本范围当作全部版本已审计。

## 最小接入

核心包不强制安装清理依赖，使用此功能的宿主明确选择：

```sh
composer require sohophp/sosecurity ezyang/htmlpurifier:^4.19.1
# 环境另须DOM和ctype扩展；核心包尚未公开发布，当前试用用README中的路径仓库。
```

```php
require 'vendor/autoload.php';
require_once 'vendor/sohophp/sosecurity/examples/rich-text.php';
$security = SoSecurity\Security::fromArray([
    'site' => 'articles-site',
    'html' => ['maximum_input' => 65536, 'allow_links' => true],
]);
$cleaner = $security->htmlCleaner();
// 宿主先验证编辑授权、CSRF、字段schema和请求预算；保留原始版本供预览/迁移恢复。
$fragment = SoSecurity\Examples\cleanRichText($cleaner, $untrustedRichText);
// 仅在经过审查的HTML正文位置直接输出fragment；其他普通数据仍做上下文编码。
echo $fragment;
```

库不自动读取/清理所有POST字段，也不更新数据库、替换编辑器或改变原页面。当前未发布候选；宿主输入来源、授权、存储/保留策略由真实业务提供。[rich-text.php](../examples/rich-text.php)为实际可调用函数，已在只安装核心与可选依赖的新消费者中验证。

也可直接 `new HtmlCleaner(new HtmlPurifierSanitizer($allowLinks), new HtmlPolicy($options))`。`clean()`是受限入口；`HtmlSanitizer::sanitize()` 是可信适配接口，调用方不能省略外层预算后仍声称享有本模块全部限制。

## 默认保留与移除

保留 `p/br/div/span/strong/b/em/i/u/s/del/blockquote/ul/ol/li/h2/h3/h4/pre/code` 等基础正文排版。启用链接时仅额外允许 `a[href|title]`，协议限http/https/mailto，普通相对链接可保留；事件、style/class/id/name/target/ping等属性不允许。未启用链接时a标签也移除，文本仍保留。

脚本、样式、SVG/MathML、表单/输入、图片、iframe/object/embed及音视频等资源不在允许列表；URI资源嵌入明确禁用。此配置没有CSS清理、图片代理、任意编辑器扩展或HTML5完整文档兼容承诺；上游会修复结构并重新序列化，输出可能与输入不同，不能把原HTML字节不变当作清理条件。

链接清理限制协议及属性，不保证目标网站可信，也不替代业务目标白名单/安全跳转策略；它不请求这些地址，不构成受限HTTP客户端。正文链接与SSRF访问授权是不同的宿主决策。输出只对这个允许列表和正文上下文负责，不能在清理后拼接未经处理内容或把结果转成其他执行上下文。

## 预算与错误

| HtmlPolicy 配置项 | 默认 | 范围/单位 |
| --- | --- | --- |
| maximum_input | 65536 | 1–1048576字节 |
| maximum_output | 131072 | 1–2097152字节 |
| maximum_nodes | 2048 | 16–8192；解析树节点及属性合计，包含固定解析包装 |
| maximum_depth | 64 | 8–128；解析树深度，包含固定解析包装 |
| maximum_attribute | 2048 | 64–4096字节；解析后的单属性值 |
| allow_links | true | bool；仅默认适配的基础链接选择 |

输入要求有效UTF-8，不接受NUL及除TAB/CR/LF外的禁用控制字符。先检查字节数，再用DOM做资源预检：不启用DTD/实体展开或PARSEHUGE，限制树/属性/待处理节点队列。预检DOM不作为清理结果；原始输入随后进入HTML Purifier语法/允许列表处理。输出再次检查字节、UTF-8和NUL，超限拒绝，不能截断后输出。

这些预算限制输入与处理结构，不是可中断的硬CPU/内存沙箱；宿主仍须在HTTP读取/解析前限制请求大小、并发、响应和实际运行时资源。DOM本身按输入构建树，异常必须作为拒绝。组件不切换宿主的libxml错误模式、不清空其已有错误，解析和上游DOM lexer可能向已启用的错误队列追加诊断；依赖该队列的宿主应明确隔离自己的读取/清理流程。正常路径保留PHP当前错误处理器，不把解析警告当作安全通过的证据。

- 编码/输入/树/属性超限抛 `ValidationException`：`html.encoding/input_limit/tree_limit/attribute_limit/parse`。宿主停止业务，可按表单需求返回422。
- 可选包/DOM/ctype缺失、已加载旧版本或不支持的版本抛 `DependencyException`，明确拒绝；没有 `strip_tags`、正则删除或直接原文返回的降级方案。
- 清理服务异常抛 `SecurityException('html.provider')`；输出违反契约为 `html.output`，不得把底层异常/路径回传客户端。
- 错误配置抛 `ConfigurationException`；未知字段/null数值/把任意HTMLPurifier配置传入本策略均拒绝。

## 定义缓存、自定义适配与诊断

默认HTMLPurifier定义缓存关闭，不在源码/Web目录写入序列化缓存；只加载宿主已安装依赖的只读定义。适配器内部配置固定，不接受任意 `HTML.Trusted`、Filter.Custom、Cache路径或可执行回调。已加载旧的全局HTMLPurifier类时会拒绝，不能在同一请求强行加载第二份不同版本；先升级宿主Composer依赖并验证。

可信宿主可实现 `HtmlSanitizer` 并通过 `html.sanitizer => 'reviewed_service'` 注入。外层仍执行资源/编码预算和异常拒绝，但不替宿主证明该实现的XSS策略；allow_links等安全配置不会神奇改写自定义服务，需审查其自身配置。`diagnose()`对此标记manual，只检查接口，不调用清理器；默认依赖也不因诊断而自动加载或初始化，渲染上下文始终需宿主确认。

`integrations/htmlpurifier` 只是本项目可选验证/演示依赖目录，有独立Composer清单及锁定版本，整体排除出核心发行包。新消费者需自行安装可选包；核心安装仍只有PHP/JSON/hash，没有强制框架或第三方运行时包。

## 旧内容迁移与演示

先抽样比较、保留原始版本、确认编辑器基础标签确实符合策略，再逐路由启用。不要批量覆盖已有正文、任意改变已有HTML/CSS/JS或把所有文本字段当成富文本。未声明需要HTML的字段继续严格输入验证与普通转义。复杂富文本/图片/样式需要另行审查的策略/组件，而不是打开不受约束的上游配置。

[HTML清理演示](http://72.rocky.wsl/SoSecurity/?module=html)提供基础排版、攻击输入、协议链接源码、树/大小超限和固定服务故障。默认8KiB输入、16KiB输出、256节点/属性、深度24、单属性1KiB；独立CSRF控制、入口请求预算和访客隔离仍启用。原始HTML仅作为文本显示；默认清理结果在无脚本权限的sandbox iframe预览，额外CSP禁资源，链接版只显示源码，不提供任意URL代理或资源加载。

```sh
php72 /path/to/composer install --working-dir=integrations/htmlpurifier
php72 /path/to/composer audit --working-dir=integrations/htmlpurifier --locked
php72 tests/html.php
python3 tests/html_demo.py php72
SOSECURITY_PLAYWRIGHT_MODULE=/path/to/playwright python3 tests/html_demo.py --url http://72.rocky.wsl/SoSecurity/ --browser
python3 tests/install_html.py php72 /path/to/composer
```

真实浏览器测试将六组清理结果重新插入HTML DOM，检查结构变化引发的XSS、脚本/事件/资源、外部请求和手机宽度，不只对字符串做正则匹配。实际证据及未执行平台见verification.md；上游成熟实现、内部测试和依赖公告检查不替代独立安全审计或完整生产接入验收。
