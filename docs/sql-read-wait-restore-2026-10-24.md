# 借读退出的锁等待恢复

已修复事务借读（`readIn`）入口不需要收紧等待值时，退出遗漏行锁等待恢复的问题；准确原生MySQL条件下，把两个已捕获原值的恢复合为一条SET。只有`SqlTransaction.php`一个SDK文件变化；公开278类型、签名、DDL、存储格式及默认预算保持。默认首次签发仍未通过，goal保持active。

## 原始复现与实际修复

原实现仅在入口确实修改行锁等待时设置恢复标志。时钟或语句适配器在读取期间改变会话设置后，入口同值的路径退出不恢复行锁等待。MySQL与SQLite各6个原始场景中4项失败；MySQL父单元内部为7秒而原值1秒，SQLite为7000毫秒而原值1毫秒，父单元最终结束才恢复。见[MySQL原始结果](sql-read-wait-restore-evidence-2026-10-24/baseline.json)、[SQLite原始结果](sql-read-wait-restore-evidence-2026-10-24/sqlite-baseline.json)。没有删除旧失败证据。

现在只要已经捕获原值，借读退出便恢复它；不再以入口是否需要SET决定。自定义时钟／PDO／语句、SQLite及未完整捕获的路径保留逐项恢复；准确原生MySQL且两个原值都完整捕获时，在退出处重新核对原生资格，用一条`SET SESSION innodb_lock_wait_timeout=...,lock_wait_timeout=...`恢复。每次仍读取当前值；没有缓存会话变量、权限或工作进程事实，也没有合并入口的两次设置或放宽期限。

已有失败状态不尝试复用连接。恢复失败使子单元失效并传播到父单元，随后业务写入被拒绝，不能通过捕获异常继续提交；错误内容丢弃，不携带模拟私有异常链。正常主体异常且清理成功时，父单元仍可合法继续。见[源码差异](sql-read-wait-restore-evidence-2026-10-24/source-change.diff)。

原生查询日志对照确认：入口需要收紧的场景，退出恢复由两条命令减少为一条，两个原值保持；入口无需收紧时仍只用一条命令，新增了原先遗漏的行锁等待恢复。见[修前命令](sql-read-wait-restore-evidence-2026-10-24/commands-before.log)和[修后命令](sql-read-wait-restore-evidence-2026-10-24/commands-after.log)。该探测使用显式测试预算，只验证命令和结果，不代表默认签发性能验收。

## 本地测试与纠正的预期

PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3、8.4、8.5覆盖相同的367份SDK／SQL输入。MySQL8.0.46按原54程序范围合并覆盖639场景：初轮36条相关程序通过，两个新测试的九版共18程序因错误的零值预期失败；纠正后只补验这18程序，全部通过，没有重复执行已通过的相关36程序。SQLite3.26.0原45程序／504场景均通过，两个修正后的测试又在九版18程序通过；9版API278及静态分析通过。

首轮错误把MySQL请求值0直接当成实际会话值，还用0匹配恢复故障注入。本机服务器实际规范为1，见[不经过SDK的会话探测](sql-read-wait-restore-evidence-2026-10-24/server-min.log)。测试现先读取并核对服务器的实际值，再比较退出恢复值和注入故障；零值请求保留，SQLite零毫秒仍严格为0。没有提高SDK预算、修改服务器配置或删去测试来获得绿色结果。

新用例覆盖0／1请求、正常／异常退出、原生PDO内的配置变化、时钟／语句回调，以及恢复返回false、抛异常、执行后报错。恢复失败时确认无业务提交、父子拒绝复用、模拟私有详情不泄露。相关范围包含会话成对读取、元数据等待和当前工作进程正常／零等待读取；不是全项目整轮。

实际ZIP离线安装到全新非符号链接消费者，367份运行时／SQL文件逐一核对。初轮22程序18通过／4个MySQL程序因同一错误测试预期失败，7个步骤6通过／1失败。修正后新建消费者，只执行受影响的两测试、双后端和PHP7.2／8.5，共8程序／128场景通过，7个步骤全部通过。按原22程序范围，14条不重复的原相关程序加8条修正补验覆盖254场景；不把原失败轮写成全部通过，也不重复累加SQLite重叠程序。原／新消费者各绑定其实际测试摘要，SDK摘要相同。

## 默认签发与兼容边界

本批其余测试结束后，使用实际SystemClock／PDO执行一次默认3000ms首次符合授权签发。此前有一次明确拒绝用于验证准入，签发前位置提示数为1；不声称完全无预热冷路径。当前约3.004秒失败，状态pending，原因为`account.completion_unknown`，未续办。失败仍位于写入后`issued`最终身份复核的第二次会话验证。见[实测](sql-read-wait-restore-evidence-2026-10-24/default-85-timing.json)及[运行结果](sql-read-wait-restore-evidence-2026-10-24/default-85-result.json)。局部命令减少不能替代签发成功。

兼容变化是：原本遗漏恢复的入口同值路径现在完整恢复；恢复报错会返回`sql.cleanup`，需要中止宿主单元并重建服务／连接。入口收紧方式、默认预算和授权检查保持。历史PHP7.2时钟／预算失败及其他未解释失败、最终非暂缓候选验收仍开放。未执行跨安全代际交接、未知回执续办、最终账号恢复启用、完整F01或外部验收，未提交、推送、部署。

[汇总及准确输入](sql-read-wait-restore-evidence-2026-10-24/delivery.json)、[原MySQL轮](sql-read-wait-restore-evidence-2026-10-24/matrix.json)、[修正后MySQL](sql-read-wait-restore-evidence-2026-10-24/corrected.json)、[SQLite／API／静态](sql-read-wait-restore-evidence-2026-10-24/local-checks.json)、[修正后SQLite](sql-read-wait-restore-evidence-2026-10-24/corrected-sqlite.json)、[原消费者](sql-read-wait-restore-evidence-2026-10-24/consumer/consumer.json)、[修正后消费者](sql-read-wait-restore-evidence-2026-10-24/consumer-corrected/consumer.json)。
