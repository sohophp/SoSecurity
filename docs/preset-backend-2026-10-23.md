# 登录预算预设：实际后端组合

R4.5的八份配置预设覆盖六类场景。原configuration-presets测试已经验证文件预算、配置解析及无加载副作用，但Redis／MySQL预设只核对连接服务名；通用驱动测试不能直接代替这两份预设的实际行为。

新增tests/preset-shared-budget.php，原样使用login_file、login_mysql、login_redis的策略，只填入本轮生成的站点、私有目录及自建连接。验证五次允许、后续拒绝与等待时间、第二个SDK对象／独立后端连接共享额度、不同账号及IP范围、不同站点隔离、重置可见性和过期后重新允许。MySQL另外核对两个连接均不遗留事务。没有降低预设额度或放宽拒绝断言。

已执行并通过：PHP7.2—8.5九版文件后端各14项，九版真实MySQL各17项，具备ext-redis的七版真实Redis各15项，共25条命令／384项断言。PHP8.2和8.4的Redis组合因缺ext-redis未执行；Redis运行器整体退出1，不将缺依赖计为通过。SQLite不是这些预设的支持后端，本批没有SQLite项目。

初轮Redis测试错误地沿用1970年的固定测试时钟，真实Redis立即过期额度记录，七个具备扩展的运行时均失败，另两个缺扩展。原日志保留。修正仅为将测试起始时间设为当前Unix时间；没有更改Redis服务时钟或产品时钟策略。最终同测试源码的三种后端结果分别记录，未用失败后的无改动重跑掩盖问题。

新增tests/preset_redis.py只启动自己创建的无TCP监听进程，退出时终止并等待该进程；MySQL复用既有私有实例运行器的新--configuration-presets分支。文件、MySQL和Redis检查接入bin/check.sh各自入口，只进行了脚本语法及上述定向执行，没有运行含暂缓项的完整脚本。资源由各运行器清理，无生产访问或外部投递。

证据：[汇总](preset-backend-evidence-2026-10-23/summary.json)、[输入摘要](preset-backend-evidence-2026-10-23/inputs.json)、[文件结果](preset-backend-evidence-2026-10-23/file-results.json)、[MySQL](preset-backend-evidence-2026-10-23/mysql-final.log)、[Redis含未执行项](preset-backend-evidence-2026-10-23/redis-final.log)。产品源码、公开API、默认策略及兼容性无变化，未重复执行归档消费者。

这是三份登录预算预设的后端验证，不证明全部六类场景的真实HTTP及业务事务组合完成。其他预设组合、默认受保护MySQL凭据签发超时、宿主时钟及缺扩展仍有未关闭项；暂缓和外部验收保持，goal为active。
