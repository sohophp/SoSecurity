# 捕获式会话的当前绝对期限

2026-10-23。本批修正 `StateAccountPolicy::credentialCaptured()`：返回会话到期时间取原记录与 `created + 当前absolute` 的较早值，与普通 SessionRegistry 收紧绝对期限的行为一致。读取仍不触达seen、不写会话，也不替代普通会话验证、因子权限回调或最终当前权限检查。

修前真实完整来源下，当前absolute为60秒，预期100090，实际返回128830，见[功能失败](captured-session-expiry-evidence-2026-10-23/before-functional.log)。更早一次试跑因PHP8.5不再需要ReflectionProperty.setAccessible而触发测试自身弃用错误，保留在before.log；测试按PHP版本处理，未隐藏产品错误。

回归测试从同一真实服务图构造更短期限的registry和StateAccountPolicy，在实际受保护只读准入中检查返回期限、到期前一秒及准确到期点。Reflection仅提取现有具体受管因子实例来复用真实图，不改内部状态、权限或捕获对象。该测试不进入恢复、交接或未知回执流程。

PHP7.2—8.5九版SQLite专项均已执行并通过，[准确输入和结果](captured-session-expiry-evidence-2026-10-23/results.json)保留；两端私有MySQL同专项通过，[日志](captured-session-expiry-evidence-2026-10-23/mysql.log)。公开API278核对及静态分析通过。两端真实Composer ZIP、离线非软链接安装消费者的SQLite／MySQL四组均取得通过证据；初轮两组MySQL因运行器TMPDIR设置被私有环境检查拒绝，产品断言未执行，原日志保留。仅修正运行器环境后补验两组MySQL通过；两份运行时／SQL资源摘要一致，自建资源已清理。见[初轮](captured-session-expiry-evidence-2026-10-23/consumer.json)、[补验](captured-session-expiry-evidence-2026-10-23/mysql-supplement/consumer.json)及[汇总](captured-session-expiry-evidence-2026-10-23/delivery.json)。

现有公开签名、状态格式、SQL表和默认预算保持；配置收紧后的捕获证明现在更早到期。默认3000ms原生签发仍未解决，本批未重复默认失败实验，也未用捕获式读取替换actor。旧PHP7.2时钟失败、完整候选及暂缓／外部验收仍未关闭，goal保持active。未提交、推送或部署，保留已有数据及未提交改动。
