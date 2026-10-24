# 当前普通组件清单与短写测试修复

旧855项普通基线之后，Codec、Change、StatePermission、CredentialEncoding、CredentialState和CredentialPolicy六份运行时源码发生变化。本批保留旧证据，对原95条普通组件清单加入14条预算／隐私用例，形成PHP7.2—8.5每版109条的固定非暂缓清单。没有运行完整check.sh或账号恢复套件。

初轮准确结果为979项通过、2项未执行、0项执行失败。PHP8.2和8.4缺少POSIX扩展，storage-failure脚本输出NOT RUN但退出0。新运行器按输出内容分类，不再把退出0直接视为执行通过；未执行也令整批退出1。首轮在发现PHP8.2未执行时停止，随后基于相同源码及固定清单从未运行位置继续，未重跑已通过项。原始初轮和继续运行日志保留。

实际修复 `tests/storage-failure.php`：在Linux缺少ext-posix但已有/usr/bin/prlimit和pcntl时，对测试自己创建的PHP子进程应用相同的内核RLIMIT_FSIZE限制。其余系统及依赖检查保持，限制设置失败仍令测试失败。没有模拟FileStore成功，没有跳过短写、旧数据保留、临时文件清理或上传失败断言；未安装扩展或修改系统配置。

修复后九版本短写专项各7项断言全部执行并通过，其中PHP8.2／8.4的POSIX扩展仍未加载。初轮后仅这一测试文件变化，所有产品源码及资源保持；其余用例结果适用于相同运行时代码。因此109×9条普通组件清单均已有执行通过证据，但不是“一次无跳过的整批运行”，也不是全项目验收。

逐日志回看还更正了三份历史报告：旧855项实际为853项通过、2项未执行；两批旧828项各为826项通过、2项未执行。旧日志和旧汇总原样保留，对应报告增加显式更正说明，不把历史跳过改写成通过。

证据：[固定清单](ordinary-final-core-evidence-2026-10-23/cases.json)、[初轮汇总](ordinary-final-core-evidence-2026-10-23/summary.json)、[九版短写补验](ordinary-final-core-evidence-2026-10-23/storage-failure-fixed.json)、[最终绑定与环境](ordinary-final-core-evidence-2026-10-23/closeout.json)、[历史更正](ordinary-final-core-evidence-2026-10-23/historical-correction.json)。同一运行时／资源集合还与此前Change专项369份文件完全匹配，既有SQL与消费者证据按原范围保留，不宣称本批重新执行归档或数据库验收。

本轮产品源码、公开API及兼容性未变化。默认PHP8.5 MySQL凭据签发超时、PHP7.2原生流程的宿主时钟倒退及其余尚未完成的独立组合仍开放；暂缓与外部验收不计完成，goal保持active。
