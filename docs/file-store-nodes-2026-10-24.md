# FileStore异常节点的有界拒绝与读取一致性

本批修复 `FileStore` 读取状态、清理过期状态和打开锁文件时可能被命名管道（FIFO）永久阻塞的问题。源码改动只涉及该类，未修改公开签名、数据格式、命名空间、64个锁条带或默认预算。见[修前源码](file-store-nodes-evidence-2026-10-24/FileStore.php.before)、[运行时差异](file-store-nodes-evidence-2026-10-24/runtime.diff)。

## 修前证据与实现

以独立临时目录分别创建状态FIFO、锁FIFO和清理目标FIFO。原实现三次都超过2秒控制器期限，原锁预算仅500ms，业务没有获得有界拒绝；测试控制器终止的都是自己启动的子进程，最终进程及资源清理均确认。见[原始结果](file-store-nodes-evidence-2026-10-24/before.json)、[输出](file-store-nodes-evidence-2026-10-24/before-controller.log)。它是私有目录出现异常节点时的资源等待缺陷，不是生产攻击演示。

状态读取现在先用lstat拒绝非普通文件和超过64KiB的物理文件，再以只读方式打开；读取前后核对描述符和路径的设备、inode、模式、所有者、链接数、长度及修改时间，返回前确认字节数。读取最多65537字节；无法打开或读取返回固定storage.io，非普通节点／已打开描述符与路径不一致返回storage.corrupt。过期清理使用同一读取路径，拒绝异常节点，不把它们当作过期状态删除。

打开状态及锁文件时使用PHP本地流的n标志，防止检查后节点被替换为FIFO时阻塞在open本身；该标志在[PHP7.2实现](https://raw.githubusercontent.com/php/php-src/PHP-7.2/main/streams/plain_wrapper.c)和[PHP8.5实现](https://raw.githubusercontent.com/php/php-src/PHP-8.5/main/streams/plain_wrapper.c)中映射为O_NONBLOCK。本批以九版实际FIFO竞争验证，不仅依赖源码推断。只读普通文件仍可读取，之后原子替换仍生成0600文件，没有改为要求以写方式打开数据。

锁文件在获取前及取得锁后均须是路径与描述符对应的同一空普通文件。仍使用原互斥锁、等待预算及持有者清理逻辑。非空锁文件现在返回storage.capacity；不会删除或重建现有锁来绕过问题。

## 开发候选的并发问题及修正

最初候选把锁文件的完整模式／ctime也作为两次元数据读取间不变的条件。另一个合法SDK调用在同一空锁上执行既有chmod时，会改变这些元数据，导致错误拒绝。测试在真实fstat后插入另一个真实SDK事务、再继续lstat，确定性复现，见[失败](file-store-nodes-evidence-2026-10-24/lock-metadata-before.log)。这是本批开发候选的问题，不归因于旧版。

最终锁校验保留普通文件类型、设备／inode、所有者、链接数和空文件大小的一致性，不把正常等待者的权限元数据刷新误判为锁替换。状态数据文件仍使用完整前后元数据检查；两者没有共用放宽的数据读取路径。九版真实交错调用检查及两端8进程／400次更新检查通过。

静态分析曾指出读取结果已排除false后再次is_string恒为真，诊断含义见[PHPStan说明](https://phpstan.org/error-identifiers/function.alreadyNarrowedType)；最终把读取失败收为单个类型检查，保留拒绝分支，没有添加忽略项或更改类型来隐藏诊断。原[分析失败](file-store-nodes-evidence-2026-10-24/static.log)和[最终通过](file-store-nodes-evidence-2026-10-24/static-final.log)分别保留。

## 当前候选的实际验证

- PHP7.2—8.5，6种FIFO／检查后替换场景共54项通过。全部在业务回调0次时拒绝；没有超时，测试子进程终态及自身目录清理均确认。见[最终节点矩阵](file-store-nodes-evidence-2026-10-24/nodes-delivery.json)。
- 58条当前程序通过：九版完整性、真实锁元数据交错、原13组核心程序、会话当前权限、物理快照及同次采集；另有两端真实部分写失败和8进程并发更新。只读0400数据、过期清理、回调失败后原状态保留、大小／目录／悬空链接及非空锁均覆盖。见[结果](file-store-nodes-evidence-2026-10-24/regressions-delivery.json)、[运行器](file-store-nodes-evidence-2026-10-24/verify-delivery.py)。
- PHP7.2／8.5 × SQLite／私有MySQL共4条受保护新账号初始化、登录、会话验证与撤销程序通过，各17断言。只初始化全新账号，没有恢复已禁用账号，没有轮换、跨代交接或未知状态续办。见[SQLite7.2](file-store-nodes-evidence-2026-10-24/fresh-sqlite72.log)、[SQLite8.5](file-store-nodes-evidence-2026-10-24/fresh-sqlite85.log)、[MySQL](file-store-nodes-evidence-2026-10-24/mysql-fresh.log)。
- 两端实际ZIP／离线全新Composer消费者14步中13步通过、1步失败。节点、普通FileStore完整性、核心程序及MySQL受保护首次登录均通过；PHP7.2的文件快照4097文件容量复核发生持续时间时钟倒退，未重复覆盖。见[消费者结果](file-store-nodes-evidence-2026-10-24/consumer/consumer.json)、[原失败](file-store-nodes-evidence-2026-10-24/consumer/consumer-72-memory.log)。vendor来源、完整运行时／SQL资源摘要、非符号链接安装及自身清理均确认，不能把整组记为通过。
- PHPStan最终无错误，已有可选turbo扩展GLIBC警告保留；公开API仍278类型，契约未修改，见[API](file-store-nodes-evidence-2026-10-24/api-final.log)。完整检查脚本仅检查语法，不运行含暂缓套件的整轮。

原A候选、修正锁元数据后的候选及最终单一读取类型检查版本的结果分别保留；上述58条程序和54项节点矩阵均在[最终输入](file-store-nodes-evidence-2026-10-24/inputs-delivery.json)下重新执行，不拼接为未执行的全项目验收。验证环境为本机Linux／WSL，不推导其他平台结果。

## 兼容与未关闭事项

非法节点、悬空链接、超过64KiB的物理状态或非空锁文件会更早拒绝，可能改变错误先后；合法JSON状态、过期语义、原子替换、只读数据兼容及命名空间保持。异常文件由宿主检查，不自动删除用户数据。新增校验未授权任何恢复或替代完整来源／见证判断。

所有其他测试结束后，准确当前候选的真实SystemClock／原生PDO默认首次签发仍约3.292827秒失败，3000ms预算；在issued返回阶段第三次actor复核时到期，保留pending／account.completion_unknown，未续办。见[当前时序](file-store-nodes-evidence-2026-10-24/default-85-timing.json)、[日志](file-store-nodes-evidence-2026-10-24/default-85-run.log)、[输入及清理](file-store-nodes-evidence-2026-10-24/default-85-result.json)。每个阶段的单次观测不用于推导稳定性能改善，也不能称完整签发成功。

PHP7.2的历史时钟问题、默认首次签发预算和最终非暂缓候选验收仍未关闭。小目录完整快照的独立优化和早期默认结果见[上一阶段](file-snapshot-memory-2026-10-24.md)，不能据其输入将本阶段消费者失败记为通过。暂缓功能及外部验收未执行，goal保持active；未提交、推送、部署、访问生产数据库或外部投递。见[交付汇总](file-store-nodes-evidence-2026-10-24/delivery.json)和[准确命令](file-store-nodes-evidence-2026-10-24/commands.json)。
