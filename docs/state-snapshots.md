# 有界只读状态快照

SQL、FileStore目录和组合快照现已并入SDK，可直接通过Composer自动加载。它们提供数据摘要和同次采集结果；摘要本身不能证明权限、新鲜度或防止恢复旧备份。独立见证、审批恢复和安全代际仍按[完整规划](security-refinement.md)分别验收。

## 使用

来源只覆盖显式声明的表、筛选范围与目录；未声明部分不在摘要中。先由宿主建立实际表结构，显式声明全部字段、主键、固定筛选和行数上限。库不会安装示例表，也不接管已有宿主事务。SQLite使用持久数据库、日志及FULL/EXTRA同步；MySQL使用InnoDB、原生预处理和REPEATABLE-READ。采集会开启自己的事务，SQLite可能暂时阻塞并发写入；不要在已打开的业务事务内调用。

```php
$source = new SoSecurity\Account\SqlStateSnapshot($pdo, 'account-state', [
    'snapshot_example' => [
        'columns' => ['scope' => 'bytes:64', 'subject' => 'bytes:64', 'enabled' => 'int'],
        'primary' => ['scope', 'subject'], 'where' => [], 'maximum_rows' => 1000,
    ],
]);
$capture = $source->capture([
    'account' => ['table' => 'snapshot_example',
        'key' => ['scope' => 'tenant', 'subject' => 'demo'], 'columns' => ['enabled']],
]);
$row = $capture->row('account'); // 缺失返回null；损坏或超限抛异常。
$digest = $capture->digest();  // 与上面的字段来自同次完整SQL扫描。
```

类型包括非负`int`、`digest`、`id`、`bytes:N`、`blob:N`及对应`nullable_`类型。字符串按完整字节处理，NUL后的字节参与长度和摘要；NULL与空字符串不同。SQLite字段的实际存储类型也必须匹配声明。表结构和主键不匹配、字段／行数超限均拒绝。

分页选择器使用`page=true`、`maximum`、`after`，并指定至少一个主键前缀。`page($alias)`返回`rows`、`total`、`more`和完整`cursor`；下一页原样传回该游标。分页数据与其摘要共用扫描，不在摘要后重读；额外筛选不能隐藏主键前缀内的成员。跨次调用可能看到变化后的数据库，应用需要自行比较观测，不能仅凭游标假定跨请求一致性。

## 文件与组合来源

`FileStateSnapshot`要求两个不同、规范路径的私有0700目录：实际FileStore目录和临时排序目录。完整扫描包括全部合法状态文件，原始文件最大65536字节，拒绝符号链接、硬链接、错误权限、异常条目或目录替换。排序与归并有界，临时数据在结束时清理。读取期限为1至30000毫秒，单次文件采集最多四项。

FileStore新增`snapshotFile($key)`、`snapshotReference($key)`和`snapshotBinding()`，仅计算物理引用。`snapshotBinding()`只表示目录身份；绑定命名空间必须使用包含具体文件名的`snapshotReference()`。两个命名空间可以共用目录，但相同逻辑键的文件引用不同。

`CompositeStateSnapshot`要求所有来源使用同一个PDO对象。组合采集最多四个来源、选定数据合计1MiB；完整观测重复两次，摘要或选定字节变化时拒绝。SQL最多32表、每表64列、复合主键四列；每条声明的字段预算最多2MiB。SQL采集最多八个别名，每条最多16列、64KiB，全部选定记录／游标合计256KiB；每页最多八条。

文件与SQL无法由普通数据库事务实现跨系统原子性。全部相关写入者必须遵守宿主的共同锁协议；连续两次观测不能代替这个协议，也不能抵御绕过协议的任意并发写入者。`capture()`只接受内置具体来源；自定义可信`StateSnapshot`仅可参与摘要组合，不得把其自报摘要作为权限证明。

## 示例、数据处理与验证

[可移植组合示例](../examples/state-snapshot.php)在消费者的Composer自动加载之后引用，返回构造函数；SQLite／MySQL示例DDL位于`resources/sql/state-snapshot-example-*.sql`，只用于显式建立的测试环境。返回的采集对象会隐藏普通调试输出并拒绝序列化；`row()`、`page()`和`file()`仍会显式返回原始数据，宿主应限制访问和日志。

执行`php -d memory_limit=8M tests/state-snapshot/example.php`验证本地SQLite示例。常规检查已纳入SQL／文件／组合、分页与损坏输入测试；一万文件容量测试单列。当前整合后的多版本、私有MySQL、独立消费者和归档结果见[验证记录](verification.md)。这些数据API不包含自动恢复、业务授权或生产验收。

## 本阶段验证（2026-10-19）

已执行并通过：PHP7.2—8.5九版共159条调用，包含每版13组新增快照测试、219类型API、588文件语法及既有核心／存储检查；原211类公开成员保持，FileStore原读写／清理／锁方法逐一核对保持。两版私有无TCP MySQL各十组317项通过，实例停止并删除。261源码PHP7.2目标level5静态、两版各一万文件容量、全新Composer消费者及412文件归档通过。291份冻结输入保持，九个并入源码与已验证候选逐字节一致。

常规入口为 `bin/check.sh`；仅本地私有MySQL专项为 `python3 tests/mysql_check.py --snapshots /path/to/php72 /path/to/php85`，脚本自行建立和清理实例，不读取宿主业务库凭据。本阶段没有完整当前SDK的HTTP／浏览器、远端CI、发布、生产或独立审查验收，恢复权限及安全代际候选也未随此基础模块接入。
