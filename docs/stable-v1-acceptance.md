# 首版固定基础接入验收（待管理审查，尚未执行）

2026-10-25。依据 [管理范围](stable-v1-management-2026-10-25.md)、[管理审查](stable-v1-review-2026-10-25.md) 和 [API范围](stable-v1-api-scope.md)。本批只制定清单，所有下列新验收项状态均为**未执行**。本文件不是测试运行器；命令供管理审查后安排执行，不能据其存在宣称通过。

## 候选绑定与记录约定

- 运行时基线：`fedc471fae6cb7d623904f1d50bc041357a178a1`；管理/发行排除配置基线：`66f2722`。这两份文档审查后的提交由管理会话固定为验收候选；不自行打标签或推送。
- 输入身份同时包含：最终候选提交、工作区差异、下列Git树对象、实际命令及参数、运行时文件SHA-256/`--version`/加载扩展、所有参与测试/资源/样例/依赖文件摘要、Composer版本/锁文件、后端版本和启动配置、安装包摘要及消费者反射来源。不得只登记被测单个PHP文件。
- 当前已核对 `/usr/bin/php72`、`php73`、`php74`、`php80`、`php81`、`php82`、`php83`、`php84`、`php85` 命令路径存在，**本批未执行版本或扩展探测**。不能把旧临时sodium运行时包装器当作当前依赖。缺少必要扩展须记录为未执行/失败，不能忽略平台要求、关闭测试分支或临时替换时钟求通过。
- 每项使用新证据输出目录，保存stdout、stderr、退出码、起止时间、实际子命令和清理结果；不得覆盖旧日志。PHP断言失败退出、父运行器失败和未执行子项分别记录。命令退出0仍须匹配该文件现有完成标记且完成所列分支；`NOT RUN`不能算对应能力通过。
- 所有正常用例也包含拒绝断言；“拒绝成功”要求返回规定的false/null、HTTP状态或受控异常，并保持无越权结果、无私有信息泄露、无错误提交。被测拒绝不等于测试失败；未捕获异常/缺少结尾标记则是测试失败。
- 工作目录均为仓库根。G01的`R`固定取上述九个原生绝对路径；后续F/B/H/C的`R`采用末尾登记的显式测试运行时映射，逐版执行，不使用含糊的默认`php`。应用默认预算不改；表中的`memory_limit`只是既有测试资源约束，不是应用时限。
- 子进程环境清除继承的`SOSECURITY_TEST_*`、`SOSECURITY_REQUIRE_*`、`SOSECURITY_*_EXAMPLE_*`测试配置和HTTP(S)/ALL代理变量，只由对应运行器注入自建资源；设置`COMPOSER_DISABLE_NETWORK=1`、`COMPOSER_NO_INTERACTION=1`、`PYTHONDONTWRITEBYTECODE=1`。运行前记录必要的非秘密变量名称，不打印宿主凭据。
- 后端只能使用运行器新建的临时目录、Unix socket、测试数据库/账号；禁止读取宿主数据库连接。HTTP仅回环地址或独立网络命名空间，无外部投递。超时只停止自己创建的进程；不按名称批量杀进程，不删除归属不明目录。

| 输入树（来自fedc471） | Git对象 |
| --- | --- |
| src | `9335d63fc9cef8a0125f942c5a76457e1a958868` |
| resources/sql | `4c7ba413f2492591a70931f0c9416c49810d1337` |
| resources/api | `42b389d54f8b56000737c9704383fc35185e33e0` |
| tests | `f4d7408f2878dfabd0100df3caafbe56f7088bd2` |
| examples | `e33d87145982ee297ccc80cf9c87818329f5ba7b` |

执行前以`git diff --exit-code 66f2722 -- src resources tests examples integrations composer.json .gitattributes`核对这些输入未漂移，并保存最终候选的逐文件摘要。源码后续经管理授权修复时，原失败保留，重新绑定候选及受影响输入；不能继续声称fedc471输入未变。仅无关文档变更不要求重复昂贵矩阵。

## 固定命令清单

下列是本版唯一清单。无参数代表不再附加其他选择器；大括号内取值逐一执行，不是任选一项。每个PHP命令均以对应`R`启动。不得运行`bin/check.sh`、`tests/mysql_check.py --matrix`、无选择器MySQL总入口、旧证据目录下的run.py或任何恢复/未知结果/工作进程总入口。

G01九版基线：

```sh
"$R" tests/run.php
"$R" tests/portable-core.php
"$R" bin/api-contract.php
```

完成判据分别为：`13 suites`且`0 failures`并退出0（断言数因算法能力不同可不同）；`48 portable core workflow assertions passed`且退出0；`PASS public API signatures: 278 classes/interfaces`且退出0。MemoryStore基线不代替共享后端。另在PHP7.2执行`/usr/bin/php72 bin/lint.php`，完整语法检查退出0；以`/usr/bin/php85 /usr/local/bin/composer validate --strict --no-interaction`检查清单，退出0。实际文件数以候选登记值为准，不写死历史1104作为成功替代。

F01—F12九版普通组件，全部使用未绑定StateBoundary的新测试数据。表内每个文件和参数是独立程序，不串行依赖先前签发的未知结果：

| ID / 拟稳定API组 | 精确命令（每个R） | 输入、拒绝/故障覆盖与完成判据 |
| --- | --- | --- |
| F01 / S01 | `"$R" -d memory_limit=32M tests/signed-csrf.php` | 独立HmacKeys、绑定/过期/来源错误；结尾断言汇总且退出0；TLS补H04 |
| F02 / S01/S02 | `"$R" -d memory_limit=32M tests/captcha.php`；`"$R" -d memory_limit=32M tests/csrf-time.php` | 内存/文件/Session验证码、重放/错误绑定/尝试次数/延迟撤权；图片与交互分支须实际加载GD，不能用no-GD算术分支冒充图片通过 |
| F03 / S03 | `"$R" -d memory_limit=32M tests/budgets.php`；`"$R" -d memory_limit=32M tests/policy-option-boundaries.php` | 窗口/封禁/预算组合/错误策略；正常、超限和无效输入断言完成；真实登录预算补B04/H01 |
| F04 / S04 | `"$R" -d memory_limit=32M tests/password.php`；`"$R" -d memory_limit=32M tests/password-dependencies.php` | bcrypt长度/空字节/错误密码/重哈希/依赖拒绝；Argon2id仅在运行时编译支持时验收，缺失须确认受控依赖拒绝，不宣称该算法已运行 |
| F05 / S05/S06 | `"$R" -d memory_limit=32M tests/auth.php`；`"$R" -d memory_limit=32M tests/session.php`；`"$R" -d memory_limit=32M tests/session-current-authority.php` | 普通身份提供者、会话登记/轮换/撤销、角色/版本/禁用变化及故障；不使用StateBoundary。auth.php附带普通TOTP恢复码检查，属于E耦合观察，不是账号恢复启用；缺少sodium的附加分支单独记未执行，不覆盖S分支 |
| F06 / S07/S08 | `"$R" -d memory_limit=32M tests/validation.php`；`"$R" -d memory_limit=32M tests/http-policy.php`；`"$R" -d memory_limit=32M tests/hardening.php`；`"$R" -d memory_limit=8M tests/input-boundaries.php` | 验证/上下文编码、可信代理、CORS/响应头、异常容器和资源预算；旧程序结尾`assertions passed`也属有效标记，不能只查大写PASS |
| F07 / S09 | `"$R" -d memory_limit=32M tests/upload.php`；`"$R" -d memory_limit=8M tests/upload-read-budget.php`；`"$R" -d memory_limit=32M tests/upload-export.php` | 真实文件检查、名称/MIME/大小/读取预算/扫描失败/隐私；fileinfo/GD必需，WebP支持按实际codec记录，仅支持已验收的格式；实际multipart补H03 |
| F08 / S10 | `"$R" -d memory_limit=32M tests/outbound.php`；`"$R" -d memory_limit=8M tests/outbound-adapter.php MODE`，MODE固定为`normal doh-normal resolver-fault transport-fault transport-known transport-unknown doh-fault doh-late doh-first-late doh-headers` | 显式Resolver/Transport/DoH模拟对象的正常与故障、超时和头预算；每项完成，原生cURL/TLS必须另过H06 |
| F09 / S11 | `"$R" -d memory_limit=32M tests/api.php`；`"$R" -d memory_limit=32M tests/api-key-time.php`；`"$R" -d memory_limit=32M tests/api-epoch.php` | 普通ApiKeys及HMAC，原始字节、签名/作用域/重放、撤销/代次、提供者/存储故障和延迟；默认无socket只证明memory/file，B02/B03补真实共享驱动 |
| F10 / S12 | `"$R" -d memory_limit=32M tests/webhooks.php`；`"$R" -d memory_limit=8M tests/webhook-key-export.php` | 四个协议、签名时效/当前密钥/错误输入/资源与隐私；Ed25519须有sodium正向验证，无sodium只记该协议未执行并保留依赖拒绝结果 |
| F11 / S13 | `"$R" -d memory_limit=32M tests/configuration.php`；`"$R" -d memory_limit=32M tests/configuration-presets.php`；`"$R" -d memory_limit=8M tests/secret-config-export.php`；`"$R" -d memory_limit=8M tests/bearer-object-export.php`；`"$R" -d memory_limit=8M tests/transport-value-export.php` | 最小按需工厂/无高级依赖/无效配置/敏感值不可导出；预设共享性须再过B04，不能只看配置数组 |
| F12 / S14 | `"$R" -d memory_limit=32M tests/authorization.php`；`"$R" -d memory_limit=8M tests/audit-budget.php` | 当前权限/资源/批量投影和普通审计故障预算。附带的高级组合不获得稳定承诺；SQL审计委托不加入执行队列 |

所有F项要求退出0、现有程序结尾完成标记及无未捕获错误；不能将中途一条PASS当作全文件通过。依赖缺失导致S必需正向分支未执行时，该能力/运行时组合不能通过；要么补齐测试环境，要么由管理会话提交支持边界方案，不能静默缩小PHP7.2—8.5。

### 真实后端和共享底层

| ID | 固定选择器（九版每个R） | 支持组合、拒绝/故障与完成判据 |
| --- | --- | --- |
| B01 | `"$R" -d memory_limit=32M tests/file-store-integrity.php`；`"$R" -d memory_limit=32M tests/file-store-lock-metadata.php`；`SOSECURITY_REQUIRE_POSIX=1 "$R" -d memory_limit=32M tests/storage-failure.php` | 自建0700普通目录；完整性、锁元数据、写入失败拒绝及回调异常后释放；POSIX/pcntl/prlimit前置条件必须满足，退出0及结尾断言完成；不绑定既有受保护目录 |
| B02 | `python3 tests/api_key_time_redis.py "$R"`；`python3 tests/preset_redis.py "$R"`；下方B02-R原始Redis检查 | 新建无TCP Redis，ext-redis必需；普通API与真实登录预算观察、重放/时效/错误backend及原子状态故障；父进程退出0，全部子程序完成，实际socket来自当前运行器 |
| B03 | `python3 tests/mysql_check.py SELECTOR "$R"`；SELECTOR固定为`--mysql-store-regression --mysql-store-index --mysql-store-errors --api-key-time --configuration-presets`，分别执行 | 私有无TCP MySQL/新测试库及账号，ext-pdo_mysql；真实存储结构/错误、调用者事务拒绝且不提交宿主事务、scope/nonce/代次、登录共享预算；父退出0且各分支全部子程序通过。`--mysql-store-regression`额外调用ownership的`store/prune/install`（各显式/隐式事务），不调用处理器执行或未知结果 |
| B04 | `"$R" -d memory_limit=32M tests/preset-shared-budget.php file`；Redis和MySQL分别由B02的preset运行器及B03的`--configuration-presets`提供 | 对同一新站点两个实例共享login预算，拒绝不共享/缺依赖；结尾`PASS actual login preset BACKEND`。File/Redis/MySQL三组均有证据才算预设共享通过 |
| Q01 | `"$R" -d memory_limit=8M tests/webhook-metadata-budget.php sqlite all`；`python3 tests/mysql_check.py --webhook-metadata-budget "$R"` | 全新SQLite/MySQL收件数据，固定all，包含`event_type/receive`原未解释失败；全部声明场景完成、零失败、退出0、无错误提交/无处理业务。SqlInbox为E，但本项用于共享SQL/时钟与已知失败隔离审查；不因新通过删除旧失败 |
| Q02 | `"$R" -d memory_limit=8M tests/deadline-clock.php`；`"$R" -d memory_limit=8M tests/deadline-failure-kind.php` | 无效/不可用/倒退/耗时越界的错误码、固定消息和脱敏；退出0及各自PASS。这是明确故障注入，不证明真实时间源稳定；B/H/C同时记录未经替换的真实Deadline路径，PHP7.2应记录`hrtime`缺失 |

B02-R使用以下固定文档内命令，补充现有`tests/redis.php`的真实类型损坏、过期/回调失败和初始化拒绝；不运行Redis恢复或账号恢复脚本。命令只在管理安排执行时复制运行，不在本批执行：

```sh
python3 - "$R" <<'PYREDIS'
import os, pathlib, subprocess, sys, tempfile, time
root=pathlib.Path.cwd(); runtime=sys.argv[1]
with tempfile.TemporaryDirectory(prefix='sosecurity-v1-redis-') as directory:
    socket=str(pathlib.Path(directory)/'redis.sock')
    env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_TEST_')}
    env['SOSECURITY_TEST_REDIS_SOCKET']=socket
    with open(pathlib.Path(directory)/'server.log','w+') as log:
        server=subprocess.Popen(['redis-server','--port','0','--unixsocket',socket,'--unixsocketperm','700','--dir',directory,'--save','','--appendonly','no'],stdout=log,stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None: raise RuntimeError('Owned Redis exited')
                if pathlib.Path(socket).is_socket():
                    p=subprocess.run(['redis-cli','-s',socket,'PING'],capture_output=True,text=True,timeout=2)
                    if p.returncode==0 and p.stdout.strip()=='PONG': break
                time.sleep(.05)
            else: raise RuntimeError('Owned Redis startup timeout')
            subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/redis.php')],env=env,check=True,timeout=120)
        finally:
            if server.poll() is None:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=5)
print('PASS v1 owned Redis runner; child complete and owned server stopped')
PYREDIS
```

B02-R须同时出现子程序`Redis integration assertions passed`与父程序PASS，不能仅以父进程收尾标记通过。此命令不替代Redis官方支持版本声明；本次实际服务器版本作为验收环境记录。SQLite仅用于支持SQLite的SQL组件，不宣称存在通用SQLite AtomicStore；MySqlStore仅MySQL，不外推MariaDB、其他数据库或分布式平台。

### 本地HTTP/TLS

九版逐一执行下表，每个运行器只生成自己拥有的临时状态、端口和进程；不使用`--browser`，所以不宣称浏览器/UI验收。真实PHP会话与HTTP状态必须由回环请求获得。

| ID | 精确命令 | 完成判据和拒绝/故障 |
| --- | --- | --- |
| H01 | `python3 tests/test_http.py "$R"` | `PASS HTTP:`且退出0；真实Session cookie/轮换、表单CSRF、多标签页、验证码重放、登录失败/429封禁、错误方法405、故意破坏自建存储权限后503；不替代完整受保护账号管理 |
| H02 | `python3 tests/api_http.py "$R"` | 结尾`real HTTP API assertions`且退出0；独立Python签名、原始body/query/Content-Type、重放/过期/错误密钥/作用域、413、提供者/存储503脱敏、普通Bearer撤销401；测试专用签发路由不进入发行包 |
| H03 | `python3 tests/upload_http.py "$R"` | `PASS native multipart uploads:`且退出0；真实POST上传、MIME/扩展名/大小/来源、413、扫描器故障503、私有目录且无路径泄露 |
| H04 | `python3 tests/signed_csrf_https.py "$R"` | `real TLS/proxy signed-CSRF assertions`且退出0；独立短期CA、本地TLS终结、Secure/HttpOnly/__Host、无Session模式、伪造403；不改系统CA和代理设置 |
| H05 | `python3 tests/webhook_http.py "$R" --tls` | `PASS native webhook TLS:`且退出0；raw签名、SQLite收件重复/冲突/锁超时、密钥/关联撤权、无业务执行；样例附带普通密码/TOTP查询权限检查，需sodium，属于E耦合检查。fixture默认processing=False，不加处理器、跨代状态或browser选项 |
| H06 | `SOSECURITY_REQUIRE_NATIVE_HTTP=1 python3 tests/native_outbound.py "$R"` | 子程序`native pinned/TLS/DoH/redirect/budget assertions passed`及父程序`PASS native namespace:`且退出0；原生cURL固定IPv4/IPv6、独立TLS CA、重定向/重绑定/DoH/响应预算。既有运行器使用`sudo -n unshare --net`，仅在现有权限允许时执行；权限/安全审查拒绝则记录阻塞，不修改策略、宿主路由或改用模拟对象凑结果 |

## 发行归档和全新消费者（C01）

使用现有归档断言：九版各执行`python3 tests/archive.py "$R" /usr/local/bin/composer`，父退出0且`PASS archive:`完整结束；保存生成包清单与摘要。归档不得带vendor/tests/bin/tools/integrations/resources/api、私密配置、日志、本地证据目录或`docs/local-evidence-manifest-*.json`；后者由下面消费者再显式检查。E源码/文档仍可在包内保留，不能因通过归档声明E能力稳定。

为避免再用历史专项消费者冒充首版消费者，下列固定命令定义一次全新离线核心包安装，复用仓库现有测试/HTTP运行器。只复制测试支持、资源、样例，不复制工作区src或vendor；测试必须实际加载安装包。不是新增产品接口或新执行阶段。命令在管理审查后执行，本批未执行：

```sh
python3 - <<'PYCONSUMER'
import hashlib, json, os, pathlib, shlex, shutil, subprocess, tempfile, zipfile
root=pathlib.Path.cwd()
runtime_map=root/'docs/stable-v1-start-evidence-2026-10-25/runtime-map.json'
reviewed=json.loads(runtime_map.read_text())['runtimes']
assert [row['version'] for row in reviewed]==['72','73','74','80','81','82','83','84','85']
runtimes=[]
for row in reviewed:
    native=pathlib.Path(row['native']); runtime=root/row['runtime']
    assert hashlib.sha256(native.read_bytes()).hexdigest()==row['native_binary_sha256']
    assert hashlib.sha256(runtime.read_bytes()).hexdigest()==row['wrapper_sha256']
    for module in row['modules']:
        assert hashlib.sha256((root/module['file']).read_bytes()).hexdigest()==module['sha256']
    if row['missing_required_extensions']:
        raise RuntimeError('Reviewed runtime profile incomplete: '+row['version']+' '+str(row['missing_required_extensions']))
    runtimes.append(str(runtime))
env={k:v for k,v in os.environ.items() if not k.startswith(('SOSECURITY_TEST_','SOSECURITY_REQUIRE_')) and not ('SOSECURITY_' in k and '_EXAMPLE_' in k) and k not in ['PHP_INI_SCAN_DIR','PHPRC'] and k.upper() not in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY']}
env.update(COMPOSER_DISABLE_NETWORK='1',COMPOSER_NO_INTERACTION='1',PYTHONDONTWRITEBYTECODE='1')
manifest={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for d in ['src','resources/sql'] for p in (root/d).rglob('*') if p.is_file()}
def run(cmd,cwd):
    print('COMMAND',json.dumps(cmd),flush=True)
    subprocess.run(cmd,cwd=cwd,env=env,check=True,timeout=180)
with tempfile.TemporaryDirectory(prefix='sosecurity-v1-consumer-') as directory:
    base=pathlib.Path(directory); package=base/'package'; package.mkdir(); consumer=base/'consumer'; consumer.mkdir()
    run(['/usr/bin/php85','/usr/local/bin/composer','--no-plugins','--no-scripts','archive','--format=zip','--dir='+str(base),'--file=candidate','--no-interaction'],root)
    archive=base/'candidate.zip'; print('ARCHIVE_SHA256',hashlib.sha256(archive.read_bytes()).hexdigest())
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            assert not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts
            assert not name.startswith(('vendor/','tests/','bin/','tools/','integrations/','resources/api/'))
            assert '-evidence-' not in name and not name.startswith('docs/local-evidence-manifest-')
            assert not name.endswith(('.log','.env','composer.lock'))
        z.extractall(package)
    cfg={'name':'sosecurity/local-v1-consumer','require':{'sohophp/sosecurity':'dev-candidate'},'repositories':[{'type':'path','url':str(package),'options':{'symlink':False,'versions':{'sohophp/sosecurity':'dev-candidate'}}},{'packagist.org':False}],'minimum-stability':'dev','config':{'allow-plugins':False,'platform':{'php':'7.2.34'}}}
    (consumer/'composer.json').write_text(json.dumps(cfg))
    run(['/usr/bin/php85','/usr/local/bin/composer','install','--no-scripts','--no-plugins','--no-interaction','--no-progress'],consumer)
    installed=consumer/'vendor/sohophp/sosecurity'; assert not installed.is_symlink()
    actual={str(p.relative_to(installed)):hashlib.sha256(p.read_bytes()).hexdigest() for d in ['src','resources/sql'] for p in (installed/d).rglob('*') if p.is_file()}
    assert actual==manifest
    print('RUNTIME_SHA256',json.dumps(actual,sort_keys=True)); print('LOCK_SHA256',hashlib.sha256((consumer/'composer.lock').read_bytes()).hexdigest())
    for d in ['tests','resources','examples']:
        shutil.copytree(root/d,consumer/d,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    origin=consumer/'origin.php'
    origin.write_text('<?php require __DIR__."/vendor/autoload.php"; foreach(["SoSecurity\\\\Security","SoSecurity\\\\Csrf\\\\CsrfTokens","SoSecurity\\\\Api\\\\ApiKeys","SoSecurity\\\\Api\\\\HmacVerifier","SoSecurity\\\\Storage\\\\FileStore","SoSecurity\\\\Storage\\\\MySqlStore","SoSecurity\\\\Storage\\\\RedisStore","SoSecurity\\\\Webhook\\\\Verifier"] as $c){$p=(new ReflectionClass($c))->getFileName(); if(strpos($p,__DIR__."/vendor/sohophp/sosecurity/src/")!==0){throw new RuntimeException("Wrong installed origin");}}')
    programs=['run','portable-core','captcha','csrf-time','budgets','password','session','auth','validation','http-policy','outbound','api','webhooks','signed-csrf','upload','configuration','storage-failure','file-store-integrity']
    for real in runtimes:
        wrapper=base/pathlib.Path(real).name
        wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(real)+' -d auto_prepend_file='+shlex.quote(str(origin))+' "$@"\n'); wrapper.chmod(0o700)
        runtime=str(wrapper); print('RUNTIME',real,'WRAPPER_SHA256',hashlib.sha256(wrapper.read_bytes()).hexdigest())
        for name in programs: run([runtime,'-d','memory_limit=32M','tests/'+name+'.php'],consumer)
        for script in ['test_http.py','api_http.py','upload_http.py','signed_csrf_https.py']: run(['python3','tests/'+script,runtime],consumer)
        for selector in ['--mysql-store-regression','--api-key-time','--configuration-presets']: run(['python3','tests/mysql_check.py',selector,runtime],consumer)
        run(['python3','tests/api_key_time_redis.py',runtime],consumer)
        run(['python3','tests/preset_redis.py',runtime],consumer)
    print('PASS v1 installed consumer; installed sources matched, nine runtime programs/backends/HTTP complete')
print('PASS v1 consumer owned temporary directory cleaned')
PYCONSUMER
```

C01完成要求：离线归档/安装退出0，无下载/插件/脚本，无symlink；安装后src及SQL逐文件相符且无额外运行时文件；每个PHP进程使用登记的原生PHP及经审查的进程级扩展映射（消费者外层包装器只追加来源断言，不替换时间函数），每版18个PHP程序、4个HTTP程序、3个MySQL选择器、2个Redis运行器全部完成，且各子程序的现有完成标记/必需分支齐全。消费者总计9×27个外层功能程序，**不是243次独立安装**；实际后端子程序另列。失败即保存原始输出及尚未执行项，不重跑未知结果。临时包/进程只清理自己创建的资源；父日志和摘要由外层新证据目录保留。

## 发布阻塞与停止条件

本版只保留以下五项，编号与管理审查一致；新发现仅归入受影响项，不扩张功能清扫：

1. **稳定/实验隔离未获审查通过**：本API表是提案，需管理核对具体方法、共享底层及最小宿主接入。不能仅凭实验标签豁免基础路径缺陷。
2. **默认受保护管理3000ms与completion_unknown**：禁止重试/续办；核对源码隔离和基础B/H/C证据后，由管理决定修复或隔离发布方案。原始失败不关闭为通过。
3. **PHP7.2真实时钟可用性**：Q02只证明倒退时拒绝保护；真实microtime倒退根因与环境支持边界未定，不能统一解释所有历史失败或静默缩小PHP范围。
4. **PHP7.2/MySQL接收未解释失败**：Q01保留原失败并按当前候选收集证据；即使新运行通过也不能凭一次通过删除旧失败，需要可审查的根因/修复或隔离说明。
5. **唯一候选完整证据及实际宿主接入未完成**：本清单各适用组合、全新消费者、最小接入/迁移/回滚指南须绑定准确候选。真实宿主接入由管理指定并协调，禁止自行操作现有业务站点或生产数据库；消费者通过不能冒称实际宿主上线完成。

有限修复由管理会话安排，限已登记阻塞，修前复现、最小修复、相关回归；同一阻塞连续两批无实质改善即交付明确的简化/隔离/环境限制选项，不继续原型扩张。任何安全审查拒绝保留原原因并停止对应操作，不改写意图或绕过限制。默认管理未知结果、跨代交接、最终恢复启用和完整F01均不进入本清单。

历史证据定位（均为旧候选，非本次已执行结果）：

- `docs/nondeferred-freeze-evidence-2026-10-24/summary.json`：828普通程序通过，当前src仅SqlProcessor曾随后变化；不能拼成当前整轮。
- `docs/default-queued-final-evidence-2026-10-24/summary.json`：九版默认管理当轮只有8.4/8.5完整通过，其余首次失败后未执行后续。
- `docs/audit-sql-cleanup-evidence-2026-10-24/default-85/default-85-run.log`：较近8.5第二次签发审计超时/未知完成，未续办。
- `docs/webhook-processing-budget-evidence-2026-10-24/72-native-sqlite-shared.log`：实际时钟倒退，在账号快照阶段失败，未到Webhook验证，不能冒称其验证失败根因。
- `docs/webhook-metadata-budget-2026-10-24.md`及其同名证据目录：`event_type/receive`未解释原断言失败，独立消费者通过不覆盖它。
- `docs/local-evidence-manifest-2026-10-25.json`：本地历史日志路径/大小/SHA-256；备份说明见管理审查。源码仓库和发行包不包含全部原始日志。

本批交付到此：仅两份文档，等待管理审查选择器、候选绑定和隔离方案后安排执行。未运行上述测试，未修复源码，未提交/推送/发布；整体goal不标完成。

## 管理审查决定（2026-10-25）

两份文档的范围和选择器已获管理审查，按本节条件进入执行；所有项目仍为未执行，不能视为通过。已纠正不存在的指南路径及契约方法表头；当前运行时源码仍为fedc471，只有管理/验收文档变化。

执行次序固定为：先九版原生命令的G01及依赖预检，随后B/F/H/C按原清单推进，先处理前置条件和具体失败，不增加产品功能。管理实测：原生php72缺sodium/posix；php73缺sodium；php74缺sodium/posix；php80缺sodium；php82缺redis/posix；php83缺sodium；php84缺redis/posix；php81/85具备本清单预检的全部扩展。所有版本为64位；php72无hrtime。以上是当前进程探测，不是测试通过。

环境准备只允许使用可核验来源、版本匹配的既有本地测试扩展，显式按进程加载并记录文件/配置摘要，禁止修改系统默认PHP配置、替换时间函数或移除保护。旧临时包装器必须按当前实际内容重新审查并探测，不能凭历史结果复用。若使用审查过的扩展激活包装器，R必须登记为该包装器及其真实原生PHP路径，消费者命令的runtimes也必须使用同一份显式运行时映射；本节取代上文“消费者包装器不能加载扩展”的过窄表述。G01原生基线与启用可选扩展的组合分别记录，不混淆支持条件。

先验证文档内Python语法、实际路径、生成的shell换行、PHP来源断言及一个最小消费者安装；这些执行器检查通过后再展开九版消费者，避免同类运行器错误重复九次。不得在消费者中添加工作区src副本，必须由安装包加载。

Q01属于已有失败的诊断：一次按当前准确候选收集具体异常原因、进程/输入摘要和时钟状态；原失败保留。新运行通过不自动关闭旧失败，同一失败不得无限重复求绿。PHP7.2时钟暂按现有倒退拒绝保护执行，不修改系统时钟或引入新的常驻服务。下一次源码修复只限已登记阻塞且先有具体复现，未取得证据不开始新的边界清扫。


## 本批执行记录：原生G01、运行时与最小消费者（2026-10-25）

本节更新本批实际状态；上文清单其余项目及九版完整C01仍为未执行。执行候选为`d9852ec`（执行时HEAD），源码及测试基线保持`fedc471`，没有产品源码/API改动。本节及C01映射修正尚待管理阶段整理，不把文档变化声称为新运行时修复。

### 已执行并通过

- 九版原生G01的27个程序全部退出0，并逐项匹配约定完成标记；`tests/run.php`每版13组、193或195条断言、0失败；portable每版48条；API每版278个类/接口。
- G01的准确命令、运行时/原生扩展及INI路径、日志和结果见[本批汇总](stable-v1-start-evidence-2026-10-25/g01.json)，[输入摘要](stable-v1-start-evidence-2026-10-25/inputs-before.json)前后保持，所有G01临时资源已清理。这不是F/B/H/C或全项目验收。
- 已逐一重新阅读旧临时包装器/INI，并核对所用本地RPM的签名、包元数据、SHA-256、模块payload摘要、PHP版本或PECL的PHP API/Zend ABI依赖；模块复制到本批自有证据目录。实际新包装器仅以`-d extension=绝对路径`按进程加载，不修改系统默认配置、业务Clock或hrtime/microtime。
- [运行时映射](stable-v1-start-evidence-2026-10-25/runtime-map.json)登记九版原生二进制摘要、包装器完整内容/摘要、扩展来源/版本/文件摘要、实际加载元数据和缺失项。未直接复用旧包装器；原生G01与扩展激活探测分别记录。C01已改为读取同一映射并在版本/文件摘要不符或必要扩展不齐时停止，不能静默回到原生路径。
- 最小离线消费者在PHP8.5执行7个外层检查通过：归档、全新离线安装、文档内PHP来源断言语法、shell包装器语法、安装包portable/core，以及故意预加载工作区类的负对照（预期退出255且`Wrong installed origin`）。负对照是运行器防误用测试，不是SDK失败。367份安装运行时文件逐一相符；没有复制工作区src/vendor，包与安装来源均核对，临时目录已清理。
- 最小消费者的[完整结果](stable-v1-start-evidence-2026-10-25/consumer-validated/consumer-minimal.json)、[执行脚本](stable-v1-start-evidence-2026-10-25/consumer-validated/run.py)及同目录原始日志保留；消费者只有一次成功的独立安装，不是九版C01或后端/HTTP验收。归档与lock摘要、来源断言源码及包装器原文均在该目录。

### 已执行但失败并保留

首轮最小消费者运行器预期Composer提示`Successfully created:`，实际本地Composer输出`Created:`且归档进程退出0，导致运行器自身判据失败；安装和后续当轮未执行。[首轮结果](stable-v1-start-evidence-2026-10-25/consumer-minimal.json)、[原日志](stable-v1-start-evidence-2026-10-25/consumer-archive.log)和[故障定位](stable-v1-start-evidence-2026-10-25/consumer-initial-failure.json)不覆盖。只在新的consumer-validated证据子目录修正准确提示匹配并验证实际归档/安装，没有修改SDK、保护或应用预算。

### 当前显式运行时映射与依赖限制

所有路径相对仓库根；对应命令由下表路径的绝对值作为`R`。本批扩展探测无启动警告，PHP7.2仍无hrtime，没有替换时间函数。

| PHP | F/B/H/C的R（G01仍用/usr/bin/phpXX） | 进程级新增扩展 | 当前完整测试配置 |
| --- | --- | --- | --- |
| 7.2.34 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php72` | sodium、posix | 已具备 |
| 7.3.33 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php73` | sodium | 已具备 |
| 7.4.33 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php74` | sodium、posix | 已具备 |
| 8.0.30 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php80` | sodium | 已具备 |
| 8.1.34 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php81` | 无 | 已具备 |
| 8.2.32 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php82` | igbinary、msgpack、redis | 仍缺版本匹配posix |
| 8.3.35 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php83` | sodium | 已具备 |
| 8.4.23 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php84` | igbinary、msgpack、redis | 仍缺版本匹配posix |
| 8.5.9 | `docs/stable-v1-start-evidence-2026-10-25/runtimes/php85` | 无 | 已具备 |

sodium/7.2与7.4的posix包与原生PHP上游版本相同，但部分Remi包release号不同；这是可核验RPM payload的进程级测试激活，不声称系统RPM依赖安装已满足。Redis6.3.0及其igbinary/msgpack依赖按对应PHP API/Zend ABI核对。旧本地8.2/8.4 process包分别面向8.2.34/8.4.26，与当前8.2.32/8.4.23不同，已拒绝加载，详情记录在runtime-map.json的rejected_modules中；未用“可以加载”代替版本匹配证明。

依赖缺口归入既有阻塞5，不新增第六项。管理后续可安排核验版本匹配的本地包，或审查既有POSIX系统工具备用路径能否满足具体用例；不能静默删测试或降低PHP兼容声明。必要依赖未齐前不展开九版大矩阵；最小消费者通过不关闭时钟、管理超时及旧Webhook失败。

下一组仍为固定B01/B04文件存储与登录共享预算，随后按已审清单的B02/B03/F/H推进；实际执行由管理会话直接安排，不重新请求用户逐步授权。本批未执行这些后端/HTTP组合、Q01诊断或九版消费者，未提交/推送/打标签/发布。
