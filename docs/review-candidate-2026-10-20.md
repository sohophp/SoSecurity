# 本地候选审查包与固定验收清单

日期：2026-10-20（Asia/Shanghai）。候选名称：`review-2026-10-20-01`。

本轮交付是整理现有未提交变更、记录可定位的候选内容并固定验收边界。完成本文、逐文件清单和整理检查后停止；不新增安全功能、不执行完整九版本门禁、不提交或发布。完整 R1—R6 规划保留在 [security-refinement.md](security-refinement.md)，不作为本轮整理工作的退出条件。

## 候选身份与变更清单

- 基线提交：`3ea8812ead75b99a58f14b44b32862fe3336da76`。
- [候选清单](review-candidate-2026-10-20.json)记录全部 Git 已跟踪文件及未忽略的新文件的相对路径、Git 状态、文件类型、可执行位和 SHA-256；清单自身不参与摘要，避免自引用。
- 清单中的 `content_sha256` 是按路径排序的 `files` 数组经紧凑 JSON 编码后的摘要；它标识本地内容，不是 Git 提交、版本标签、发布签名或安全审查结论。
- `resources/api/candidate.json` 仅描述公开 API 契约，不能替代本清单的完整内容身份。
- 忽略文件、`.git`、本机 `vendor` 和 `/tmp` 原型不在候选中；历史日志中的临时路径不能成为安装后的运行依赖。生成清单不移动文件、不清理工作树，也不将历史变更归为本轮新实现。

整理前 `git status --short` 显示 510 项，其中部分是折叠目录。使用 `git status --porcelain=v1 -uall` 展开后，实际为 **819 个变更文件：68 个已跟踪修改、751 个未跟踪文件**。暂存区为空。本轮新增的审查文档和清单另计；最终数量以清单为准。

| 整理前范围 | 变更文件数 | 审查重点 |
| --- | ---: | --- |
| `src/` | 209 | 公共接口、权限边界、状态一致性及基础功能的可选依赖 |
| `tests/` | 377 | 用例是否验证真实拒绝路径、仅本地数据库、运行入口与证据范围 |
| `docs/` | 84 | 历史快照与当前候选区分，已完成与未完成表述 |
| `integrations/` | 64 | OIDC、WebAuthn、PSR-3、PSR-15 独立 Composer 包及各自 PHP 要求 |
| `examples/`、`demo/` | 47 | 宿主授权、配置注入、示例不自动创建生产状态 |
| `resources/` | 27 | SQL／格式迁移与公开 API 清单同步 |
| `bin/`、`.github/` | 4 | 门禁调用、可选测试环境与 CI 定义；配置不等于远端已通过 |
| `skills/` | 2 | 安全检查清单同步；不属于 SDK 运行时代码 |
| 根目录文件 | 5 | Composer 声明、README、SECURITY、CHANGELOG |

## 建议审查顺序

以下是审查批次，不是已完成的逐行安全审查，也不是可直接独立 cherry-pick 的提交。共享工厂、配置、诊断、测试入口和 API 清单存在交叉依赖，实际拆分提交前必须核对依赖。

1. **安装边界与通用基础**：`composer.json`、`src/Security.php`、`src/Configuration/`、`src/Diagnostics/`，以及密码、验证码、存储、HTTP、上传等现有基础接口变更；先核对 PHP 7.2 语法和旧接口兼容。
2. **SQL 与 Outbox 防御性修复**：`src/Support/SqlSchema.php`、`src/Outbox/`、对应 SQL、`tests/outbox-*.php` 及 Outbox 指南。重点审查 SQL 层字节限量、合法二进制往返、超限拒绝及事务不受拒绝操作破坏。
3. **认证、账号与权限扩展**：`src/Auth/`、`Account/`、`Mfa/`、`Authorization/`、`Operation/` 及相关测试／迁移。完整旧备份风险必须作为明确未关闭项保留。
4. **其他可选能力与通知链路**：API 凭据、Webhook、幂等、下载、签名链接、预算、审计和通知。Outbox、SMTP、Worker 只在显式启用的功能中使用；不得成为密码、CSRF 等基础能力的启动条件。
5. **独立适配包、打包与文档**：`integrations/`、消费者测试、归档测试、CI、API 清单、示例和文档。最后检查拆分后的每个提交是否自洽，而不是按目录机械提交。

## 本轮固定验收

| 编号 | 验收要求 | 证据与结论 |
| --- | --- | --- |
| C1 | 全部未忽略的候选文件可定位，修改和新增文件均不遗漏 | JSON 清单、基线提交、内容摘要；生成后独立核对文件集合、摘要、类型和可执行位 |
| C2 | 明确变更范围、审查顺序和相互依赖 | 上表与五个审查批次；不声称 819 个文件已逐行复核 |
| C3 | Composer 基础依赖保持精简，异步能力显式可选 | `require` 仅 PHP `>=7.2 <8.6`、JSON、Hash；无 Outbox 配置时为 `null`，基础工厂不加载 Outbox／SMTP／Worker；两端运行核对 |
| C4 | 已有基础功能在两端运行正常 | 本轮 PHP 7.2.34、8.5.9 的 `tests/portable-core.php` 各 48 项通过；仅测试用 MemoryStore，不代表共享存储或生产 |
| C5 | 安装声明、文档链接与补丁格式可检查 | 本轮 `composer validate --strict --no-check-publish`、本审查文档的相对文件链接检查及 `git diff --check` 通过 |
| C6 | 已验证、未验证及已知风险明确，达到条件后停止 | 本页后续表格；本轮不重跑无源码变化的 Outbox 大型矩阵，不将历史通过扩展成当前完整候选通过 |

**停止条件：C1—C6 满足即结束本轮整理。** 只有本轮清单遗漏、摘要漂移、链接错误或声明核对失败才修正对应交付物。新的安全修复、九版本完整验收、独立审查和发布均单独安排。

## 功能证据与发布边界

| 范围 | 状态 | 可用证据与限制 |
| --- | --- | --- |
| Outbox 限量读取、NUL、超限拒绝 | 既有本地专项已执行并通过 | [验证记录](verification.md)：PHP 7.2／8.5 SQLite 输入边界各 243 项、正文预算各 986 项；私有禁 TCP MySQL 输入各 195 项、硬上限各 8 项。本轮未重跑 |
| 因子通知事件、本机 SMTP、通知与 Outbox 密钥轮换 | 既有本地专项已执行并通过 | [验收工作单](release-readiness.md)及[验证记录](verification.md)；本机 TLS 不代表外部 SMTP 接受或真实收件箱投递。本轮未重跑 |
| 当前候选完整 PHP 7.2—8.5 九版本发行门禁 | 未执行 | 历史不同快照的通过记录不能拼成当前候选完整通过 |
| 远端 CI、真实下游、外部服务、独立安全审查 | 未执行或未完成 | 本轮整理不补做，也不把作者自检称为独立审查 |
| Git 提交、标签、发布和部署 | 未执行 | 候选内容摘要不等于发布许可；暂存与提交需按最终确定的范围执行 |

## 尚存风险与下一轮

**完整有效旧备份仍可能使旧认证状态重新生效。** 主 SDK 尚未关闭该风险；详情见[完整旧备份的新鲜度与安全代际](account-factor-freshness.md)。独立原型和 HMAC 完整性检查不能作为主 SDK 已修复的依据。

当前变更跨度大，尚未完成逐文件安全审查和同一候选完整发行验证。因此，本交付物是供审查的本地候选，不具备“稳定版已验收”的结论。基础包的 PHP 支持范围也不意味着每个独立适配包具有相同最低版本。

下一轮建议先按上述顺序审查现有变更，形成明确接受／退回清单，冻结实际准备提交的范围；完整备份防回滚修复独立立项。达到下一轮固定清单后同样停止，不以补齐所有规划为隐含退出条件。

## 复核候选内容

在仓库根目录运行以下只读检查。新增、删除、修改、类型或可执行位变化都会令检查失败；清单自身只做结构与内部摘要一致性检查，不提供防恶意替换保证。

```bash
python3 - <<'PY'
import hashlib, json, os, pathlib, subprocess
manifest = 'docs/review-candidate-2026-10-20.json'
data = json.loads(pathlib.Path(manifest).read_text())
raw = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'])
paths = sorted(set(p.decode() for p in raw.split(b'\0') if p) - {manifest})
assert paths == [row['path'] for row in data['files']], 'file set changed'
subprocess.run(['git', 'merge-base', '--is-ancestor', data['base_commit'], 'HEAD'], check=True)
for row in data['files']:
    p = pathlib.Path(row['path'])
    kind = 'symlink' if p.is_symlink() else 'file'
    body = os.fsencode(os.readlink(p)) if kind == 'symlink' else p.read_bytes()
    assert kind == row['kind'], row['path']
    assert bool(p.lstat().st_mode & 0o111) == row['executable'], row['path']
    assert hashlib.sha256(body).hexdigest() == row['sha256'], row['path']
encoded = json.dumps(data['files'], ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
assert hashlib.sha256(encoded).hexdigest() == data['content_sha256']
print('PASS candidate content:', len(paths), 'files;', data['content_sha256'])
PY
```
