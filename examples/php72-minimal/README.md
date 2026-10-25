# PHP7.2独立最小登录示例（仅S范围）

本项目是独立Composer消费者，固定使用已验收的soSecurity 1.0.0 ZIP：源码提交`46fa6d44df312082ae77da361186b9cb7dbd0ab3`，SHA256为`0ec1b95079603f53c81a9320eb209bd79e9f5e38f6ccfbef71f4a915a55b83d5`。不会从SDK工作区直接加载源码，不从Packagist下载，也不使用符号链接安装依赖。

只复用包内原样的`examples/legacy-login.php`：登录表单、会话CSRF、本地算术验证码、FileStore共享IP/账号限流、bcrypt校验和登录后会话轮换。账号是本地演示账号，不连接真实用户库。没有E配置、恢复流程、MFA接管、持久收件或后台任务。

## 环境与目录

- 在已验证的WSL/Linux原生文件系统运行；PHP7.2 CLI及json/hash/session，兼容PHP7.2的Composer，Python3.6或更高。无需GD、Redis、MySQL、POSIX PHP扩展。
- `public/`是唯一Web根；`var/`包含独占0700共享状态、会话、离线包、随机演示凭据及安装记录；配置/凭据文件0600。不要将项目根或vendor作为Web根。
- 同一个示例项目的不同浏览器会话共用同一FileStore；MemoryStore/SessionStore不替代共享限流。这里不宣称多主机文件共享或生产部署验证。

## 直接运行

将交付目录中的`php72-minimal-example`源码复制到新的WSL原生目录。以下路径适用本次交付环境，Composer和PHP路径可替换为自己的实际路径：

```sh
DEMO_DIR=$(mktemp -d /tmp/sosecurity-php72-demo.XXXXXX)
cp -R /mnt/c/Users/sohop/Documents/Codex/2026-10-25/codex-for-vscode-sosecurity-sosecurity-goal-2/outputs/php72-minimal-example/. "$DEMO_DIR/"
cd "$DEMO_DIR"
python3 install.py \
  --package /mnt/c/Users/sohop/Documents/Codex/2026-10-25/codex-for-vscode-sosecurity-sosecurity-goal-2/outputs/sosecurity-1.0.0.zip \
  --php /usr/bin/php72 --composer /usr/local/bin/composer
cat var/demo-login.txt
python3 serve.py --port 8080
```

打开`http://127.0.0.1:8080/`，填写随机生成的demo密码及页面算术验证码。Ctrl+C停止。只监听127.0.0.1；HTTP和关闭Secure仅限本机演示，不能照此发布正式站点或暴露到外网。

安装器拒绝覆盖已有var/vendor/锁文件，避免清空现有状态或续办未知结果。失败时保留目录和原始日志；需要重新演示则使用新的独立目录，不删除旧安全状态来解除限流。

安装后的`var/config.json`是实际启动配置：PHP路径、演示账号、bcrypt哈希、状态/会话目录；路径由安装器固定为当前独立目录。共享登录预算沿用原样例：账号+IP组合5次，IP广域100次，表单渲染60次/60秒。其余时间窗/封禁使用包内原策略，不擅自调整。

## 本地验证

在刚安装、尚未手动尝试登录的独立目录执行：

```sh
python3 verify.py
```

验证实际启动配置、真实HTTP表单/JSON、HttpOnly/SameSite、跨会话CSRF拒绝、验证码一次性/错误拒绝、错误密码、成功登录与Session轮换、多个独立会话共用账号+IP预算、429/Retry-After、非法方法及存储故障503。验证使用并保留本目录演示状态，不是自动清理/重置状态；验证后demo账号仍可用于本地查看。错误尝试计入原策略，请勿反复测试同一目录以求绕过封禁。结果见`var/verification.json`和`var/http-server.log`。

## 接入真实项目前的边界

这只是独立本机示例，不操作真实站点。真正接入时由宿主提供参数化用户查询、当前禁用/权限事实、HTTPS、可信代理和可靠会话锁；保留已有认证/MFA。不能把demo账号或测试用配置搬到正式站点。

PHP7.2时钟回拨可能拒绝合法请求并503；依赖/存储故障必须拒绝，结果未知不得自动重试。回滚先恢复可靠旧保护，保留状态与审计；不清空目录、降低保护或开启E。完整S/E说明位于已安装包的`vendor/sohophp/sosecurity/docs/stable-v1-php-adoption.zh-CN.md`。

## 验证来源

安装记录`var/installation.json`绑定固定ZIP、367份运行时文件、780个安装成员和原样登录适配器摘要。示例源码提交与本次实际验证记录另见包外`php72-example-delivery.json`；它们不是依赖ZIP的源码提交，不能混用两种身份。
