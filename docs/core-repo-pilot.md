# CoreRepo 组件接入试点

这是可复现的宿主组件集成检查，不是现有后台完整业务、SSO或生产验收。当前CoreRepo原工作区有未提交变更，试点只使用其已提交基线 `24a64019` 的独立工作区 `/var/www/php/7.2/CoreRepo-sosecurity-pilot`，原工作区和数据库未修改。

## 实际接入范围

`integrations/core-repo/login.php` 在新的Composer消费者中安装SoSecurity，并加载独立工作区实际的 `App\Components\Session\Session/SessionManager`、`App\Components\Csrf` 和 `CsrfTokenStorage`。宿主现有Symfony CSRF及Twig继续使用，不替换其认证/授权/路由。验证码使用SessionStore命名空间，跨会话限流使用独立私有FileStore，登录成功后通过SessionSecurity更新原生Session ID并保留宿主其他数据。

测试只绑定127.0.0.1；Session、共享状态、模拟身份及密码哈希位于临时目录/进程环境，没有加载CoreRepo的settings、数据库配置或远程SSO。HTTP和关闭Secure仅适用于此本地测试。宿主Composer自动加载器仅用于现有第三方依赖，不修改vendor；独立App自动加载器最后注册并优先加载，随后用Reflection核对四个宿主类全部来自独立工作区，避免把原工作区当作已隔离。

```sh
python3 tests/core_repo_pilot.py php72 \
  /var/www/php/7.2/CoreRepo-sosecurity-pilot \
  /var/www/php/7.2/CoreRepo/vendor/autoload.php
```

此命令使用受信任的本地路径；不是从网页接受路径的服务。既有第三方依赖没有经过本次全量重新解析/升级，实际依赖版本和安全维护属于宿主负责范围；不能用本次SoSecurity消费者审计证明旧站全部依赖安全。试点和开发脚本排除Composer发行包。

## 已执行并通过

PHP7.2.34、7.4.33各33项真实HTTP检查：Composer安装；实际宿主类来源；既有CSRF字段/多标签令牌、缺失/伪造/跨访客拒绝；验证码及旧表单重放拒绝；正确登录、Session ID更新且宿主其他数据保留；未知账号/错误密码统一401；IP+账号跨会话预算及429/Retry-After；Twig实际表单渲染；非支持方法405；共享存储故障503、恢复后正常且登录状态保留；私有Session文件。

初次检查发现Composer新注册的自动加载器优先于试点加载器，类来自原工作区；来源校验因此明确拒绝503。调整注册顺序后两版本通过，没有放宽来源断言。

## 下一步真实业务接入

先由宿主选择一个实际登录/注册/联系表单，保留原Csrf/SSO/权限检查，只替换需要改善的验证码和共享失败预算；配置真实登录标识规范化及代理信任，再验证原登录成功/失败、跳转、注销及其他应用SSO。对宿主的Session存储确认锁及生命周期，不默认把SessionStore作为全局账号限流。

默认关闭接入开关，保留旧模板/业务调用路径；先完成隔离数据库/外部服务测试及浏览器验收，再在受控环境启用。撤销接入开关可以回滚业务调用，但不能删除仍有效的安全状态、并将存储故障降级为放行。不能复制本测试的固定身份或私有测试环境变量到生产。

原后台路由、真实管理员/数据库、第三方验证码、SSO及目标站部署仍未执行；本页如实保留这些验收项。
