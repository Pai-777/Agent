# 上传 / 任意写文件 → RCE 工作流

## 触发条件

出现任一情况就切进来：
- 文件上传表单；
- 头像/附件/媒体上传；
- 插件/主题/模板上传；
- 后台文件管理器；
- 模板编辑器；
- 任意文件写入；
- SQLi 能写文件；
- Shell 已经能 `file_put_contents()`。

## 总原则

**先找最短写入链，再做绕过。**

优先级：
1. 后台文件管理器直写 webroot；
2. 已知可执行 CGI / PHP 目录直写；
3. 上传目录直接执行；
4. 上传目录被禁用后，再做后缀和服务器绕过。

## Step 1：确认落点与执行限制

必须明确：
- 文件最终落到哪里；
- 是 Apache 还是 Nginx；
- `.htaccess` 是否生效；
- PHP 是否禁执行；
- 是否存在 CGI handler；
- 是否只有图片后缀可上传。

## Step 2：最小验证文件

先上传/写入最小探针，而不是完整大马：
- PHP：`<?php phpinfo(); ?>` 或更小的回显探针；
- CGI：输出 `Content-Type` 和 `id`；
- 静态回显文件：确认路径可访问。

## Step 3：绕过分支

### A. Apache + AllowOverride 有效
优先尝试：
- `.htaccess` + `AddType` / `AddHandler`
- `.htaccess` + `Options +ExecCGI`
- `.cgi` / `.sh` 作为 CGI 脚本

典型思路：
```apache
Options +ExecCGI
AddHandler cgi-script .cgi .sh
```

### B. PHP 后缀被拦截
尝试：
- `.phtml`
- `.php5`
- `.pht`
- 大小写 / 双后缀 / 截断（按环境判断）

### C. 上传目录禁 PHP
看是否能：
- 在子目录单独写 `.htaccess`；
- 写 CGI 而不是 PHP；
- 写到别的可执行目录；
- 利用后台编辑器直接写站点根目录。

## Step 4：优先利用后台文件管理器

如果已经拿到后台账号，不要执着于前台上传绕过。

优先做：
1. 登录后台；
2. 找文件管理器 / 模板编辑器；
3. 直接写 webroot 下的探针、`.htaccess`、CGI；
4. 验证命令执行；
5. 再考虑 shell 交互化。

## Step 5：验证顺序

1. 文件是否成功落地；
2. URL 是否可访问；
3. 是否按预期解释执行；
4. 命令执行函数是否被禁用；
5. 若 PHP 执行受限，是否能转 CGI；
6. 若命令执行成功，再升级为交互式面板。

## 特别规则

- 发现上传点，不要只停留在“文件可上传”；必须继续判断“是否可执行”。
- 若 `disable_functions` 禁了 `system/exec/passthru`，优先考虑 CGI、SUID helper、后台文件写入其他解释器链。
- 若 Chrome MCP 可直接编辑远端文件，优先用它，避免 PowerShell 破坏 payload。
