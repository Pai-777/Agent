# Shell 稳定化与交互化

## 初始验证

拿到 RCE / WebShell 后第一轮至少做：
```bash
id
whoami
uname -a
pwd
mount
```

如果是 PHP 探针，再补：
- `phpinfo()` 关键信息
- `disable_functions`
- Web 根路径
- Apache 模块 / Nginx 配置痕迹

## 交互优先级

1. **现成 CGI / 命令执行接口**：直接复用；
2. **PHP 探针能写文件**：优先写稳一点的 CGI / 面板；
3. **后台文件管理器**：用浏览器编辑远端文件；
4. **复杂 payload**：浏览器 `fetch()` 发 POST。

## ECP / 浏览器交互面板

如果后续要频繁执行命令，建议尽快落一个轻量交互页面：
- 单输入框 + Run 按钮；
- 后台用 `/cgi/x.sh?cmd=` 或既有 WebShell；
- 记录当前 `cwd`；
- 便于后续提权时连续发命令。

适用场景：
- 大量枚举命令；
- 需要避免手动拼长 URL；
- 需要给后续提权、POC 编译、文件读写降成本。

## 远端写文件原则

优先顺序：
1. 浏览器编辑器直接写；
2. `file_put_contents()` 写远端文件；
3. 本地生成文件后上传；
4. base64 投递；
5. HTTP 拉取。

## 命令执行失败时

如果出现：
- PHP 命令函数禁用；
- `/tmp` `noexec`；
- shell 命令被过滤；

则立即切换：
- CGI 执行链；
- 写到可执行目录（如 webroot 下 CGI 目录）；
- 改用浏览器面板发命令；
- 走 SUID/文件读链拿更强能力。
