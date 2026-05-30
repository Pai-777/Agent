# 工具路由与使用场景

## 1. Shell / 本地脚本

优先用途：
- 本地 `rg` 检索 POC 库、技能库、代码仓库；
- 生成 payload、编码/解码、拼装源码、编译本地辅助文件；
- 启本地临时 HTTP 服务给目标拉取源码/二进制；
- 对已下载的 ELF、脚本、配置做最小分析。

适用信号：
- 需要快速 grep；
- 需要生成 base64 / C / Python 文件；
- 需要本地逆向自定义 SUID 二进制；
- 需要规避浏览器上下文或批量编辑本地文件。

## 2. Kali MCP

### nmap_scan
用于：端口、服务识别。

适用场景：
- 目标不止一个 Web 端口；
- 需要确认 SSH / Redis / DB / 管理口；
- 需要版本探测。

### gobuster_scan / dirb_scan
用于：目录、后台、备份文件枚举。

适用场景：
- `robots.txt` / CMS 指纹已给出大致路径；
- 需要围绕 `/plus/`、`/uploads/`、`/admin/` 窄扫；
- 需要对某个子目录补目录树。

### nikto_scan
用于：Web 服务器弱配置、已知路径、常见危险文件补充发现。

适用场景：
- 需要快速补一遍 Apache/Nginx 常见暴露面；
- 已发现中间件指纹，希望找已知默认路径。

### sqlmap_scan
用于：参数已疑似/确认 SQL 注入后的自动化利用。

适用场景：
- 参数加引号报错；
- 布尔/时间注入已成立；
- 需要枚举数据库、表、列、凭据；
- 需要自动化跑 `--batch`，减少人工手输。

见：`sqli-workflow.md`

## 3. Chrome MCP

优先用途：
- 登录后台并维持 cookie / session；
- 表单、CSRF、富文本、文件管理器、上传组件；
- 浏览器中直接 `fetch()` 调 WebShell / CGI / API；
- 复杂 payload 写远端文件，避免 PowerShell 转义破坏；
- 读取 XHR / DOM / 渲染后的数据；
- 做页面快照、校验回显。

### 必用场景

1. **后台登录**
   - 用户名/密码已拿到；
   - 需要实际看后台有哪些文件管理、模板、上传、插件入口。

2. **文件上传 / 文件管理器**
   - 需要用真实浏览器点上传；
   - 需要在在线编辑器里写 `.htaccess`、PHP、CGI；
   - 多个字段、隐藏字段、token 难以手工维护。

3. **WebShell / CGI 交互**
   - 用 `evaluate_script` + `fetch()` 直接请求 `/cgi/x.sh?cmd=...`；
   - 用页面写一个简易交互面板（如 `ecp.php`），降低后续操作成本。

### 常用动作

- `take_snapshot`：先拿 uid，再点按钮/输入；
- `fill_form`：登录表单优先一次性填；
- `evaluate_script`：页面内发 `fetch()`、拼 URL、发 POST；
- `upload_file`：需要真文件上传时使用；
- `new_page`：直接打开验证 URL；
- `list_network_requests`：看真实请求路径和参数。

## 4. PowerShell 何时降级

如果出现以下情况，应主动放弃继续用 PowerShell 直接拼 payload：
- 单引号、双引号、反斜杠、换行被吃；
- CGI / PHP / Python 源码在命令行中难以稳定表达；
- POST 数据过长或带特殊字符；
- 已经有 Chrome MCP 可直接在页面里写文件或发请求。

此时改用：
- Chrome MCP 页面编辑器；
- 浏览器 `fetch()` POST；
- 本地工作区生成文件，再通过上传 / HTTP 拉取 / base64 投递。
