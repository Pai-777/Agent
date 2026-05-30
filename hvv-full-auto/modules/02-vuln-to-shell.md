# 模块 02：漏洞确认 → getshell

优先链路：
1. SQLi
2. 上传 / 任意写文件
3. 后台模板 / 文件编辑
4. RCE / 命令执行

工作习惯：
- 报错/参数异常 → 先最小验证，再 `sqlmap`
- 上传点 → 先看落点和执行限制，再走最短链
- PowerShell 吃 payload → 改走 Chrome MCP / 本地投递
- 拿到后台 → 优先 Chrome MCP 真实登录验证
