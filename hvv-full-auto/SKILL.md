---
name: hvv-full-auto
description: |
  HVV 全自动化渗透测试总控 Skill，基于 CyberSecurity-Skills-master 技能库渗透模块。
  作为总执行入口，覆盖 PTES 全流程：信息搜集→漏洞扫描→漏洞利用→权限提升→后渗透→横向移动→持久化→痕迹清除→报告撰写。
  同时内置多目标分诊前置、路径优先、提示优先、POC/模板调度、Chrome MCP / Kali MCP / Shell 路由与低交互自动推进规则。
  当用户提及 HVV、护网、渗透、红队、攻防演练、漏洞挖掘、内网渗透，或要求完整自动化执行 / 批量目标分诊时触发。
---

# HVV 全自动化渗透测试（总控 Skill）

## 目标

这个 Skill 的目标是：
- 作为 **总控型执行 Skill**，保留完整阶段树，而不是只保留精简版首段流程；
- 在授权的 HVV / CTF / 演练场景中尽量减少渗透人员来回提示；
- 收到目标后优先自主推进，而不是频繁停下来提问；
- 遇到具体路径、CVE、payload、账号、截图、POC 提示时，先验证提示，再继续泛化枚举；
- 优先走最短利用链：入口 → 关键路径 → 漏洞确认 → 初始权限 → 提权 → 后渗透 → 证据 → 报告。

## 设计定位

这是一个 **总控 / 总执行 / 总调度 Skill**：

1. 它本身要保留完整的 PTES / HVV 主流程与阶段决策。
2. 它负责决定当前该打哪一条链、该用哪类工具、该切到哪个子工作流。
3. 它可以把细分动作分发给：
   - `references/*.md` 中的专门工作流；
   - `CyberSecurity-Skills-master` 中的细分类技能；
   - 本地 POC / nuclei 模板 / Kali MCP / Chrome MCP / Shell。
4. **不要把这个 Skill 做成只有前半段的精简路由器。**
5. 细节可以下沉，但总控全流程必须保留在这里。
6. 批量场景下，优先把“nuclei 识别层 → 定向批量 N-day 锁定 → Top N 深打”做成固定前置链。

## 模式选择

### 模式 A：单目标深打

适用：
- 单个 URL / 域名 / IP / 后台入口
- 少量目标（默认 `<= 20`）
- 用户已经指出具体路径、参数、CVE、账号、截图或利用点

处理方式：
- 直接进入本 Skill 的单目标主流程（Phase 1-9）

### 模式 B：多目标分诊 / 资产池编排

适用：
- 大量目标（默认 `> 20`）
- 用户给出 `txt/csv/xlsx` 资产清单、URL 列表、IP 列表、CIDR、子域名池
- 用户明确说“5000 个目标”“批量资产”“先挑好打的”“先分诊再深打”

处理方式：
1. 先进入 **Phase 0：多目标分诊（模块 00）**
2. 输出：
   - 去重后的目标清单
   - 指纹簇
   - 价值评分
   - 可利用性评分
   - Top N 深打队列
3. 然后再把高分目标回流到本 Skill 的单目标深打流程

如需加载独立前置 Skill，使用：
- `C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\SKILL.md`

## 技能库位置

- 主技能库：`C:\Users\pai\.cc-switch\skills\CyberSecurity-Skills-master`
- 查询工具：`python C:\Users\pai\.cc-switch\skills\CyberSecurity-Skills-master\skill_query.py`
- 本地 POC 库：`C:\Users\pai\Desktop\tool\Awesome-POC-master`
- 本地 Nuclei 模板库：`C:\Users\pai\nuclei-templates`
- 多目标分诊 Skill：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage`

---

## 默认执行总则

1. **被动优先，路径优先**：先看首页、`robots.txt`、`sitemap.xml`、已知 JS、管理入口、调试页、公开文件，再做主动探测。
2. **提示优先于盲扫**：用户一旦给出具体路径、CVE、参数、利用方向，先按提示验证，不要继续大范围枚举。
3. **证明一条链，再扩展**：先证明一个参数 / 一个上传点 / 一个后台入口能走通，再横向扩展。
4. **最短利用链优先**：优先选择最短能拿结果的路径，不为了“流程完整”而跳过现成线索。
5. **拿到 shell 后立即提权**：不要拿到 WebShell 还停在目录浏览阶段。
6. **区分读 root 文件与真正 root shell**：文件读取型提权不等于 uid=0。
7. **所有结论都要附带证据**：路径、参数、回显、权限、文件、进程、挂载、版本、截图或命令输出。
8. **减少 PowerShell 负面影响**：如果 payload 被转义、吃字符、换行破坏，优先改用 Chrome MCP 页面编辑器、浏览器 `fetch()`、或先在工作区生成文件再投递。
9. **只按当前阶段加载需要的 reference / 子技能**：避免一次性把所有细节灌入上下文。
10. **批量目标先分诊后深打**：不要把单目标深打逻辑直接平铺到 5000 个目标上。
11. **批量目标优先做 N-day 锁定**：先用定向漏扫锁定疑似 N-day，再把命中目标交给单目标深打流程。

## 模块化索引

- `modules/00-multi-target-gateway.md`：多目标入口、样本优先、分诊回流
- `modules/01-single-target-entry.md`：单目标入口与首轮动作
- `modules/02-vuln-to-shell.md`：漏洞确认、后台利用、上传/RCE、getshell
- `modules/03-shell-to-privesc.md`：shell 稳定化、环境枚举、提权
- `modules/04-postex-lateral-report.md`：后渗透、横向、持久化、痕迹清理、报告

## 工具总路由

### 1. Shell / 本地脚本

用于：
- `rg` 检索技能库、POC 库、模板库、源码；
- 生成 payload、编码/解码、拼装源码、编译辅助文件；
- 本地逆向下载回来的 ELF / SUID / 脚本；
- 构造批量验证脚本；
- 在浏览器 / PowerShell 不适合时本地生成文件再投递。

### 2. Kali MCP

用于：
- `nmap_scan`：端口、服务、版本探测；
- `nikto_scan`：Web 基础风险补充；
- `gobuster_scan` / `dirb_scan`：目录和文件枚举；
- `sqlmap_scan`：疑似 SQL 注入后的自动化深挖；
- 其他适合网络侧扫描的标准化动作。

### 3. Chrome MCP

用于：
- 后台登录、保持会话；
- 文件管理器、模板编辑器、插件上传、头像上传；
- 富文本、动态表单、CSRF、复杂 POST；
- 需要真实浏览器环境的上传与交互；
- PowerShell 容易吃掉 payload 的场景；
- 通过浏览器 `fetch()` / 页面编辑器写入 shell、`.htaccess`、CGI。

### 4. POC / 模板调度

用于：
- 根据产品名、组件名、版本、CVE、路径特征，从本地知识库快速定位可复用验证逻辑；
- 先读、先理解、先无害验证，再按需执行；
- 不把模板库 / POC 仓库当“盲扫弹药库”。

详细工具切换规则见：`references/tool-routing.md`

---

## POC / 模板库调度规则

### 默认检索源

- POC / EXP 仓库：`C:\Users\pai\Desktop\tool\Awesome-POC-master`
- Nuclei 模板库：`C:\Users\pai\nuclei-templates`

### 检索原则

1. 先识别产品、组件、版本、路径、CVE、利用前置条件。
2. 先用 `rg` 同时精确检索本地 POC 库与 Nuclei 模板库，而不是凭感觉盲试：
   - `rg -n -i "<组件|产品|CVE|版本|漏洞类型>" C:\Users\pai\Desktop\tool\Awesome-POC-master`
   - `rg -n -i "<组件|产品|CVE|版本|漏洞类型|关键路径>" C:\Users\pai\nuclei-templates`
3. 如果用户已经给出路径、参数或文件名，要把这些关键词一起带入检索。
4. 只读取与当前指纹强相关的 POC / 模板文件，不批量灌整个仓库。
5. 优先无害验证：版本/路径/错误回显/时间差/只读端点。
6. 若前置条件不满足，明确记录“未命中 / 不适用”，不要为了跑 POC 而跑 POC。

### 命中 Nuclei 模板后的处理

命中 `nuclei-templates` 后，至少抽出：
- 模板 `id`
- `info` / `severity` / `tags`
- `requests` / `http`
- `matchers`
- `extractors`
- `variables`
- 目标路径、请求方法、认证前/后条件

然后：
1. 先手工最小验证该路径/参数/状态码是否匹配；
2. 再按需运行 **单模板或极小模板集**；
3. 不要一上来全量扫整个 `C:\Users\pai\nuclei-templates`。

### 示例检索

```powershell
rg -n -i "dedecms|recommend.php|CVE-2017-17731" "C:\Users\pai\Desktop\tool\Awesome-POC-master"
rg -n -i "dedecms|recommend.php|CVE-2017-17731" "C:\Users\pai\nuclei-templates"
rg -n -i "upload|avatar|htaccess|cgi|file upload" "C:\Users\pai\nuclei-templates"
rg -n -i "copy-fail|CVE-2026-31431|authencesn|AF_ALG" "C:\Users\pai\Desktop\tool\Awesome-POC-master"
```

详细规则见：`references/poc-dispatch.md`

---

## 参考工作流入口

- **工具选择与切换**：`references/tool-routing.md`
- **路径与敏感文件收集**：`references/path-harvest.md`
- **SQL 注入工作流**：`references/sqli-workflow.md`
- **上传 / 任意写文件 → RCE 工作流**：`references/upload-rce-workflow.md`
- **Shell 稳定化 / 交互化**：`references/shell-ops.md`
- **Linux / 容器提权工作流**：`references/privesc-workflow.md`
- **本地 POC 调度细则**：`references/poc-dispatch.md`

---

## 自动化引擎：目标识别 → 技能调度

收到目标后，自动识别类型并选择攻击路径：

```text
目标输入 → 类型识别
├── 多目标列表 / 资产池 / Excel / CSV / CIDR → Phase 0 多目标分诊 → Top N / 样本簇 → Web 深打（Phase 1-9）
├── IP / 域名 / URL → Web 渗透全流程（Phase 1-9）
├── 源码 / 代码仓库 → 代码审计（模块 12）
├── 二进制 / 固件 → 逆向工程（模块 13）
├── API / 微服务 → API 安全（模块 34）
├── Docker / K8s → 容器逃逸（模块 33）
├── IoT 设备 / 固件 → 物联网安全（模块 21）
└── 移动应用 APK / IPA → 移动安全（模块 10）
```

### 技术栈自动识别

对 Web 目标自动识别：
- **服务器**：Nginx / Apache / IIS / Tomcat / WebLogic / WebSphere
- **语言**：PHP / Java / Python / Node.js / Go / .NET
- **框架**：Spring / Struts / Django / Flask / Laravel / ThinkPHP / Shiro
- **数据库**：MySQL / MSSQL / Oracle / PostgreSQL / MongoDB / Redis
- **CMS**：WordPress / Drupal / Joomla / 帝国 / 织梦 / DedeCMS
- **中间件**：Redis / Memcached / RabbitMQ / Kafka / Elasticsearch
- **WAF / CDN**：安全狗、云锁、长亭雷池、阿里云WAF、Cloudflare 等

识别到产品/组件/CVE 后：
1. 先查路径与参数是否命中；
2. 再查 POC / 模板库；
3. 再决定扫描、验证还是直接利用。

---

## Phase 0：多目标分诊（模块 00）

**触发：**
- 目标数量明显很多（默认 `> 20`）
- 输入是 URL / 域名 / IP / CIDR 列表
- 用户要求“先挑好打的”“先漏扫再深打”“先分批处理”“5000 个目标怎么排优先级”

### 本阶段目标

1. **目标归一化**
   - 去空行、去注释、去重复
   - 统一 URL / 域名 / IP / 端口格式
   - 合并同站点同端口重复项
2. **nuclei 识别层**
   - 优先跑 `http/technologies`、`http/exposed-panels`、精选 `http/exposures`
   - 先拿到产品 / 组件 / 面板 / 暴露面，而不是先写自定义指纹脚本
   - 标准入口优先使用 `C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\scripts\nuclei_fingerprint.py`
3. **识别结果整理 / 产品映射**
   - 产出 `technologies`、`candidate_products`、`exposed_panels`、`exposure_hits`、`recommended_nuclei_tags`
   - 先识别，再选 N-day 模板
   - 仅在需要 `robots.txt` / 登录口 / favicon / generator 等补充字段时，才回退 `fingerprint_targets.py`
4. **价值分类**
   - 行业：医院 / 教育 / 政务 / 金融 / 企业 / 工控
   - 系统：SSO / 4A / OA / VPN / 邮件 / 堡垒机 / 教务 / HIS / PACS / 数据库管理
5. **可利用性分类**
   - 已知产品 / 组件 / 老版本
   - 路径泄露 / 报错 / 参数异常
   - 登录口 / 后台口 / 上传口 / API 暴露
   - 本地 POC / nuclei 模板命中
6. **样本优先**
   - 按 favicon / 标题 / server / 技术栈 / 路径形态聚类
   - 每簇先选 1~3 个样本验证，不要整簇盲打
7. **生成深打队列**
   - Top N 高价值高可利用目标
   - 样本簇代表目标
   - 次级补充目标
8. **批量 N-day 锁定**
   - 对高价值 / 高信号目标池运行低噪声定向 nuclei 漏扫
   - 优先吃 `nuclei_fingerprint.py` 产出的 `recommended_nuclei_tags` / `technologies` / `candidate_products` / `exposed_panels`
   - 输出 `nday_locked_targets.*`
   - 将命中目标优先交给单目标深打流程

### 强制规则

1. 对 5000 目标 **禁止直接套用单目标深打逻辑逐个重打**。
2. 对 5000 目标 **禁止一上来全量跑整个 nuclei 模板库**。
3. 优先：
   - nuclei 识别层
   - 行业/系统分类
   - 样本聚类
   - 定向单模板 / 小模板集验证
4. 命中某个产品链后，再回扫同簇资产。

### 工具路由

- 清洗、归一化、去重、聚类、评分：Shell / 本地脚本
- 大批量技术识别 / 面板识别 / 暴露识别：优先 `nuclei` + `nuclei-templates`
- fallback 元数据补充（robots/login/favicon/generator）：本地轻探针 / Kali MCP
- 少量高分目标的真实交互验证：Chrome MCP
- 批量数据库/表单型深利用：回流给单目标 `hvv-full-auto`

### 输出要求

本阶段至少产出：
- `normalized_targets.*`
- `clustered_targets.*`
- `scored_targets.*`
- `top_targets.*`
- Markdown 简报：为什么这些目标值得先打
- `nday_locked_targets.*`：为什么这些目标应优先深打

详细规则：
- 总体流程：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\references\workflow.md`
- 推荐识别入口脚本：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\scripts\nuclei_fingerprint.py`
- 指纹识别与 N-day 映射：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\references\fingerprint-nday-mapping.md`
- 批量 N-day 策略：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\references\bulk-nday-scan.md`
- 评分模型：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\references\priority-scoring.md`
- 行业与系统关键词：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\references\sector-keywords.md`
- nuclei 选模板：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\references\nuclei-template-selection.md`
- 分发与样本簇策略：`C:\Users\pai\.cc-switch\skills\hvv-multi-target-triage\references\dispatch-rules.md`

---

## Phase 1：信息搜集（模块 01）

**触发：** 收到任何目标时首先执行

### 收到 URL / 站点时的固定首轮动作

按下面顺序执行，除非用户已经给出了更具体的入口：

1. 打开首页，记录：
   - `Server`
   - 语言 / CMS 指纹
   - 状态码
   - 跳转
   - 页面中出现的路径
2. 主动看：
   - `/robots.txt`
   - `/sitemap.xml`
   - `/favicon.ico`
   - 常见后台路径（如 `/admin`、`/login`、`/dede`、`/manage`）
3. 抽取首页 HTML / JS 中的：
   - API 路径
   - 上传目录
   - 调试入口
   - 备份/安装路径
4. 如果 `robots.txt`、注释、JS、报错页泄露了具体路径，立即回访该路径。
5. 如果用户已经指出路径（例如某个 `recommend.php`、上传页、后台地址），直接跳过去验证。

详细动作见：`references/path-harvest.md`

### 被动信息搜集
**技能：** `01-信息搜集-Reconnaissance/skills/被动信息搜集-PassiveRecon.md`

- 公开页面、报错页、注释、前端 JS
- 证书、历史快照、公开仓库、搜索引擎缓存
- 已知管理面板、后台目录、安装残留、备份文件

### 主动信息搜集
**技能：** `01-信息搜集-Reconnaissance/skills/主动信息搜集-ActiveRecon.md`

- 端口扫描（nmap/masscan/rustscan）
- 服务版本识别、OS 指纹
- 仅在需要时做窄范围目录爆破

### DNS 枚举
**技能：** `01-信息搜集-Reconnaissance/skills/DNS枚举-DNSEnumeration.md`

- 区域传送测试、DNS 暴力枚举、缓存投毒测试

### 子域名探测
**技能：** `01-信息搜集-Reconnaissance/skills/子域名探测-SubdomainDiscovery.md`

- subfinder / amass / OneForAll、子域名接管检测

### 网络空间搜索引擎
**技能：** `01-信息搜集-Reconnaissance/skills/网络空间搜索引擎-OSINT-SearchEngine.md`

- Shodan / Fofa / ZoomEye / Hunter、Google Hacking

### 目标技术栈识别
**技能：** `01-信息搜集-Reconnaissance/skills/目标技术栈识别-TechStackFingerprint.md`

- Wappalyzer / WhatWeb 指纹、框架版本、WAF/CDN 检测
- 将产品、框架、版本、CVE、路径作为 POC / 模板检索关键词

### 社会工程学信息
**技能：** `01-信息搜集-Reconnaissance/skills/社会工程学信息-SocialEngineeringInfo.md`

- 密码泄露数据库、社工库关联（仅在授权范围内）

---

## Phase 2：漏洞扫描（模块 02）

**触发：** 信息搜集完成后

### 默认扫描策略

1. 目录/文件探测：优先围绕已泄露路径和 CMS 指纹做窄范围枚举。
2. 组件/CVE：命中指纹后再查 POC 库和 `nuclei-templates`，不要反过来先铺天盖地试 CVE。
3. 若本地 `nuclei-templates` 已经命中具体 CVE / 组件模板，优先缩到单模板验证，不做全库扫描。
4. 用户已经指出某个参数/某个路径可能存在问题时，停止继续盲扫，先验证该点。

### Web 漏洞扫描
**技能：** `02-漏洞扫描-VulnerabilityScanning/skills/Web漏洞扫描-WebVulnScan.md`

- nuclei / xray / nikto 自动扫描
- 目录爆破（dirsearch / gobuster / ffuf）
- 备份文件、API 端点、调试接口发现

### 网络漏洞扫描
**技能：** `02-漏洞扫描-VulnerabilityScanning/skills/网络漏洞扫描-NetworkVulnScan.md`

- CVE 漏洞扫描、服务漏洞检测

### 数据库安全评估
**技能：** `02-漏洞扫描-VulnerabilityScanning/skills/数据库安全评估-DatabaseAssessment.md`

- 弱口令、默认配置、权限审计

### 配置审计扫描
**技能：** `02-漏洞扫描-VulnerabilityScanning/skills/配置审计扫描-ConfigAuditScan.md`

- SSL/TLS 审计、HTTP 安全头、CORS 配置

### 漏洞扫描器自动化
**技能：** `02-漏洞扫描-VulnerabilityScanning/skills/漏洞扫描器自动化-VulnScannerAutomation.md`

- 扫描器编排、结果去重、优先级排序
- 扫描器命中 CVE/组件时，先回到本地 POC / 模板库核对适用条件与无害验证方式

---

## Phase 3：漏洞利用（模块 03）

**触发：** 发现可利用漏洞时

### 触发器与自动切换规则

#### A. 遇到参数异常 / 报错 / 引号闭合异常
立即进入 `references/sqli-workflow.md`

适用信号：
- 单引号后报错；
- 布尔差异明显；
- 时间延迟可控；
- 用户明确指出“这里可能 SQL 注入”；
- 组件已知存在该参数相关 SQLi。

默认策略：
1. 先手工快速确认；
2. 一旦成立或高疑似，马上用 `sqlmap` 深挖；
3. 拿到账号、表、文件写能力后，立即进入后台登录 / 文件写入 / getshell 工作流。

#### B. 遇到上传点 / 文件管理器 / 模板编辑器 / 任意写文件
立即进入 `references/upload-rce-workflow.md`

适用信号：
- 存在头像/附件/媒体上传；
- 后台文件管理器可访问站点目录；
- 任意文件写入、模板修改、插件上传、日志写入；
- 前台上传路径可控，或能写 `.htaccess` / CGI / PHP 脚本。

默认策略：
1. 先确认落点目录；
2. 判断执行限制（PHP 禁止、后缀过滤、Web 服务器类型、`.htaccess` 是否生效）；
3. 优先最短链：直接写 webroot > 写 CGI 目录 > 写上传目录并绕过；
4. 上传失败再进入绕过分支，不要一开始就跑全套花式后缀。

#### C. 遇到后台登录 / CSRF / 动态表单 / 富文本编辑器
优先使用 Chrome MCP。

适用场景：
- 登录后台并保持会话；
- 管理面板里的文件编辑器；
- 上传组件需要真实浏览器交互；
- 复杂 `POST` payload 被 PowerShell 破坏；
- 需要看 XHR、cookie、DOM、跳转结果。

### Web 漏洞利用
**技能：** `03-漏洞利用-Exploitation/skills/Web漏洞利用-WebExploitation.md`

- 文件上传绕过、任意文件读取、目录穿越、反序列化

### SQL 注入利用
**技能：** `03-漏洞利用-Exploitation/skills/SQL注入利用-SQLInjection.md`

- 联合/报错/盲注/堆叠注入、WAF 绕过、sqlmap 自动化

### XSS 跨站脚本
**技能：** `03-漏洞利用-Exploitation/skills/XSS跨站脚本-XSSExploitation.md`

- 反射/存储/DOM XSS、CSP 绕过、Cookie 窃取

### 文件包含利用
**技能：** `03-漏洞利用-Exploitation/skills/文件包含利用-FileInclusion.md`

- LFI / RFI、PHP 伪协议、日志投毒

### 命令注入
**技能：** `03-漏洞利用-Exploitation/skills/命令注入-CommandInjection.md`

- 命令拼接、空格/关键字绕过、反弹 Shell

### SSRF 服务端请求伪造
**技能：** `03-漏洞利用-Exploitation/skills/SSRF服务端请求伪造-SSRF.md`

- gopher / dict / file 协议、内网探测、云元数据攻击

### 认证绕过
**技能：** `03-漏洞利用-Exploitation/skills/认证绕过-AuthBypass.md`

- 弱口令爆破、默认凭据、JWT 攻击、Session 劫持

### Metasploit 框架利用
**技能：** `03-漏洞利用-Exploitation/skills/Metasploit框架利用-Metasploit.md`

- 漏洞模块、Payload 生成、后渗透模块

---

## Phase 4：获取初始权限与权限提升（模块 04）

**触发：** 获取初始命令执行、WebShell、后台文件写能力或低权限 shell 后

### 固定动作

拿到命令执行或 WebShell 后，第一轮必须至少收集：

```bash
id
whoami
uname -a
pwd
mount
cat /proc/self/status | grep ^Cap
find / -perm -4000 -type f 2>/dev/null
find / -writable -user root -type f 2>/dev/null | head -n 100
cat /proc/1/cmdline
```

然后根据结果自动选择：
- 普通 WebShell → 升级为更稳的 CGI / 交互式 Shell；
- 容器环境 → 看 `PID 1`、挂载、entrypoint、seccomp；
- 自定义 SUID → 拉回本地最小逆向分析；
- root 可写脚本/配置 → 先证明真实执行链，再写入。

Shell 稳定化见：`references/shell-ops.md`

### 自动优先级

拿到初始 shell 后，优先级默认如下：

1. **自定义 SUID / 可疑二进制**
2. **root:root 且 world-writable 的脚本、服务配置、入口脚本**
3. **计划任务 / 服务配置错误 / capabilities**
4. **容器误配置 / 可利用挂载 / entrypoint**
5. **内核提权 POC（只有前置条件命中时才编译执行）**

### 强制区分两类结果

- **文件读取型提权**：例如 SUID 程序代读 `/root/flag3.txt`
- **真正 root shell / uid=0**：例如得到 root 命令执行或可持续 root 会话

不要把“能读 root 文件”误写成“已经 root shell”。

详细决策树见：`references/privesc-workflow.md`

### Linux 提权
**技能：** `04-权限提升-PrivilegeEscalation/skills/Linux提权-LinuxPrivEsc.md`

- SUID / SGID、Sudo 错误、Cron 劫持、内核漏洞、Capabilities

### Windows 提权
**技能：** `04-权限提升-PrivilegeEscalation/skills/Windows提权-WindowsPrivEsc.md`

- 服务配置错误、Unquoted Service Path、Potato 系列、注册表劫持

### 内核漏洞与服务配置错误提权
**技能：** `04-权限提升-PrivilegeEscalation/skills/内核漏洞与服务配置错误提权-KernelServicePrivEsc.md`

- DirtyCow / DirtyPipe / PrintNightmare / ZeroLogon

### 凭证窃取与利用
**技能：** `04-权限提升-PrivilegeEscalation/skills/凭证窃取与利用-CredentialTheft.md`

- Mimikatz、浏览器密码、配置文件凭证、内存密码

---

## Phase 5：后渗透（模块 05）

**触发：** 提权成功，或已获得足够稳定的主机级控制能力后

### 总控要求

后渗透阶段不是“可选附录”，而是总控 Skill 必须保留的正式阶段。默认目标：

1. 环境画像：主机、用户、服务、内网网段、业务目录、敏感数据位置；
2. 权限巩固：稳定 shell、会话回连、交互化；
3. 情报获取：凭据、配置、部署关系、信任关系；
4. 高价值线索判断：域控、数据库、堡垒机、统一身份、容器控制面；
5. 为横向移动、持久化、证据留存和报告输出做准备。

### 信息收集与数据窃取
**技能：** `05-后渗透-PostExploitation/skills/信息收集与数据窃取-InfoGatheringDataExfil.md`

- 内网信息收集、敏感文件搜索、数据外传通道

### 凭证转储与哈希传递
**技能：** `05-后渗透-PostExploitation/skills/凭证转储与哈希传递-CredentialDumpingPtH.md`

- SAM / LSA / SYSTEM 转储、NTLM 哈希传递、Kerberos 票据攻击

### 远程控制与交互式 Shell
**技能：** `05-后渗透-PostExploitation/skills/远程控制与交互式Shell-RemoteControlShell.md`

- Shell 升级、C2 框架、隧道建立

### 键盘记录与屏幕捕获
**技能：** `05-后渗透-PostExploitation/skills/键盘记录与屏幕捕获-KeyloggingScreenCapture.md`

- 键盘记录、屏幕截图、剪贴板监控

---

## Phase 6：横向移动（模块 06）

**触发：** 后渗透信息收集完成，已识别出可用凭据、信任关系、可达资产或内网通道后

### 总控要求

1. 先判断目标价值，再决定是否横向。
2. 优先打：
   - 域控 / 统一身份 / 堡垒机 / 数据库 / 云控台 / 容器控制面
   - 与当前主机存在明确信任关系的资产
3. 先建通道，再移动；先证明确实可达，再打利用链。

### 横向移动
**技能：** `06-横向移动-LateralMovement/skills/横向移动-LateralMovement.md`

- Pass the Hash / Ticket、PsExec / WMI / WinRM、DCOM 利用

### 内网代理与隧道
**技能：** `06-横向移动-LateralMovement/skills/内网代理与隧道-InternalProxyTunnel.md`

- frp / reGeorg / chisel、SSH / DNS / ICMP 隧道

### PsExec 与 WMI 远程执行
**技能：** `06-横向移动-LateralMovement/skills/PsExec与WMI远程执行-PsExecWMI.md`

- PsExec、WMI 远程命令、WinRM

---

## Phase 7：持久化（模块 07）

**触发：** 已拿到高价值目标，且场景允许做持久化验证时

### 总控要求

1. 优先可逆、可清理、可说明的持久化方式。
2. 先判断是：
   - Web 层持久化
   - 主机层持久化
   - 账户 / 凭据层持久化
   - 票据 / 密钥层持久化
3. 持久化动作必须记录落点、清理方式、验证方式。

### 持久化
**技能：** `07-持久化-Persistence/skills/持久化-Persistence.md`

- WebShell 植入、后门账户、计划任务

### 启动项与登录自动执行
**技能：** `07-持久化-Persistence/skills/启动项与登录自动执行-BootLogonAutostart.md`

- 注册表启动项、服务创建、登录脚本

### 账户创建与凭证持久化
**技能：** `07-持久化-Persistence/skills/账户持久化-AccountPersistence.md`

- 隐藏账户、SSH 密钥、Golden / Silver Ticket

---

## Phase 8：痕迹清除（模块 08）

**触发：** 每个关键动作完成后，以及任务结束前

### 总控要求

1. 把“写入过什么、改过什么、上传过什么、启动过什么”记成清单。
2. 优先清理：
   - 测试文件
   - shell 落点
   - 临时脚本
   - 浏览器编辑残留
   - 日志中的明显测试痕迹
3. 若场景是 CTF/题目环境，以不破坏复现与判定为前提。

### 痕迹清除与反取证
**技能：** `08-痕迹清除-CoveringTracks/skills/痕迹清除-CoveringTracks.md`

- 日志清理、文件时间戳修改、历史记录清除

### 进程注入与代码注入
**技能：** `08-痕迹清除-CoveringTracks/skills/进程注入与代码注入-ProcessInjection.md`

- DLL 注入、进程 Hollow、APC 注入

### 代码混淆与反分析
**技能：** `08-痕迹清除-CoveringTracks/skills/代码混淆与反分析-ObfuscationAntiAnalysis.md`

- 免杀处理、代码混淆、反调试

### AMSI 绕过与 EDR 规避
**技能：** `08-痕迹清除-CoveringTracks/skills/AMSI绕过与EDR规避-AMSIByPassEDREvasion.md`

- AMSI 补丁、ETW 绕过、EDR 绕过

---

## Phase 9：报告撰写（模块 09）

**触发：** 渗透测试完成后，或阶段成果需要快速提交时

### 总控要求

报告不是最后才想起来的补充项，而是整个 Skill 持续产出的结果面。

全过程都要持续记录：
- 时间线
- 入口点
- 关键参数
- 账号口令
- 利用链
- 权限变化
- 证据截图
- shell 落点
- 清理动作

### 渗透测试报告编写
**技能：** `09-报告撰写-Reporting/skills/报告编写-PentestReport.md`

- 攻击路径图、漏洞详情、修复建议

### 漏洞评级与 CVSS 评分
**技能：** `09-报告撰写-Reporting/skills/漏洞评级与CVSS-VulnRatingCVSS.md`

- CVSS 3.1 评分、风险等级划分

### 安全报告模板
**技能：** `09-报告撰写-Reporting/skills/安全报告模板-Markdown.md`

- Markdown 报告模板

---

## 条件触发模块

### 自动条件切换（减少人工指挥）

遇到以下情况时，不需要等用户再次提示，直接切换工作流：

- `robots.txt` / JS / 注释 / 报错页泄露路径 → 回访该路径；
- 某参数加 `'` 报错 → 进入 SQLi 流程；
- 发现上传点 / 文件管理器 / 任意写文件 → 进入上传 / RCE 流程；
- 拿到后台账号 → Chrome MCP 登录并找文件编辑、上传、模板、插件入口；
- 拿到命令执行 → 立即环境枚举并进入提权流程；
- 发现 SUID 自定义程序 → 拉本地分析，不只停留在“读 flag”；
- 发现内核 POC 提示 → 先做接口、权限、挂载、seccomp、可执行路径探测；
- PowerShell 影响 payload → 立刻改走 Chrome MCP / 本地文件投递；
- 命中 `nuclei-templates` → 先读模板，再做单模板验证，不全量乱扫。

### 发现源码 → 代码审计（模块 12）

**触发：** 源码泄露、GitHub/GitLab 仓库、代码审计需求

| 语言 | 技能文件 |
|:---|:---|
| PHP | `12-代码审计-CodeAudit/skills/PHP代码审计-PHPCodeAudit.md` |
| Java | `12-代码审计-CodeAudit/skills/Java代码审计-JavaCodeAudit.md` |
| JavaScript | `12-代码审计-CodeAudit/skills/JavaScript代码审计-JSCodeAudit.md` |
| Python | `12-代码审计-CodeAudit/skills/Python代码审计-PythonCodeAudit.md` |
| C/C++ | `12-代码审计-CodeAudit/skills/C代码审计-CCodeAudit.md` / `C++代码审计-CPPCodeAudit.md` |
| Go | `12-代码审计-CodeAudit/skills/Go代码审计-GoCodeAudit.md` |
| Rust | `12-代码审计-CodeAudit/skills/Rust代码审计-RustCodeAudit.md` |

### 发现二进制 → 逆向工程（模块 13）

**触发：** 二进制文件、固件、恶意软件样本

| 技能 | 技能文件 |
|:---|:---|
| 静态分析 | `13-逆向工程-ReverseEngineering/skills/静态逆向分析-StaticReverseAnalysis.md` |
| 动态调试 | `13-逆向工程-ReverseEngineering/skills/动态调试分析-DynamicDebugAnalysis.md` |
| 恶意软件 | `13-逆向工程-ReverseEngineering/skills/恶意软件分析-MalwareAnalysis.md` |

### 发现 API → API 安全（模块 34）

**触发：** REST/GraphQL/微服务 API

| 技能 | 技能文件 |
|:---|:---|
| OWASP API | `34-API安全-APISecurity/skills/OWASP API安全测试-OWASPAPISecurityTesting.md` |
| 认证授权 | `34-API安全-APISecurity/skills/API认证与授权安全-APIAuthAuthorizationSecurity.md` |
| GraphQL | `34-API安全-APISecurity/skills/GraphQL与微服务API安全-GraphQLMicroserviceAPISecurity.md` |

### 发现容器 → 容器逃逸（模块 33）

**触发：** Docker、Kubernetes、容器环境

| 技能 | 技能文件 |
|:---|:---|
| 镜像扫描 | `33-容器安全-ContainerSecurity/skills/容器镜像安全与漏洞扫描-ContainerImageSecurityScanning.md` |
| RBAC | `33-容器安全-ContainerSecurity/skills/Kubernetes RBAC与安全策略-KubernetesRBACSecurityPolicy.md` |
| 运行时 | `33-容器安全-ContainerSecurity/skills/容器运行时安全-Falco-ContainerRuntimeSecurityFalco.md` |
| 逃逸 | `33-容器安全-ContainerSecurity/skills/容器逃逸检测与防御-ContainerEscapeDetectionDefense.md` |

### 发现 IoT 设备 → 物联网安全（模块 21）

**触发：** 路由器、摄像头、嵌入式设备

| 技能 | 技能文件 |
|:---|:---|
| 固件逆向 | `21-物联网安全-IoT-Security/skills/固件逆向与分析-FirmwareReverseEngineering.md` |
| 无线协议 | `21-物联网安全-IoT-Security/skills/BLE-Zigbee-Z-Wave无线安全测试-WirelessProtocolSecurity.md` |
| 通信协议 | `21-物联网安全-IoT-Security/skills/物联网通信协议安全-IoTCommunicationSecurity.md` |
| 硬件安全 | `21-物联网安全-IoT-Security/skills/嵌入式设备硬件安全测试-EmbeddedHardwareSecurity.md` |

### 发现移动应用 → 移动安全（模块 10）

**触发：** APK、IPA、移动应用

| 技能 | 技能文件 |
|:---|:---|
| Android | `10-移动安全-MobileSecurity/skills/Android安全测试-AndroidSecurityTest.md` |
| iOS | `10-移动安全-MobileSecurity/skills/iOS安全测试-iOSSecurityTest.md` |

---

## 自动化工作流示例

### Web 渗透全流程

```text
输入：http://target.example.com

[Phase 1] 信息搜集
→ 首页/robots/JS/后台入口
→ 识别出 Nginx + PHP + MySQL
→ 目录线索：/plus/ /upload/ /dede/

[Phase 2] 漏洞扫描
→ 围绕已泄露路径窄范围枚举
→ nuclei 命中 DedeCMS / ThinkPHP 相关模板
→ 单模板验证，不全量扫库

[Phase 3] 漏洞利用
→ 参数加引号报错，切 SQLi 工作流
→ sqlmap 拿到后台账号
→ Chrome MCP 登录后台
→ 上传 / 写文件 / 模板编辑 getshell

[Phase 4] 初始权限与提权
→ 环境枚举
→ SUID / root 可写脚本 / 容器误配置 / 内核 POC 前置探测
→ 拿到 root shell 或 root 文件读取能力

[Phase 5] 后渗透
→ 凭据、配置、内网网段、敏感数据定位

[Phase 6] 横向移动
→ 根据凭据和通道攻击高价值资产

[Phase 7] 持久化
→ 可逆、可清理、可验证

[Phase 8] 痕迹清除
→ 清理测试文件与 shell 落点

[Phase 9] 报告撰写
→ 输出完整利用链、证据、修复建议
```

### 发现源码

```text
输入：GitHub / GitLab 仓库
→ 识别语言
→ 调用对应代码审计模块
→ 自动扫描：硬编码密钥、SQL注入、RCE、文件包含
→ 生成代码审计报告
```

### 发现容器

```text
输入：Docker / Kubernetes 环境
→ 镜像漏洞扫描
→ RBAC 权限审计
→ 挂载、特权、capabilities、socket、seccomp 检查
→ 逃逸路径检测
→ 生成容器安全报告
```

---

## 评分标准（HVV 专用）

### 得分优先级（按分值排序）

```yaml
高价值目标（优先攻击）:
  1. 核心生产网入侵：5000分
  2. 逻辑强隔离业务内网：2000分
  3. 0day 漏洞利用：最高5000分
  4. 统一身份管理平台（SSO/4A）：管理员权限200分 + 每个可登入系统50分（上限2000分）
  5. 域控系统权限：管理员权限200分 + 域内设备10分/台（上限1000分）
  6. 数据库权限：管理员权限100分（上限2000分）
  7. 服务器主机权限：管理员权限100分（上限2000分）
  8. 获取数据：按数据量计分（上限3000分）

中价值目标:
  1. 堡垒机/运维机：管理员权限200分 + 托管服务器10分/台（上限1000分）
  2. 办公自动化系统：管理员权限200分（上限1000分）
  3. 邮箱权限：管理员权限200分（上限1000分）
  4. 网络设备权限：100-200分/台（上限1000分）
  5. 云管理平台：管理员权限200分 + 云上主机10分/台（上限1000分）

低价值目标（快速得分）:
  1. 终端权限：PC 10分/台，打印机/摄像头 5分/台（上限500分）
  2. 域名控制权：一级域名100分，二级域名50分（上限500分）
  3. Web应用权限：管理员权限100分（上限2000分）
```

### 得分策略

```yaml
攻击路径选择:
  1. 优先攻击互联网暴露面：Web应用、邮件系统、VPN
  2. 利用漏洞获取初始权限，然后横向移动
  3. 优先获取域控、数据库、堡垒机等高价值目标
  4. 获取数据时，优先获取个人信息、业务配置与关键证据
  5. 寻找 0day / Nday 高价值链路，可获得额外高分

报告提交策略:
  1. 及时提交成果，避免被其他队伍抢先
  2. 确保报告完整，包含漏洞发现和攻击过程
  3. 提供关键证据截图，证明时间、数量、权限
  4. 重大成果需详细描述，争取额外计分
```

---

## 漏洞利用技术要点

### Web 应用漏洞优先级

```yaml
高价值漏洞（优先寻找）:
  1. 远程代码执行（RCE）
  2. SQL注入
  3. 文件上传漏洞
  4. 反序列化漏洞
  5. SSRF

中价值漏洞:
  1. 文件包含漏洞
  2. 命令注入
  3. 逻辑漏洞
  4. 信息泄露

低价值漏洞:
  1. XSS
  2. CSRF
  3. 目录遍历
```

### 漏洞利用技术细节

```yaml
SQL注入:
  - 优先尝试联合注入、报错注入
  - 绕过 WAF：编码、注释、大小写混合
  - 获取数据：数据库用户、密码哈希、敏感数据
  - 进一步利用：执行命令、读写文件（需要权限）

文件上传:
  - 绕过前端验证、MIME 检测、后缀名过滤
  - 特殊后缀：.php5, .phtml, .php.jpg
  - 利用解析漏洞：Apache、Nginx、IIS
  - 上传 WebShell 后优先升级为更稳的交互式 shell

命令注入:
  - 命令拼接：&&, ||, ;, |, ``, $()
  - 绕过空格：${IFS}, {cat,/etc/passwd}
  - 绕过关键字：双写、大小写、编码
  - 反弹 Shell：bash, nc, python

SSRF:
  - 协议支持：http, gopher, dict, file
  - 内网探测：127.0.0.1, 10.0.0.0/8, 172.16.0.0/12
  - 攻击内部服务：Redis, MySQL, FastCGI
  - 云元数据：169.254.169.254

反序列化:
  - Java：ysoserial
  - PHP：phpggc
  - 先找利用链，再找 payload
  - 白名单、黑名单、防护绕过要结合框架判断
```

---

## 数据获取与标记

```yaml
数据获取策略:
  1. 优先获取个人信息、业务数据、运行配置、信任关系证据
  2. 以“证明能力、证明影响、证明数量”为目标
  3. 报告中保留脱敏样例、统计信息、时间证据

证据要求:
  1. 截图中体现 URL / 参数 / 权限 / 时间
  2. 数据类证据体现数量、字段、归属
  3. 权限类证据体现当前用户、主机、控制范围
  4. 提权类证据体现 uid/gid、root 文件、shell 级别差异
```

---

## 输出格式

默认使用短格式汇报，降低对话负担：

- **结果**：现在拿到了什么
- **证据**：1~3 条关键路径 / 回显 / 权限 / 文件
- **下一步**：马上要做什么

例如：
- 结果：确认 `type` 参数报错型 SQL 注入。
- 证据：`recommend.php?aid=1&type=test'` 报 SQL 错；CMS 指纹为 DedeCMS；`robots.txt` 泄露了 `plus/` 路径。
- 下一步：切 `sqlmap` 跑库，优先拿后台账号和可写点。

如果是阶段性总结，再补：
- **影响**：当前可达到的权限/数据/资产范围
- **清理点**：写入了什么，需要怎么回滚

---

## 行为规范

### 必须遵守的规则

1. 默认自主推进，不因常规分支频繁向用户确认。
2. 除非存在明显分歧或多条代价很高的路线，否则直接选最短链执行。
3. 记录所有关键路径、参数、口令、shell 文件、落地位置与验证 URL，便于复现。
4. 对用户提供的情报（路径、POC、payload、账户）优先验证，不忽略。
5. 对“robots.txt 是否高敏”这类问题，默认回答：
   **`robots.txt` 本身通常不算高敏，但里面泄露的路径是高价值线索，必须逐条跟进。**

### 风险规避

```yaml
操作规范:
  1. 测试前确认目标授权范围
  2. 避免无意义高强度盲扫
  3. 有现成线索时优先走线索，不重复枚举
  4. 及时清理测试文件、日志、shell 落点
  5. 记录所有操作，便于报告撰写

时间管理:
  1. 先拿结果，再补宽度
  2. 先拿 shell，再补枚举
  3. 先拿提权，再补持久化与横移
  4. 预留报告撰写时间
```

---

## 工具路径配置

```yaml
渗透测试工具:
  # 信息搜集
  nmap: "nmap"
  subfinder: "subfinder"
  amass: "amass"

  # 漏洞扫描
  nuclei: "C:\\Users\\pai\\Desktop\\tool\\nuclei_3.8.0_windows_amd64\\nuclei.exe"
  nuclei_templates: "C:\\Users\\pai\\nuclei-templates"
  nikto: "nikto"
  xray: "xray"

  # 目录扫描
  dirsearch: "dirsearch"
  gobuster: "gobuster"
  ffuf: "ffuf"

  # 漏洞利用
  sqlmap: "sqlmap"
  ysoserial: "ysoserial"
  phpggc: "phpggc"

  # 后渗透
  mimikatz: "mimikatz"
  bloodhound: "bloodhound"
  sharpHound: "SharpHound"

  # 横向移动
  psexec: "PsExec"
  frp: "frp"
  chisel: "chisel"

  # C2 框架
  cobaltstrike: "C:\\Users\\pai\\Desktop\\tool\\vshell_4.9.3\\v_windows_amd64"

  # 综合工具
  burpsuite: "BurpSuite"
  metasploit: "msfconsole"
```

---

## 报告模板

### 漏洞报告结构

```markdown
# 漏洞报告

## 基本信息
- 目标单位：xxx
- 目标系统：xxx系统
- 漏洞类型：SQL注入 / 文件上传 / RCE / 提权等
- 发现时间：2026-05-xx xx:xx:xx
- 报告作者：攻击队名称 / 操作人

## 漏洞描述
简要描述漏洞位置、类型、影响范围。

## 漏洞复现
1. 访问目标 URL
2. 输入测试 Payload
3. 观察响应差异 / 错误回显 / 时间延迟
4. 使用自动化工具进一步验证

## 攻击路径
互联网入口 → 中间落点 → 主机权限 → 提权 → 横向 / 数据 / 证据

## 权限获取
- 获取权限类型：WebShell / 系统权限 / 数据库权限 / 后台权限
- 权限级别：普通用户 / 管理员 / root / SYSTEM
- 可控范围：服务器数量、终端数量、系统数量

## 数据获取（如适用）
- 数据类型：个人信息 / 业务数据 / 运行数据
- 数据量：xxx条记录
- 数据示例：脱敏处理

## 证据截图
1. 漏洞证明截图：URL、Payload、响应
2. 权限获取截图：登录界面、命令执行、uid/gid
3. 数据获取截图：数据内容、数量统计
4. 时间证明截图：系统时间、日志时间

## 修复建议
1. 输入过滤 / 参数化查询 / 权限收缩
2. 上传校验 / 执行目录隔离 / 中间件配置修复
3. 凭据轮换 / 权限最小化 / 补丁升级
4. 增加检测与审计

## 附录
- 完整攻击脚本
- 工具使用说明
- 参考链接
```

---

## 工具依赖

```text
必备：nmap masscan nuclei nikto sqlmap dirsearch gobuster subfinder amass BurpSuite Metasploit
常用：Mimikatz BloodHound frp chisel ysoserial phpggc
可选：CobaltStrike Volatility xray trufflehog
```

---

## 参考资源

详细技术参考，请参考 `CyberSecurity-Skills-master` 库中的模块：

- `01-信息搜集-Reconnaissance/` - 信息搜集完整流程
- `02-漏洞扫描-VulnerabilityScanning/` - 漏洞扫描完整流程
- `03-漏洞利用-Exploitation/` - 漏洞利用完整流程
- `04-权限提升-PrivilegeEscalation/` - 权限提升完整流程
- `05-后渗透-PostExploitation/` - 后渗透完整流程
- `06-横向移动-LateralMovement/` - 横向移动完整流程
- `07-持久化-Persistence/` - 持久化完整流程
- `08-痕迹清除-CoveringTracks/` - 痕迹清除完整流程
- `09-报告撰写-Reporting/` - 报告撰写完整流程

本 Skill 本地 references：
- `references/tool-routing.md`
- `references/path-harvest.md`
- `references/sqli-workflow.md`
- `references/upload-rce-workflow.md`
- `references/shell-ops.md`
- `references/privesc-workflow.md`
- `references/poc-dispatch.md`

快速参考：
- `python C:\Users\pai\.cc-switch\skills\CyberSecurity-Skills-master\skill_query.py`
- `skill_query.py search --keyword <关键词>`
