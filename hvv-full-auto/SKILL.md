---
name: hvv-full-auto
description: |
  HVV 全自动化渗透测试 Skill，基于 CyberSecurity-Skills-master 技能库渗透模块。
  覆盖 PTES 全流程：信息搜集→漏洞扫描→漏洞利用→权限提升→后渗透→横向移动→持久化→痕迹清除→报告撰写。
  根据目标特征自动调度：Web渗透、代码审计、逆向工程、API安全、容器逃逸、IoT固件。
  当用户提及 HVV、护网、渗透、红队、攻防演练、漏洞挖掘、内网渗透 时触发。
---

# HVV 全自动化渗透测试

## 技能库位置

`C:\Users\pai\.cc-switch\skills\CyberSecurity-Skills-master`

查询工具：`python C:\Users\pai\.cc-switch\skills\CyberSecurity-Skills-master\skill_query.py`

---

## POC 知识库调度

主 Skill 不保存具体目标、站点、一次性漏洞点或实测 URL；可复用漏洞验证逻辑优先从本地 POC 知识库检索并按需读取：

- POC 知识库：`C:\Users\pai\Desktop\tool\Awesome-POC-master`
- 索引入口：`README.md`
- 分类目录：`CMS漏洞/`、`OA产品漏洞/`、`Web应用漏洞/`、`中间件漏洞/`、`云安全漏洞/`、`人工智能漏洞/`、`开发框架漏洞/`、`开发语言漏洞/`、`操作系统漏洞/`、`数据库漏洞/`、`网络设备漏洞/`、`base/`

调用规则：

1. Phase 1/2 先识别组件、产品、框架、版本、CVE、服务指纹和可访问路径。
2. 用 `rg -n -i "<组件|产品|CVE|版本|漏洞类型>" C:\Users\pai\Desktop\tool\Awesome-POC-master` 搜索候选 POC。
3. 只读取与当前指纹强相关的候选文件；不要批量加载整个仓库。
4. 使用 POC 前先核对适用版本、认证前/后条件、影响端点、请求方法、成功判据和副作用。
5. 优先做无害验证：版本/指纹匹配、只读端点、错误回显、时间差、DNS/HTTP 回连观测；避免直接写文件、执行破坏性命令或批量利用。
6. 若 POC 与现场指纹不匹配，记录为“未命中/不适用”，不要强行尝试。
7. 若命中多个候选，按“产品精确匹配 > CVE 精确匹配 > 版本范围匹配 > 漏洞类型泛匹配”排序。
8. 结论中区分：已验证漏洞、疑似风险、配置问题、扫描器误报。

检索模板：

```powershell
rg -n -i "grafana|CVE-2021-43798" "C:\Users\pai\Desktop\tool\Awesome-POC-master"
rg -n -i "struts|s2-067|CVE-2024-53677" "C:\Users\pai\Desktop\tool\Awesome-POC-master"
rg -n -i "vite|CVE-2025-30208|任意文件读取" "C:\Users\pai\Desktop\tool\Awesome-POC-master"
```

输出要求：只引用被实际读取并与目标指纹匹配的 POC 文件路径；不要把 POC 仓库中的漏洞清单整体复制进报告。

---
## 自动化引擎：目标识别 → 技能调度

收到目标后，自动识别类型并选择攻击路径：

```
目标输入 → 类型识别
├── IP/域名/URL → Web 渗透全流程（Phase 1-9）
├── 源码/代码仓库 → 代码审计（模块 12）
├── 二进制/固件 → 逆向工程（模块 13）
├── API/微服务 → API 安全（模块 34）
├── Docker/K8s → 容器逃逸（模块 33）
├── IoT 设备/固件 → 物联网安全（模块 21）
└── 移动应用 APK/IPA → 移动安全（模块 10）
```

### 技术栈自动识别

对 Web 目标自动识别：
- **服务器**：Nginx/Apache/IIS/Tomcat/WebLogic/WebSphere
- **语言**：PHP/Java/Python/Node.js/Go/.NET
- **框架**：Spring/Struts/Django/Flask/Laravel/ThinkPHP/Shiro
- **数据库**：MySQL/MSSQL/Oracle/PostgreSQL/MongoDB/Redis
- **CMS**：WordPress/Drupal/Joomla/帝国/织梦
- **中间件**：Redis/Memcached/RabbitMQ/Kafka/Elasticsearch
- **WAF/CDN**：安全狗、云锁、长亭雷池、阿里云WAF、Cloudflare 等；识别到产品/组件/CVE 后优先检索 POC 知识库

---

## Phase 1：信息搜集（模块 01）

**触发：** 收到任何目标时首先执行

### 被动信息搜集
**技能：** `01-信息搜集-Reconnaissance/skills/被动信息搜集-PassiveRecon.md`

- WHOIS / DNS 记录（A/MX/NS/TXT）
- 子域名被动收集（crt.sh、VirusTotal、SecurityTrails）
- IP 历史解析、邮箱收集、搜索引擎缓存

### 主动信息搜集
**技能：** `01-信息搜集-Reconnaissance/skills/主动信息搜集-ActiveRecon.md`

- 端口扫描（nmap/masscan/rustscan）
- 服务版本识别、OS 指纹

### DNS 枚举
**技能：** `01-信息搜集-Reconnaissance/skills/DNS枚举-DNSEnumeration.md`

- 区域传送测试、DNS 暴力枚举、缓存投毒测试

### 子域名探测
**技能：** `01-信息搜集-Reconnaissance/skills/子域名探测-SubdomainDiscovery.md`

- subfinder/amass/OneForAll、子域名接管检测

### 网络空间搜索引擎
**技能：** `01-信息搜集-Reconnaissance/skills/网络空间搜索引擎-OSINT-SearchEngine.md`

- Shodan/Fofa/ZoomEye/Hunter、Google Hacking

### 目标技术栈识别
**技能：** `01-信息搜集-Reconnaissance/skills/目标技术栈识别-TechStackFingerprint.md`

- Wappalyzer/WhatWeb 指纹、框架版本、WAF/CDN 检测；将产品、框架、版本、CVE 作为 POC 知识库检索关键词

### 社会工程学信息
**技能：** `01-信息搜集-Reconnaissance/skills/社会工程学信息-SocialEngineeringInfo.md`

- 密码泄露数据库、社工库关联

---

## Phase 2：漏洞扫描（模块 02）

**触发：** 信息搜集完成后

### Web 漏洞扫描
**技能：** `02-漏洞扫描-VulnerabilityScanning/skills/Web漏洞扫描-WebVulnScan.md`

- nuclei/xray/nikto 自动扫描
- 目录爆破（dirsearch/gobuster/ffuf）
- 备份文件、API 端点发现

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

- 扫描器编排、结果去重、优先级排序；扫描器命中 CVE/组件时，先到 POC 知识库核对适用条件与无害验证方式

---

## Phase 3：漏洞利用（模块 03）

**触发：** 发现可利用漏洞时

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

- LFI/RFI、PHP 伪协议、日志投毒

### 命令注入
**技能：** `03-漏洞利用-Exploitation/skills/命令注入-CommandInjection.md`

- 命令拼接、空格/关键字绕过、反弹 Shell

### SSRF 服务端请求伪造
**技能：** `03-漏洞利用-Exploitation/skills/SSRF服务端请求伪造-SSRF.md`

- gopher/dict/file 协议、内网探测、云元数据攻击

### 认证绕过
**技能：** `03-漏洞利用-Exploitation/skills/认证绕过-AuthBypass.md`

- 弱口令爆破、默认凭据、JWT 攻击、Session 劫持

### Metasploit 框架利用
**技能：** `03-漏洞利用-Exploitation/skills/Metasploit框架利用-Metasploit.md`

- 漏洞模块、Payload 生成、后渗透模块

---

## Phase 4：权限提升（模块 04）

**触发：** 获取初始权限后

### Linux 提权
**技能：** `04-权限提升-PrivilegeEscalation/skills/Linux提权-LinuxPrivEsc.md`

- SUID/SGID、Sudo 错误、Cron 劫持、内核漏洞、Capabilities

### Windows 提权
**技能：** `04-权限提升-PrivilegeEscalation/skills/Windows提权-WindowsPrivEsc.md`

- 服务配置错误、Unquoted Service Path、Potato 系列、注册表劫持

### 内核漏洞与服务配置错误提权
**技能：** `04-权限提升-PrivilegeEscalation/skills/内核漏洞与服务配置错误提权-KernelServicePrivEsc.md`

- DirtyCow/DirtyPipe、PrintNightmare、ZeroLogon

### 凭证窃取与利用
**技能：** `04-权限提升-PrivilegeEscalation/skills/凭证窃取与利用-CredentialTheft.md`

- Mimikatz、浏览器密码、配置文件凭证、内存密码

---

## Phase 5：后渗透（模块 05）

**触发：** 权限提升成功后

### 信息收集与数据窃取
**技能：** `05-后渗透-PostExploitation/skills/信息收集与数据窃取-InfoGatheringDataExfil.md`

- 内网信息收集、敏感文件搜索、数据外传通道

### 凭证转储与哈希传递
**技能：** `05-后渗透-PostExploitation/skills/凭证转储与哈希传递-CredentialDumpingPtH.md`

- SAM/LSA/SYSTEM 转储、NTLM 哈希传递、Kerberos 票据攻击

### 远程控制与交互式 Shell
**技能：** `05-后渗透-PostExploitation/skills/远程控制与交互式Shell-RemoteControlShell.md`

- Shell 升级、C2 框架、隧道建立

### 键盘记录与屏幕捕获
**技能：** `05-后渗透-PostExploitation/skills/键盘记录与屏幕捕获-KeyloggingScreenCapture.md`

- 键盘记录、屏幕截图、剪贴板监控

---

## Phase 6：横向移动（模块 06）

**触发：** 后渗透信息收集完成后

### 横向移动
**技能：** `06-横向移动-LateralMovement/skills/横向移动-LateralMovement.md`

- Pass the Hash/Ticket、PsExec/WMI/WinRM、DCOM 利用

### 内网代理与隧道
**技能：** `06-横向移动-LateralMovement/skills/内网代理与隧道-InternalProxyTunnel.md`

- frp/reGeorg/chisel、SSH/DNS/ICMP 隧道

### PsExec 与 WMI 远程执行
**技能：** `06-横向移动-LateralMovement/skills/PsExec与WMI远程执行-PsExecWMI.md`

- PsExec、WMI 远程命令、WinRM

---

## Phase 7：持久化（模块 07）

**触发：** 横向移动到高价值目标后

### 持久化
**技能：** `07-持久化-Persistence/skills/持久化-Persistence.md`

- WebShell 植入、后门账户、计划任务

### 启动项与登录自动执行
**技能：** `07-持久化-Persistence/skills/启动项与登录自动执行-BootLogonAutostart.md`

- 注册表启动项、服务创建、登录脚本

### 账户创建与凭证持久化
**技能：** `07-持久化-Persistence/skills/账户持久化-AccountPersistence.md`

- 隐藏账户、SSH 密钥、Golden/Silver Ticket

---

## Phase 8：痕迹清除（模块 08）

**触发：** 每次操作完成后

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

**触发：** 渗透测试完成后

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

```
输入：http://target.example.com

[Phase 1] 信息搜集
→ WHOIS/DNS/子域名 → 识别出 Nginx + PHP + MySQL
→ 端口扫描：80, 443, 3306
→ 目录爆破：/admin, /backup, /phpmyadmin

[Phase 2] 漏洞扫描
→ nuclei 发现 ThinkPHP RCE
→ 目录爆破发现 /backup/sql.bak

[Phase 3] 漏洞利用
→ ThinkPHP RCE 获取 WebShell
→ SQL 注入获取管理员密码

[Phase 4] 权限提升
→ Linux SUID 提权 → root

[Phase 5] 后渗透
→ 凭证收集、内网信息

[Phase 6] 横向移动
→ 发现域环境 → 哈希传递

[Phase 8] 痕迹清除

[Phase 9] 报告撰写
```

### 发现源码

```
输入：GitHub 仓库链接

→ 识别语言 → 调用对应代码审计模块
→ 自动扫描：硬编码密钥、SQL注入、RCE、文件包含
→ 生成代码审计报告
```

### 发现容器

```
输入：Kubernetes 集群

→ 镜像漏洞扫描
→ RBAC 权限审计
→ 逃逸路径检测
→ 生成容器安全报告
```

---

## 评分标准（HVV 专用）

### 得分优先级（按分值排序）

```yaml
高价值目标（优先攻击）:
  1. 核心生产网入侵：5000分（如铁路调度专网、银行核心账务网）
  2. 逻辑强隔离业务内网：2000分（行业专网）
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
  1. 终端权限：PC 10分/台，打印机/摄像头5分/台（上限500分）
  2. 域名控制权：一级域名100分，二级域名50分（上限500分）
  3. Web应用权限：管理员权限100分（上限2000分）
```

### 得分策略

```yaml
攻击路径选择:
  1. 优先攻击互联网暴露面：Web应用、邮件系统、VPN
  2. 利用漏洞获取初始权限，然后横向移动
  3. 优先获取域控、数据库、堡垒机等高价值目标
  4. 获取数据时，优先获取个人信息（100-20000条100分）
  5. 寻找0day漏洞，可获得额外高分

报告提交策略:
  1. 及时提交成果，避免被其他队伍抢先
  2. 确保报告完整，包含漏洞发现和攻击过程
  3. 提供关键证据截图，证明时间、数量等
  4. 重大成果需详细描述，争取额外计分
```

---

## 漏洞利用技术要点

### Web 应用漏洞优先级

```yaml
高价值漏洞（优先寻找）:
  1. 远程代码执行（RCE）：直接获取服务器权限
  2. SQL注入：获取数据库权限，可能获取服务器权限
  3. 文件上传漏洞：上传WebShell获取权限
  4. 反序列化漏洞：Java/PHP反序列化执行命令
  5. 服务器端请求伪造（SSRF）：内网探测，攻击内部服务

中价值漏洞:
  1. 文件包含漏洞：读取敏感文件，可能执行代码
  2. 命令注入：执行系统命令
  3. 逻辑漏洞：密码重置、越权访问
  4. 信息泄露：配置文件、数据库信息

低价值漏洞:
  1. XSS：窃取Cookie，钓鱼攻击
  2. CSRF：伪造请求
  3. 目录遍历：读取文件
```

### 漏洞利用技术细节

```yaml
SQL注入:
  - 优先尝试联合注入、报错注入
  - 绕过WAF：使用编码、注释、大小写混合
  - 获取数据：数据库用户、密码哈希、敏感数据
  - 进一步利用：执行命令、读写文件（需要权限）

文件上传:
  - 绕过前端验证、MIME检测、后缀名过滤
  - 使用特殊后缀：.php5, .phtml, .php.jpg
  - 利用解析漏洞：Apache、Nginx、IIS
  - 上传WebShell后，提权获取服务器权限

命令注入:
  - 命令拼接：&&, ||, ;, |, ``, $()
  - 绕过空格：${IFS}, {cat,/etc/passwd}
  - 绕过关键字：双写、大小写、编码
  - 反弹Shell：bash, nc, python

SSRF:
  - 协议支持：http, gopher, dict, file
  - 内网探测：127.0.0.1, 10.0.0.0/8, 172.16.0.0/12
  - 攻击内部服务：Redis, MySQL, FastCGI
  - 云元数据：169.254.169.254

反序列化:
  - Java：使用ysoserial生成Payload
  - PHP：使用phpggc生成Payload
  - 寻找利用链：常见框架、库
  - 绕过防护：白名单、黑名单绕过
```

---

## 数据获取与标记

```yaml
数据获取策略:
  1. 优先获取个人信息：
     - 姓名、手机号、身份证、地址（精确到门牌号）
     - 数量要求：100-20000条100分，20000-50000条300分
     - 数据格式：CSV、Excel、数据库导出

  2. 业务生产敏感数据：
     - 财务数据、客户数据、合同数据
     - 设计图纸、源代码、技术文档
     - 由指挥部研判给分

  3. 运行管理数据：
     - 系统配置、网络拓扑、账户密码
     - 日志数据、监控数据
     - 由指挥部研判给分

数据获取注意事项:
  1. 禁止下载存储数据：仅需提供证明材料
  2. 截图证据：包含数据内容、数量、时间
  3. 数据来源：明确资产归属为防守方
  4. 数据脱敏：避免泄露真实个人信息（在报告中）
```

---

## 行为规范

### 必须遵守的规则

```yaml
禁止行为:
  1. 禁止下载、复制、拷贝数据（仅需提供证明材料）
  2. 禁止使用破坏性工具：病毒、蠕虫、木马
  3. 禁止物理入侵、光纤截断、无线电干扰
  4. 禁止删除文件、损坏引导扇区、造成服务器宕机
  5. 禁止影响业务系统正常运行

必须行为:
  1. 所有技术活动通过演习系统开展
  2. 敏感操作向指挥部报告
  3. 攻击结束后清除后门、木马
  4. 使用U盘需向指挥部申请
  5. 提交完整可复现的漏洞报告
```

### 风险规避

```yaml
操作规范:
  1. 测试前确认目标授权范围
  2. 避免对生产系统造成影响
  3. 使用低强度扫描，避免触发告警
  4. 及时清理测试文件、日志
  5. 记录所有操作，便于报告撰写

时间管理:
  1. 合理安排攻击时间，避免高峰时段
  2. 及时提交成果，避免被其他队伍抢先
  3. 预留报告撰写时间
  4. 注意演习时间限制
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
  nuclei: "C:\Users\pai\Desktop\tool\nuclei_3.8.0_windows_amd64\nuclei.exe"
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
  cobaltstrike: "C:\Users\pai\Desktop\tool\vshell_4.9.3\v_windows_amd64"

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
- 漏洞类型：SQL注入/文件上传/RCE等
- 发现时间：2026-05-xx xx:xx:xx
- 报告作者：攻击队名称

## 漏洞描述
简要描述漏洞位置、类型、影响范围。

## 漏洞复现
1. 访问目标URL：http://xxx.xxx.xxx.xxx/xxx
2. 输入测试Payload：' OR 1=1--
3. 观察响应：返回数据库错误信息
4. 利用sqlmap获取数据：sqlmap -u "http://xxx.xxx.xxx.xxx/xxx?id=1" --dbs

## 攻击路径
互联网xxx系统 → 内网xxx系统 → 专网xxx系统 → 核心生产网

## 权限获取
- 获取权限类型：WebShell/系统权限/数据库权限
- 权限级别：管理员/普通用户
- 可控范围：服务器数量、终端数量

## 数据获取（如适用）
- 数据类型：个人信息/业务数据/运行数据
- 数据量：xxx条记录
- 数据示例：（脱敏处理）

## 证据截图
1. 漏洞证明截图：包含URL、Payload、响应
2. 权限获取截图：登录界面、命令执行
3. 数据获取截图：数据内容、数量统计
4. 时间证明截图：包含系统时间

## 修复建议
1. 输入过滤：对用户输入进行严格过滤
2. 参数化查询：使用预编译语句
3. 最小权限：限制数据库用户权限
4. WAF防护：部署Web应用防火墙

## 附录
- 完整攻击脚本
- 工具使用说明
- 参考链接
```

---

## 工具依赖

```
必备：nmap masscan nuclei nikto sqlmap dirsearch gobuster subfinder amass BurpSuite Metasploit Mimikatz BloodHound frp chisel
可选：CobaltStrike Volatility ysoserial phpggc trufflehog
```

---

## 参考资源

详细技术参考，请参考 CyberSecurity-Skills-master 库中的模块：

- `01-信息搜集-Reconnaissance/` - 信息搜集完整流程
- `02-漏洞扫描-VulnerabilityScanning/` - 漏洞扫描完整流程
- `03-漏洞利用-Exploitation/` - 漏洞利用完整流程
- `04-权限提升-PrivilegeEscalation/` - 权限提升完整流程
- `05-后渗透-PostExploitation/` - 后渗透完整流程
- `06-横向移动-LateralMovement/` - 横向移动完整流程
- `07-持久化-Persistence/` - 持久化完整流程
- `08-痕迹清除-CoveringTracks/` - 痕迹清除完整流程
- `09-报告撰写-Reporting/` - 报告撰写完整流程

快速参考：
- `skill_query.py search --keyword <关键词>` - 搜索技能
- `skill_query.py list-skills --module <模块ID>` - 列出模块技能
- `skill_query.py get-skill --id <技能ID>` - 获取技能内容
