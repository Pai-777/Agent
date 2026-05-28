# Agent Skills

AI Agent 技能集合，涵盖 CTF、渗透测试、二进制分析等方向。每个 Skill 是一个独立的任务指令集，告诉 AI 在特定场景下如何使用工具、构造参数、处理异常。

## Skill 列表

### CTF 方向

| Skill | 描述 |
|-------|------|
| **ctf-ai** | AI 类题目：提示词注入、越狱、AI 安全机制绕过、提取隐藏信息 |
| **ctf-crypto** | 密码学题目：弱加密识别、密钥提取、自定义算法还原 |
| **ctf-misc** | Misc 题目：隐写分析、编码解码、流量分析、内存取证 |
| **ctf-pwn** | 二进制利用：栈溢出、格式化字符串、堆利用、ROP |
| **ctf-rev** | 逆向工程：crackme、序列号校验、混淆代码、算法还原 |
| **ctf-web** | Web 攻击：SQL 注入、XSS、SSRF、SSTI、XXE、反序列化、JWT 伪造、WAF 绕过 |
| **ctf-wp-writer** | 自动撰写中文 Writeup，产出可一键运行的 Python EXP |

### 渗透测试

| Skill | 描述 |
|-------|------|
| **hvv-web** | 以得分为导向的系统化 Web 渗透测试，覆盖信息搜集到横向移动，含规避检测和报告撰写规范 |

### 二进制分析

| Skill | 描述 |
|-------|------|
| **binary-triage** | 二进制初步分析：内存布局、字符串、导入/导出、函数概览 |
| **deep-analysis** | 聚焦式深度逆向分析：迭代重命名、修类型、加注释，输出基于证据的结论 |
| **unpacking** | 脱壳工具集成：加壳检测 + UPX 自动解包 |

## 目录结构

```
skills/
├── binary-triage/     # 二进制初步分析
├── ctf-ai/            # CTF AI 题目
├── ctf-crypto/        # CTF 密码学
├── ctf-misc/          # CTF Misc
├── ctf-pwn/           # CTF PWN
├── ctf-rev/           # CTF 逆向
├── ctf-web/           # CTF Web
├── ctf-wp-writer/     # CTF WP 撰写
├── deep-analysis/     # 深度逆向分析
├── hvv-web/           # 护网 Web 渗透
├── unpacking/         # 脱壳工具
└── README.md
```

每个 Skill 目录下包含 `SKILL.md`，定义了该 Skill 的触发条件、工作流程和工具使用规范。
