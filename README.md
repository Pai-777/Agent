# Agent Skills

AI Agent 技能集合，覆盖 CTF、HVV / 护网、渗透测试、二进制分析、逆向工程、脱壳与 Writeup / 报告撰写等方向。

每个 Skill 通常包含以下内容：

- `SKILL.md`：触发条件、主工作流、工具路由、输出要求
- `modules/`：按阶段或漏洞类型拆分的模块化流程
- `docs/`：速查表、Payload、工具说明
- `scripts/`：辅助脚本、批处理、自动化工具
- `references/`：模板、样例、补充规则、旁路工作流
- `agents/`：面向 Agent 平台的配置

## Skill 列表

### CTF 方向

| Skill | 描述 |
| --- | --- |
| `ctf-ai` | AI 类题目：提示词注入、越狱、LLM 防护绕过、隐藏信息提取、AI 输出解码。 |
| `ctf-crypto` | 密码学题目：弱加密识别、密钥提取、自定义算法还原、密文解密。 |
| `ctf-misc` | Misc 题目：图片/音频隐写、编码解码、压缩包分析、流量分析、内存取证。 |
| `ctf-pwn` | 二进制利用：栈溢出、格式化字符串、堆利用、ROP、泄露与利用链构造。 |
| `ctf-rev` | 逆向工程：crackme、序列号校验、混淆代码、算法还原、flag/key 提取。 |
| `ctf-web` | Web 安全题：SQL 注入、XSS、SSRF、SSTI、XXE、文件包含、反序列化、JWT、WAF 绕过。 |
| `ctf-wp-writer` | CTF Writeup 撰写：生成中文 WP、复现步骤和可一键运行的 Python EXP。 |

### HVV / 渗透方向

| Skill | 描述 |
| --- | --- |
| `hvv-full-auto` | HVV 总控 Skill：覆盖 PTES 全流程，支持单目标深打、多目标回流、POC / 模板调度、提权、后渗透与报告。 |
| `hvv-multi-target-triage` | 多目标分诊 Skill：面向 URL / 域名 / IP / CIDR / 资产清单，负责归一化、聚类、指纹识别、N-day 锁定和 Top N 深打编排。 |

### 二进制 / 逆向 / 脱壳方向

| Skill | 描述 |
| --- | --- |
| `binary-triage` | 二进制初步分诊：检查文件头、导入导出、字符串、内存布局、可疑行为。 |
| `deep-analysis` | 深度逆向分析：聚焦函数/算法/配置/C2 等问题，迭代重命名、修类型、加注释并输出证据结论。 |
| `unpacking` | 脱壳工具集成：壳检测与 UPX 自动解包。 |

## 当前仓库结构

```text
skills/
├── binary-triage/
├── ctf-ai/
├── ctf-crypto/
├── ctf-misc/
├── ctf-pwn/
├── ctf-rev/
├── ctf-web/
├── ctf-wp-writer/
├── deep-analysis/
├── hvv-full-auto/
│   ├── agents/
│   ├── modules/
│   └── references/
├── hvv-multi-target-triage/
│   ├── agents/
│   ├── references/
│   └── scripts/
├── unpacking/
├── .gitignore
└── README.md
```

## 使用方式

将仓库克隆或同步到 Agent 可读取的 `skills` 目录，例如：

```powershell
cd C:\Users\pai\.cc-switch
git clone https://github.com/Pai-777/Agent.git skills
```

如果本地已存在仓库：

```powershell
cd C:\Users\pai\.cc-switch\skills
git pull --rebase origin master
```

Agent 会根据用户任务描述与各 `SKILL.md` 中的触发条件自动选择合适技能。

## 本地依赖说明

部分 HVV 相关 Skill 会引用本地知识库或模板目录，这些目录默认不纳入本仓库版本控制，例如：

- `CyberSecurity-Skills-master/`
- 本地 POC 仓库
- 本地 `nuclei-templates`

这些依赖用于增强检索、分诊、POC 调度和批量锁定能力；如需共享，请单独维护对应仓库或私有资料目录。

## 更新仓库

修改或新增 Skill 后，可按以下流程同步到 GitHub：

```powershell
cd C:\Users\pai\.cc-switch\skills
git pull --rebase origin master
git status
git add .
git commit -m "Update skills"
git push origin master
```

说明：

- `git pull --rebase origin master`：先同步远端最新内容，减少冲突
- `git status`：确认变更范围
- `git add .`：加入暂存区
- `git commit -m "..."`：提交本地修改
- `git push origin master`：推送到 GitHub，README 也会同步更新

## 维护建议

- 每个 Skill 尽量保持独立，避免跨目录强依赖
- 大文件、压缩包、临时备份文件不要提交到仓库
- 新增 Skill 时至少包含 `SKILL.md`，并同步更新 README
- 脚本、EXP、规则和模板优先放入 `scripts/`、`modules/`、`references/`
