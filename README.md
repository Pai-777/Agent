# Agent Skills

AI Agent 技能集合，覆盖 CTF、渗透测试、二进制分析、逆向工程、脱壳与报告撰写等方向。

每个 Skill 都是一个独立的任务指令集，通常包含：

- `SKILL.md`：技能触发条件、工作流、工具使用规范
- `modules/`：按漏洞类型或任务类型拆分的参考模块
- `docs/`：速查表、工具说明、Payload 集合等
- `scripts/`：可复用脚本或自动化工具
- `references/`：模板、样例、补充资料
- `agents/`：Agent 平台适配配置

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

### 渗透测试 / 护网方向

| Skill | 描述 |
| --- | --- |
| `hvv-web` | 护网 Web 渗透技能：信息搜集、漏洞发现、权限获取、横向移动、报告撰写。 |
| `hvv-full-auto` | HVV 全自动化渗透测试技能：覆盖 PTES 全流程，自动调度 Web、代码审计、逆向、API、容器、IoT 等模块。 |

### 二进制 / 逆向 / 脱壳方向

| Skill | 描述 |
| --- | --- |
| `binary-triage` | 二进制初步分诊：检查文件头、导入导出、字符串、内存布局、可疑行为。 |
| `deep-analysis` | 深度逆向分析：聚焦函数/算法/配置/C2 等问题，迭代重命名、修类型、加注释并输出证据结论。 |
| `unpacking` | 脱壳工具集成：壳检测与 UPX 自动解包。 |

## 目录结构

```text
skills/
├── binary-triage/          # 二进制初步分析
├── ctf-ai/                 # CTF AI
├── ctf-crypto/             # CTF Crypto
├── ctf-misc/               # CTF Misc
├── ctf-pwn/                # CTF Pwn
├── ctf-rev/                # CTF Reverse
├── ctf-web/                # CTF Web
├── ctf-wp-writer/          # CTF Writeup Writer
├── deep-analysis/          # 深度逆向分析
├── hvv-full-auto/          # HVV 全自动化渗透
├── hvv-web/                # HVV Web 渗透
├── unpacking/              # 脱壳工具
├── .gitignore
└── README.md
```

## 使用方式

将仓库克隆或同步到 Agent 可读取的 skills 目录，例如：

```powershell
cd C:\Users\pai\.cc-switch
git clone https://github.com/Pai-777/Agent.git skills
```

如果已经存在本地仓库，进入目录后更新即可：

```powershell
cd C:\Users\pai\.cc-switch\skills
git pull --rebase origin master
```

Agent 会根据用户任务描述和各 `SKILL.md` 中的触发条件自动选择合适技能。

## 更新仓库

修改或新增 Skill 后，按以下流程提交到 GitHub：

```powershell
cd C:\Users\pai\.cc-switch\skills
git pull --rebase origin master
git status
git add .
git commit -m "Update skills"
git push origin master
```

说明：

- `git pull --rebase origin master`：先同步 GitHub 上的最新内容，减少冲突。
- `git status`：确认哪些文件发生了变化。
- `git add .`：把本地改动加入暂存区。
- `git commit -m "..."`：提交本地修改，双引号里面填写本次更改说明。
- `git push origin master`：推送到 GitHub，GitHub 首页 README 会同步更新。

## 维护建议

- 每个 Skill 尽量保持独立，避免跨目录强依赖。
- 大文件、压缩包、临时备份文件不要提交到仓库。
- 新增 Skill 时至少包含 `SKILL.md`，并在本 README 中补充说明。
- 涉及脚本或 EXP 的内容建议放入 `scripts/` 或 `references/`，避免塞进主说明文档。
