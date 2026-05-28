---
name: binary-triage
description: 通过检查内存布局、字符串、导入/导出以及函数，对二进制文件进行初步分析，以快速理解其功能并识别可疑行为。适用于首次检查二进制文件、用户请求对程序进行分诊/概览/分析，或在进行更深入的逆向工程之前需要一个整体认知时使用。
---

# Binary Triage

## 指南
我们正在对一个二进制文件进行分诊，以快速理解它的行为。这是一次**初步调查**，而不是深入分析。我们的目标是：
1. 识别关键组件和行为
2. 标记可疑或值得关注的区域
3. 创建一个用于后续深入调查的任务清单

## 使用 ida-pro-mcp 进行二进制分诊

按照以下系统化流程，使用 ida-pro-mcp 的 MCP 工具进行分析：

### 1. 识别程序
- 使用 `get-current-program` 查看当前活动程序
- 或使用 `list-project-files` 查看项目中可用的程序
- 记录 `programPath`（例如 `"/Hatchery.exe"`），供后续工具使用

### 2. 调查内存布局
- 使用 `get-memory-blocks` 了解二进制结构
- 检查关键区段：
  - `.text` - 可执行代码
  - `.data` - 已初始化数据
  - `.rodata` - 只读数据（字符串、常量）
  - `.bss` - 未初始化数据
- 标记异常特征：
  - 区段异常偏大
  - 被加壳 / 加密的区段
  - 可执行的数据区段
  - 可写的代码区段

### 3. 调查字符串
- 使用 `get-strings-count` 查看字符串总数
- 使用 `get-strings` 并启用分页（每次 100–200 条）
- 查找可反映功能或恶意行为的线索：
  - **网络**：URL、IP 地址、域名、API 端点
  - **文件系统**：文件路径、注册表键、配置文件
  - **API**：函数名、库引用
  - **消息**：错误信息、调试字符串、日志信息
  - **可疑关键词**：admin、password、credential、token、crypto、encrypt、decrypt、download、execute、inject、shellcode、payload

### 4. 调查符号与导入
- 使用 `get-symbols-count` 并设置 `includeExternal=true` 统计导入数量
- 使用 `get-symbols`，设置 `includeExternal=true` 和 `filterDefaultNames=true`
- 重点关注外部符号（来自库的导入）
- 按类别标记有趣或可疑的导入：
  - **网络 API**：connect、send、recv、WSAStartup、getaddrinfo、curl_*、socket
  - **文件 I/O**：CreateFile、WriteFile、ReadFile、fopen、fwrite、fread
  - **进程操作**：CreateProcess、exec、fork、system、WinExec、ShellExecute
  - **内存操作**：VirtualAlloc、VirtualProtect、mmap、mprotect
  - **加密**：CryptEncrypt、CryptDecrypt、EVP_*、AES_*、bcrypt、RC4
  - **反分析**：IsDebuggerPresent、CheckRemoteDebuggerPresent、ptrace
  - **注册表**：RegOpenKey、RegSetValue、RegQueryValue
- 注意导入数量与符号总数的比例（大量依赖导入可能意味着强依赖库）

### 5. 调查函数
- 使用 `get-function-count` 并设置 `filterDefaultNames=true` 统计已命名函数
- 使用 `get-function-count` 并设置 `filterDefaultNames=false` 统计所有函数
- 计算已命名函数与未命名函数的比例（未命名比例高通常意味着二进制被 strip）
- 使用 `get-functions` 并设置 `filterDefaultNames=true` 列出已命名函数
- 识别关键函数：
  - **入口点**：`entry`、`start`、`_start`
  - **主函数**：`main`、`WinMain`、`DllMain`、`_main`
  - **可疑命名**：如果未被 strip，关注具有明确语义的函数名

### 6. 针对关键发现的交叉引用分析
- 针对步骤 3 中发现的有趣字符串：
  - 使用 `find-cross-references`，设置 `direction="to"` 和 `includeContext=true`
  - 确定哪些函数引用了这些可疑字符串
- 针对步骤 4 中发现的可疑导入：
  - 使用 `find-cross-references`，设置 `direction="to"` 和 `includeContext=true`
  - 确定哪些函数调用了这些可疑 API
- 该步骤有助于优先确定需要深入检查的函数

### 7. 有选择的初步反编译
- 对入口点或主函数使用 `get-decompilation`
  - 设置 `limit=30`，初步获取约 30 行代码
  - 设置 `includeIncomingReferences=true` 查看调用者
  - 设置 `includeReferenceContext=true` 获取上下文片段
- 对步骤 6 中识别出的 1–2 个可疑函数使用 `get-decompilation`
  - 设置 `limit=20–30` 进行快速概览
- 关注高层模式：
  - 循环（加解密逻辑）
  - 网络操作
  - 文件操作
  - 进程创建
  - 可疑控制流（混淆迹象）
- **此阶段不要进行深入分析** —— 目标只是理解整体行为

### 8. 记录发现并创建任务清单
- 使用 `TodoWrite` 工具创建可执行的任务清单，例如：
  - “调查字符串 `http://malicious-c2.com`（在 0x00401234 被引用）”
  - “反编译函数 sub_401000（调用了 VirtualAlloc + memcpy + CreateThread）”
  - “分析函数 encrypt_payload 中的加密逻辑（使用 CryptEncrypt）”
  - “追踪反调试检测（IsDebuggerPresent 位于 0x00402000）”
  - “检查被加壳区段 .UPX0 中的解包逻辑”
- 每个待办事项应具备：
  - 明确性（包含地址、函数名、字符串）
  - 可执行性（需要做什么）
  - 优先级（最可疑的优先）

## 输出格式

请按照以下结构化格式向用户呈现分诊结果：

### Program Overview
- **Name**：[来自 programPath 的程序名]
- **Type**：[可执行文件类型 - PE、ELF、Mach-O 等]
- **Platform**：[Windows、Linux、macOS 等]

### Memory Layout
- **Total Size**：[大小（字节/KB/MB）]
- **Key Sections**：[主要区段及其大小与权限]
- **Unusual Characteristics**：[任何加壳/加密/可疑区段]

### String Analysis
- **Total Strings**：[来自 get-strings-count 的数量]
- **Notable Findings**：[带上下文的关键字符串列表]
- **Suspicious Indicators**：[发现的 URL、IP、可疑关键词]

### Import Analysis
- **Total Symbols**：[来自 get-symbols-count 的数量]
- **External Imports**：[外部符号数量]
- **Key Libraries**：[主要导入的库]
- **Suspicious APIs**：[按类别列出的可疑导入]

### Function Analysis
- **Total Functions**：[filterDefaultNames=false 的统计结果]
- **Named Functions**：[filterDefaultNames=true 的统计结果]
- **Stripped Status**：[根据比例判断 是否被 strip]
- **Entry Point**：[地址与名称]
- **Main Function**：[地址与名称]
- **Key Functions**：[识别出的关键函数列表]

### Suspicious Indicators
[按严重程度排序的风险信号列表]

### Recommended Next Steps
[第 8 步中创建的任务清单]
- 每项应具体且可执行
- 按严重性 / 重要性排序
- 包含地址、函数名和上下文

## 重要说明

- **速度优先于深度**：这是分诊，而不是完整分析
- **使用分页**：不要一次请求成千上万条字符串/函数，使用 100–200 的分块
- **关注异常点**：标记不寻常、可疑或值得关注的内容
- **上下文很关键**：在使用交叉引用时启用 `includeContext=true`
- **创建可执行的待办事项**：每一步都应具体到可以交给另一个 Agent 执行
- **保持系统性**：严格按 8 个步骤执行，以获得全面覆盖