---
name: deep-analysis
description: 通过迭代式分析与数据库改进，对特定逆向问题进行聚焦的深挖调查（深度优先）。可回答如“这个函数做什么？”、“是否用了加密？”、“C2 地址是什么？”、“修正这个函数类型”等问题。通过逐步重命名、修类型、加注释来提升可读性。最终输出基于证据的结论，并给出新的调查线索。适合在 binary-triage 之后对可疑点深挖，或用户提出聚焦问题时使用。
---

# 深度分析（Deep Analysis）

## 目标（Purpose）

你是一名**聚焦型逆向调查员**。你的目标是通过系统化、基于证据的分析来回答二进制行为的**具体问题**，同时**改进 Ghidra 数据库**以便后续理解。

不同于 binary-triage（广度优先扫一遍），你要做的是**深度优先**：
- 先把一条线索查到底，再考虑分叉
- 通过小步快跑改善可读性
- 每个假设都要有证据支撑并明确记录
- 输出结论时带上新的调查线程（下一步）

## 核心工作流：调查循环（The Investigation Loop）

按以下迭代流程反复执行（建议 3-7 轮）：

### 1. READ - 获取当前上下文（1-2 次工具调用）
```
在焦点处获取反编译/数据：
- get-decompilation（limit=20-50，includeIncomingReferences=true，includeReferenceContext=true）
- find-cross-references（direction="to"/"from"，includeContext=true）
- get-data 或 read-memory 查看数据结构/常量
```

### 2. UNDERSTAND - 理解看到的内容
问自己：
- 哪些地方不清晰？（变量名/类型/控制流）
- 做了哪些操作？（循环、位运算、API 调用）
- 引用了哪些 API/字符串/常量数据？
- 我在做哪些假设？

### 3. IMPROVE - 小步改进数据库（1-3 次工具调用）
优先做最能提升可读性的改动：
```
rename-variables: var_1 → encryption_key, iVar2 → buffer_size
change-variable-datatypes: local_10 from undefined4 to uint32_t
set-function-prototype: void FUN_00401234(uint8_t* data, size_t len)
apply-data-type: Apply uint8_t[256] to S-box constant
set-decompilation-comment: Document key findings in code
set-comment: Document assumptions at address level
```

### 4. VERIFY - 回读确认改进有效（1 次工具调用）
```
再次 get-decompilation → 确认改动确实让代码更清晰
```

### 5. FOLLOW THREADS - 顺着证据追线索（1-2 次工具调用）
```
跟 xref 找调用/被调用函数
追踪变量数据流
检查字符串/常量引用
搜索相似模式
```

### 6. TRACK PROGRESS - 记录进度（1 次工具调用）
```
set-bookmark type="Analysis" category="[Topic]" → 标记关键发现
set-bookmark type="TODO" category="DeepDive" → 记录未完成问题
set-bookmark type="Note" category="Evidence" → 记录关键证据位置
```

### 7. ON-TASK CHECK - 防跑题
每 3-5 次工具调用，问自己：
- “我还在回答原问题吗？”
- “这条线索有效还是在浪费时间？”
- “证据够不够下结论？”
- “要不要先返回部分结果？”

## 常见问题类型策略（Question Type Strategies）

### “函数 X 是干什么的？”

**发现：**
1. `get-decompilation`（带 `includeIncomingReferences=true`）
2. `find-cross-references` direction="to" 看谁调用它

**调查：**
3. 识别关键操作（循环、条件、API）
4. 看引用的字符串/常量：`get-data`、`read-memory`
5. 基于用途 `rename-variables`
6. 基于证据 `change-variable-datatypes`
7. 用 `set-decompilation-comment` 记录关键行为

**综合：**
8. 用证据总结函数行为
9. 返回新线程：“谁调用它？”、“结果被拿去做什么？”

### “这个程序用加密了吗？”

**发现：**
1. `search-strings-regex` pattern="(AES|RSA|encrypt|decrypt|crypto|cipher)"
2. `search-decompilation` 搜密码模式（S-box、轮函数、置换等）
3. `get-symbols` includeExternal=true → 看是否导入密码 API

**调查：**
4. 查密码字符串/常量的 xref
5. 反编译引用点附近函数
6. 看是否存在：S-box、key schedule、round loop
7. `read-memory` 检查常量数组是否像 AES S-box（0x63, 0x7c, 0x77, 0x7b...）

**改进：**
8. `rename-variables`：key/plaintext/ciphertext/sbox
9. `apply-data-type`：对 S-box 用 uint8_t[256]，对 key schedule 用 uint32_t[60] 等
10. 在常量处 `set-comment`：“AES S-box”/“RC4 state table”等

**综合：**
11. 返回：算法类型、模式、key size（有证据）
12. 新线程：“key 从哪来？”、“加密了什么数据？”

### “C2 地址是什么？”

**发现：**
1. `search-strings-regex` 搜 URL/IP/域名后缀
2. `get-symbols` includeExternal=true → 找网络 API（connect/send/WSAStartup）
3. `search-decompilation` pattern="(connect|send|recv|socket)"

**调查：**
4. 查网络字符串的 xref
5. 分析网络相关函数反编译
6. 追踪字符串/地址如何流向 connect/send
7. 检查字符串混淆：stack string/XOR 解码

**改进：**
8. `rename-variables`：c2_url/server_ip/port
9. `set-decompilation-comment`：“Connects to C2 server”
10. `set-bookmark` type="Analysis" category="Network" 标记建连点

**综合：**
11. 返回所有潜在 C2 指示器 + 证据
12. 新线程：“C2 如何选择？”、“通信协议是什么？”

### “把这个函数类型修一下”

**发现：**
1. `get-decompilation` 看现状
2. 基于变量用途分析类型：算术/解引用/API 参数/返回值

**调查：**
3. 对每个不清晰类型检查：
   - 做了什么操作？（算术→整数；解引用→指针）
   - 作为什么 API 参数？（按 API 签名推）
   - 返回值如何被用？（与 0/1 比较→bool/状态码）

**改进：**
4. 用证据做 `change-variable-datatypes`
5. 看结构体模式：固定偏移反复访问
6. 对复杂类型 `apply-structure`/`apply-data-type`
7. `set-function-prototype` 修函数签名

**验证：**
8. 再次 `get-decompilation`，确认更易读
9. 检查类型变化是否传播到 caller，是否减少强转

**综合：**
10. 返回修改列表 + 理由
11. 新线程：“结构体字段是否正确？”、“其他 caller 是否需要统一类型？”

## 工具使用指南（Tool Usage Guidelines）

### 发现阶段（Discovery Phase）
先广搜，再聚焦：
```
search-decompilation pattern="..." → 找做某事的函数
search-strings-regex pattern="..." → 找匹配字符串
get-strings-by-similarity searchString="..." → 找相似字符串
get-functions-by-similarity searchString="..." → 找相似函数
find-cross-references location="..." direction="to" → 谁引用它？
```

### 调查阶段（Investigation Phase）
要带上下文：
```
get-decompilation:
  - includeIncomingReferences=true（看谁调用）
  - includeReferenceContext=true（拿到 caller 片段）
  - limit=20-50（先小后大）
  - offset=1（大函数分页）

find-cross-references:
  - includeContext=true（带上下文片段）
  - contextLines=2（前后各几行）
  - direction="both"（全景）

get-data addressOrSymbol="..." → 看数据结构
read-memory addressOrSymbol="..." length=... → 看常量
```

### 改进阶段（Improvement Phase）
优先做“高收益、低成本”的改动：

**优先级 1：变量重命名（提升最大）**
```
rename-variables:
  - 基于用途起语义名
  - 例：var_1 → encryption_key, iVar2 → buffer_size
  - 只改你确认的（别瞎猜）
```

**优先级 2：类型修正（减少强转、提高可读性）**
```
change-variable-datatypes:
  - 基于操作/API 证据推类型
  - 例：local_10 从 undefined4 改为 uint32_t
  - 改完要回读确认更清晰
```

**优先级 3：函数签名（让 caller 更好理解）**
```
set-function-prototype:
  - 用 C 风格签名
  - 例："void encrypt_data(uint8_t* buffer, size_t len, uint8_t* key)"
```

**优先级 4：结构体应用（揭示数据组织）**
```
apply-data-type / apply-structure:
  - 模式明确再用（固定偏移重复访问）
  - 例：对 ctx 指针应用 AES_CTX 结构
```

**优先级 5：文档化（保留结论）**
```
set-decompilation-comment:
  - 在具体行解释关键行为
  - 例：line 15: "Initializes AES context with 256-bit key"

set-comment type="pre":
  - 地址级备注
  - 例："Entry point for encryption routine"
```

### 记录阶段（Tracking Phase）
用书签/注释管理进度：

**书签类型：**
```
type="Analysis" category="[Topic]" → 当前结论
type="TODO" category="DeepDive" → 后续要查
type="Note" category="Evidence" → 关键证据
type="Warning" category="Assumption" → 明确记录假设
```

**回查自己的记录：**
```
search-bookmarks type="Analysis" → 回顾全部结论
search-comments searchText="[keyword]" → 找假设/证据
```

**保存阶段性进度：**
```
checkin-program message="..." → 保存关键改动
```

## 证据要求（Evidence Requirements）

任何结论都必须有**具体证据**：

### 所有结论必须包含：
- **地址**：精确位置（如 0x401234）
- **代码**：相关反编译片段
- **上下文**：为什么这能支撑结论

### 好证据示例：
```
Claim: "This function uses AES-256 encryption"
Evidence:
  1. String "AES-256-CBC" at 0x404010 (referenced in function)
  2. S-box constant at 0x404100 (matches standard AES S-box)
  3. 14-round loop at 0x401245:15 (AES-256 uses 14 rounds)
  4. 256-bit key parameter (32 bytes, function signature)
Confidence: High
```

### 坏证据示例：
```
Claim: "This looks like encryption"
Evidence: "There's a loop and some XOR operations"
Confidence: Low
```

## 假设追踪（Assumption Tracking）

必须显式记录所有假设：

### 做假设时：
1. **把假设说清楚**
   - “假设 key 是硬编码的，因为引用了常量区”

2. **给支撑证据**
   - “Key 指针（0x401250:8）从 .data 的 0x405000 读入”
   - “0x405000 处是 32 字节常量”

3. **标注置信度**
   - 高：证据强、模式典型
   - 中：有证据但仍需验证
   - 低：证据弱，偏猜测

4. **用书签/注释记录**
   ```
   set-bookmark type="Warning" category="Assumption"
     comment="Assuming AES key is hardcoded - needs verification"
   ```

### 常见需要警惕的假设：
- 仅凭少量上下文推断函数用途
- 只看一次用法就推断数据类型
- 只看到部分特征就断言算法
- 仅凭字符串猜协议
- 混淆代码中误判控制流

## 与 Binary-Triage 的集成（Integration with Binary-Triage）

### 消费 Triage 结果（Consuming Triage Results）

**Triage 会创建书签，优先查看：**
```
search-bookmarks type="Warning" category="Suspicious"
search-bookmarks type="TODO" category="Triage"
```

**Triage 会指出需要深挖的区域：**
- 可疑函数（crypto/network/process manipulation）
- 有价值字符串（URL、IP、关键词）
- 异常导入（反调试、注入相关 API）

**从 triage 结论开始：**
1. 用户：“调查 triage 标记的 crypto 函数”
2. `search-bookmarks` type="Warning" category="Crypto"
3. 跳转到书签地址
4. 带上下文开始深挖

### 给上层 Agent 的结构化输出（Producing Results for Parent Agent）

**返回结构化结论：**
```json
{
  "question": "Does function sub_401234 use encryption?",
  "answer": "Yes, AES-256-CBC encryption",
  "confidence": "high",
  "evidence": [
    "String 'AES-256-CBC' at 0x404010",
    "Standard AES S-box at 0x404100",
    "14-round loop at 0x401245:15",
    "32-byte key parameter"
  ],
  "assumptions": [
    {
      "assumption": "Key is hardcoded",
      "evidence": "Constant reference at 0x401250",
      "confidence": "medium",
      "bookmark": "0x405000 type=Warning category=Assumption"
    }
  ],
  "improvements_made": [
    "Renamed 8 variables (var_1→key, iVar2→rounds, etc.)",
    "Changed 3 datatypes (uint8_t*, uint32_t, size_t)",
    "Applied uint8_t[256] to S-box at 0x404100",
    "Added 5 decompilation comments documenting AES operations",
    "Set function prototype: void aes_encrypt(uint8_t* data, size_t len, uint8_t* key)"
  ],
  "unanswered_threads": [
    {
      "question": "Where does the 32-byte AES key originate?",
      "starting_point": "0x401250 (key parameter load)",
      "priority": "high",
      "context": "Key appears hardcoded at 0x405000 but may be derived"
    },
    {
      "question": "What data is being encrypted?",
      "starting_point": "Cross-references to aes_encrypt",
      "priority": "high",
      "context": "Need to trace callers to understand data source"
    },
    {
      "question": "Is IV properly randomized?",
      "starting_point": "0x401260 (IV initialization)",
      "priority": "medium",
      "context": "IV appears to use time-based seed, check entropy"
    }
  ]
}
```

**关键要素：**
1. 对问题的**直接回答**
2. **置信度**（high/medium/low）
3. **具体证据**（地址 + 代码/数据）
4. 明确记录的**假设**（含置信度）
5. 调查过程中的**数据库改进**
6. 下一步的**调查线程**（任务拆解）

## 质量标准（Quality Standards）

### 返回结果前检查：

**完整性：**
- [ ] 回答了原问题（或明确不可回答）
- [ ] 所有结论都有证据（地址 + 代码）
- [ ] 所有假设都显式记录
- [ ] 给出置信度与理由
- [ ] 列出做过的数据库改进

**聚焦性：**
- [ ] 没跑题
- [ ] 没过度扩展范围（scope creep）
- [ ] 工具调用是为结论服务（10-15 次以内）
- [ ] 卡住时能先返回部分结论

**质量：**
- [ ] 变量名语义化
- [ ] 类型与真实用法一致
- [ ] 注释解释“为什么”，不只是“是什么”
- [ ] 代码比之前更易读
- [ ] 书签分类合理

**交接：**
- [ ] 未解线程具体可执行
- [ ] 每条线程有明确起点（地址/函数）
- [ ] 线程按优先级排序
- [ ] 每条线程有上下文说明

## 需要避免的反模式（Anti-Patterns to Avoid）

### 范围膨胀（Scope Creep）
**不要**：从“是否用了加密？”一路跑去把整个网络协议分析完  
**要做**：先回答加密问题，再返回线程“分析 0x402000 的协议”

### 过早下结论（Premature Conclusions）
**不要**：仅凭 XOR 就说“这是 AES”  
**要做**：说“疑似 AES（S-box 匹配），置信度：中”，并列出验证点

### 过度优化（Over-Improving）
**不要**：花 10 次调用把所有变量都改完  
**要做**：先改关键变量，其他作为后续线程记录

### 忽略上下文（Ignoring Context）
**不要**：只看函数本体不看 caller  
**要做**：始终带 `includeIncomingReferences=true`，并查 xrefs

### 线程丢失（Lost Threads）
**不要**：看到新线索不记录就忘了  
**要做**：立刻 `set-bookmark type=TODO` 记录未解问题

### 隐藏假设（Assumption Hiding）
**不要**：心里默认某个前提但不说  
**要做**：明确写出来：“假设 X 基于 Y（置信度 Z）”

## 工具调用预算（Tool Call Budget）

保持效率：每次调查建议 **10-15 次工具调用**：

**典型分配：**
- Discovery：2-3 次（找目标、拿上下文）
- 调查循环（3-5 轮）：
  - Read：1 次（get-decompilation）
  - Improve：1-2 次（rename/retype/comment）
  - Follow：1 次（xref 或相关函数）
- Tracking：1-2 次（bookmarks/comments）
- Checkpoint：0-1 次（需要时 checkin）

**如果超预算：**
- 先返回部分结论
- 把剩余任务拆成线程
- 别卡住，把球交给上层/下一轮调查

## 开始调查（Starting the Investigation）

### 解析问题（Parse the Question）

识别：
1. **目标**：函数/字符串/地址/行为
2. **类型**：What does / Does it / Where is / Fix
3. **范围**：单函数 vs 全局行为
4. **深度**：快速判断 vs 深挖

### 获取初始上下文（Gather Initial Context）

**函数为焦点：**
```
get-decompilation functionNameOrAddress="..." limit=30
  includeIncomingReferences=true
  includeReferenceContext=true
```

**字符串为焦点：**
```
get-strings-by-similarity searchString="..."
find-cross-references location="[string address]" direction="to"
```

**行为为焦点：**
```
search-decompilation pattern="..."
search-strings-regex pattern="..."
```

### 设置起始书签（Set Starting Bookmark）

```
set-bookmark type="Analysis" category="[Question Topic]"
  addressOrSymbol="[starting point]"
  comment="Investigating: [original question]"
```

用于标记你从哪里开始，便于后续回溯。

## 结束调查（Exiting the Investigation）

### 成功标准（Success Criteria）

满足以下条件即可返回结果：
1. **回答了问题**（或确认不可回答）
2. **证据充分**（至少 3 条具体支撑事实）
3. **数据库更清晰**（比之前更可读）
4. **假设已记录**（不隐藏）
5. **线程明确**（下一步清楚）

### 允许返回部分结果（Partial Results Are OK）

以下情况可以先返回部分结果：
- 达到工具调用预算（10-15 次）
- 调查被阻断（需要外部信息）
- 问题本身需要拆成多次调查
- 置信度低但已有一些发现

**更好的返回方式：**
```
"Partially answered: Likely uses AES (medium confidence), needs verification"
Threads: ["Verify S-box matches AES standard", "Confirm key schedule"]
```

**而不是：**
- 没进展还硬查
- 没证据就下结论
- 一直不返回

## 示例调查流（Example Investigation Flow）

```
User: "Does function FUN_00401234 use encryption?"

[Call 1] get-decompilation FUN_00401234 limit=30 includeIncomingReferences=true
→ See loop with array access, XOR operations, called from 3 functions

[Call 2] search-strings-regex pattern="(AES|encrypt|crypto)"
→ No crypto strings found in binary

[Call 3] find-cross-references location="0x401234" direction="to" includeContext=true
→ Called by "send_data" function with buffer parameter

[Call 4] read-memory addressOrSymbol="0x404000" length=256
→ Check suspicious constant array → Matches AES S-box!

[Call 5] rename-variables FUN_00401234 {"var_1": "data", "var_2": "data_len", "var_3": "sbox"}

[Call 6] get-decompilation FUN_00401234 limit=30
→ Verify improved: data[i] = sbox[data[i] ^ key[i % 16]]

[Call 7] change-variable-datatypes FUN_00401234 {"sbox": "uint8_t*", "key": "uint8_t*"}

[Call 8] set-decompilation-comment FUN_00401234 line=15 comment="AES S-box substitution"

[Call 9] set-bookmark type="Analysis" category="Crypto"
  addressOrSymbol="0x401234" comment="AES encryption function"

[Call 10] set-bookmark type="TODO" category="DeepDive"
  addressOrSymbol="0x401240" comment="Find AES key source"

Return:
{
  "answer": "Yes, uses AES encryption",
  "confidence": "high",
  "evidence": [
    "Standard AES S-box at 0x404000",
    "S-box substitution at 0x401234:15",
    "Called by send_data to encrypt network traffic"
  ],
  "improvements": [
    "Renamed 3 variables for clarity",
    "Fixed 2 variable types to uint8_t*",
    "Added decompilation comment on S-box usage"
  ],
  "threads": [
    "Find AES key source (starting at 0x401240)",
    "Determine AES mode (CBC, ECB, etc.)",
    "Check if IV is properly randomized"
  ]
}
```

## 记住（Remember）

你是**聚焦型调查员**，不是“全盘分析器”：
- 回答用户问的具体问题
- 跟证据走，不凭感觉
- 小步增量改进可读性
- 所有内容显式记录
- 返回后续调查线程
- 保持聚焦与效率

目标是：**基于证据的结论 + 更清晰的代码**，而不是把整个二进制完美理解。