---
name: ctf-rev
description: 使用系统化分析解 CTF 逆向题，提取 flag/key/password。适用于 crackme、binary bomb、序列号校验、混淆代码、算法还原等所有需要理解程序行为的场景。
---

# CTF 逆向工程

## 目标（Purpose）

你是一名 CTF 逆向题解题者。你的目标是**理解程序在做什么**，并通过系统化分析**提取 flag/key/password**。

CTF 逆向本质是**在约束条件下做理解**：
- 时间有限（比赛压力）
- 题目结构未知（考点是什么？）
- 文档极少（这就是题目的一部分）
- 以目标为导向（拿到 flag，而不是“全懂”）

与恶意代码分析或漏洞研究不同，CTF 逆向更考验你：
1. **快速定位核心考点**（密码？混淆？算法还原？）
2. **追踪关键数据流**（输入去哪了？怎么被校验？）
3. **识别常见模式**（标准算法、常见套路）
4. **灵活切换策略**（静态/动态，正向/逆向）

## 概念框架（Conceptual Framework）

### 三个问题（The Three Questions）

每道逆向题最终都要回答：

**1. 程序想要什么输入（EXPECT）？**
- 输入格式（字符串/数字/二进制？）
- 输入结构（长度/格式/编码？）
- 校验标准（比较/约束/校验和？）

**2. 程序对输入做了什么（DO）？**
- 变换（加密/哈希/编码/计算？）
- 比较（与硬编码值比？还是与派生值比？）
- 算法（标准算法/自定义逻辑/数学过程？）

**3. 我怎么把它逆回来（REVERSE）？**
- 操作是否可逆？（加密 vs 哈希）
- 能否爆破？（keyspace、性能）
- 能否推导？（解方程、倒推数据流）
- 能否绕过？（patch、调试、改状态）

### 理解 vs 解题（Understanding vs Solving）

**不需要把所有东西都看懂**，只要够你拿到 flag：

**完全理解（通常没必要）：**
- 每个函数的意义
- 全部程序流程
- 所有边界与错误处理
- 库实现细节

**足够理解（你真正需要的）：**
- flag 校验入口
- 核心变换逻辑
- 输入到输出的关系
- 比较点/成功条件

**示例：**
```
Program has 50 functions. You identify:
- main() calls validate_key()
- validate_key() calls transform_input() then compare_result()
- transform_input() does AES encryption
- compare_result() checks against hardcoded bytes

Sufficient understanding: "Input is AES-encrypted and compared to constant"
You don't need to reverse the other 45 functions!
```

## 核心方法论（Core Methodologies）

### 静态分析：代码理解（Static Analysis）

**目标：** 通过阅读反编译/汇编理解程序逻辑

**适用：**
- 小程序（crackme、keygen）
- 算法识别类题
- 动态分析受阻（反调试/复杂状态）
- 需要还原变换逻辑

**做法：**
1. **找关键路径**：入口 → 校验 → 成功
2. **追输入流**：输入进哪，怎么用
3. **识别操作**：发生了哪些变换（XOR/循环/比较）
4. **模式匹配**：与已知模式对照（见 patterns.md）

**ReVa 工作流：**
```
1. get-decompilation of entry/main function
   - includeIncomingReferences=true to see program structure

2. Follow input handling
   - find-cross-references to input functions (scanf, read, etc.)
   - Trace data flow from input to validation

3. Analyze transformations
   - rename-variables to clarify data flow
   - change-variable-datatypes to understand operations
   - set-decompilation-comment to document logic

4. Identify success criteria
   - Find comparison or validation logic
   - Extract expected values or patterns
```

### 动态分析：运行时观察（Dynamic Analysis）

**目标：** 通过运行观察程序行为与中间值

**适用：**
- 控制流复杂（静态难跟）
- 混淆/壳/自解密
- 需要看中间变量
- 时间/环境相关校验

**做法：**
1. **在关键点下断**
   - 输入处理
   - 变换函数
   - 比较点
   - 成功/失败分支

2. **观察状态变化**
   - 寄存器/变量
   - 内存内容
   - 函数参数/返回值

3. **验证假设**
   - “输入 X 会发生 Y 吗？”
   - “这里到底在比较什么？”

**注意：** ReVa 更偏静态；动态建议用 gdb/x64dbg 等外部调试器。

### 混合打法：静态 + 动态（Hybrid）

**通常是 CTF 最有效的组合**

**流程：**
1. **静态找结构**（校验函数/成功路径）
2. **动态看关键值**（在比较点观察期望值）
3. **静态理解变换**（逆算法）
4. **动态验证结果**（测试你推出来的输入）

**示例：**
```
Static: "Input is transformed by function sub_401234 then compared"
Dynamic: Run with test input, breakpoint at comparison → see expected value
Static: Decompile sub_401234 → recognize as base64 encoding
Solve: base64_decode(expected_value) = flag
Dynamic: Verify flag works
```

## 解题策略（Problem-Solving Strategies）

### 策略 1：自顶向下（Top-Down）

**从成功条件开始，倒推回输入**

**适用：**
- 成功/失败提示明显（"Correct!" / "Wrong!"）
- 程序结构较清晰
- 想用最小成本拿到解

**流程：**
```
1. Find success message/function
2. find-cross-references direction="to" → What calls this?
3. get-decompilation of validation function
4. Identify what conditions lead to success
5. Work backwards to understand required input
```

### 策略 2：自底向上（Bottom-Up）

**从输入开始，正向追到校验**

**适用：**
- 程序结构复杂（函数多）
- 成功条件不明显
- 需要理解完整变换链

**流程：**
```
1. search-strings-regex pattern="(scanf|read|fgets|input)"
2. find-cross-references to input function
3. Trace data flow: input → storage → transformation → usage
4. Follow transformations until you reach comparison/validation
```

### 策略 3：模式识别（Pattern Recognition）

**识别标准算法或常见套路**

**适用：**
- 密码类（加密/哈希）
- 编码类（base64/自定义编码）
- 算法实现类

**流程：**
```
1. Look for algorithmic patterns (see patterns.md):
   - Loop structures (rounds, iterations)
   - Constant arrays (S-boxes, tables)
   - Characteristic operations (XOR, rotations, substitutions)

2. Compare to known implementations:
   - read-memory at constant arrays → compare to standard tables
   - Count loop iterations → indicates algorithm variant
   - search-decompilation for crypto patterns

3. Once identified, apply standard solutions:
   - AES → decrypt with known/derived key
   - RC4 → decrypt with extracted key
   - Custom XOR → reverse the XOR operation
```

### 策略 4：约束求解（Constraint Solving）

**把校验逻辑抽象成数学约束来解**

**适用：**
- 序列号/输入校验（方程组）
- 数学谜题
- 多个相关检查

**流程：**
```
1. Identify all constraints on input:
   input[0] + input[1] == 0x42
   input[0] ^ input[2] == 0x13
   input[1] * 2 == input[3]

2. Extract to external solver (z3, constraint solver)

3. Solve for input values

4. Verify solution in program
```

## 灵活工作流（Flexible Workflow）

CTF 题变化很大，按情况调整：

### 初始评估（5-10 分钟）

**先弄清题面：**
- 给了什么？（binary/source/描述？）
- 目标是什么？（找 flag/生成 key/绕过校验？）
- 限制是什么？（时限/黑盒/平台？）

**ReVa 侦察：**
```
1. get-current-program or list-project-files
2. get-strings-count and sample strings (100-200)
   - Look for: flag format, hints, library names
3. get-symbols with includeExternal=true
   - Check for suspicious imports (crypto APIs, anti-debug)
4. get-function-count to gauge complexity
```

### 聚焦调查（15-45 分钟）

**跟最有希望的线索走：**

**若 strings 里直接有 flag 格式：**
→ 自顶向下从字符串入手

**若看到 crypto 相关：**
→ 先做模式识别确定算法

**若看到输入校验：**
→ 追数据流找到 compare 点

**若程序很小（< 10 个函数）：**
→ 全量静态分析

**若程序复杂/混淆：**
→ 混合打法（动态找关键点，静态理解逻辑）

### 提取解（10-20 分钟）

**理解机制后，问：**

1. **能逆吗？**
   - 解密/解码/求逆

2. **能推吗？**
   - 解约束/从比较点提取期望值

3. **能爆破吗？**
   - keyspace 小，校验快

4. **能绕过吗？**
   - patch 比较/改状态

**验证：**
- 能运行就跑一下
- 看 flag 格式（一般 flag{...}/CTF{...}/某战队格式）

## 模式识别（Pattern Recognition）

CTF 逆向经常考“识别标准模式”。详见 `patterns.md`：

**密码学模式：**
- 分组密码（AES/DES/魔改）
- 流密码（RC4/魔改）
- 哈希（MD5/SHA/自定义）
- XOR 混淆

**算法模式：**
- 编码（base64/自定义 alphabet）
- 数学运算（模运算/矩阵）
- 状态机（按状态校验输入）

**代码模式：**
- 输入校验循环
- 逐字符比较
- 变换 + 比较结构
- 反调试（CTF 常见）

**数据结构模式：**
- 查表（代换）
- 硬编码数组（expected）
- buffer 变换

## ReVa 工具用法（面向 CTF）

### 发现类工具（Discovery Tools）

**快速定位“有用的地方”：**

```
search-strings-regex pattern="(flag|key|password|correct|wrong|success)"
→ Find win/lose conditions

search-decompilation pattern="(scanf|read|input|strcmp|memcmp)"
→ Find input/comparison functions

get-functions-by-similarity searchString="check"
→ Find validation functions
```

### 分析类工具（Analysis Tools）

**理解核心逻辑**

```
get-decompilation with includeIncomingReferences=true, includeReferenceContext=true
→ Get full context of validation logic

find-cross-references direction="both" includeContext=true
→ Trace data flow and function relationships

read-memory to extract constants, tables, expected values
→ Get hardcoded comparison targets
```

### 可读性改进（Improvement Tools）

**边看边让代码“更像人话”：**

```
rename-variables to track data flow
→ input_buffer, encrypted_data, expected_hash

change-variable-datatypes to clarify operations
→ uint8_t* for byte buffers, uint32_t for crypto state

set-decompilation-comment to document findings
→ "AES round function", "Compares against flag"

set-bookmark for important locations
→ type="Analysis" for key findings
→ type="TODO" for things to investigate
```

## 关键原则（Key Principles）

### 1. 目标导向（Goal Focus）
**不要把所有东西都分析完——先拿 flag**
- 找关键路径（input → validation → success）
- 无关函数先放一边
- 足够理解 > 完全理解

### 2. 快速切换（Adapt Quickly）
**卡住就换策略**
- 静态看不动？上动态
- 太复杂？找绕过/爆破
- 模式对不上？可能是自定义算法

### 3. 复用经验（Leverage Knowledge）
**CTF 总在反复考同一批东西**
- 标准密码算法
- 常见混淆套路
- 典型校验结构
- 识别后直接套成熟解法

### 4. 记录进度（Document Progress）
**把你学到的东西记下来**
```
set-bookmark type="Analysis" category="Finding"
  → Document what you've confirmed

set-bookmark type="TODO" category="Investigate"
  → Track unanswered questions

set-decompilation-comment
  → Preserve understanding for later reference
```

### 5. 逐步验证（Verify Incrementally）
**边分析边验证你的假设**
- “如果是 AES，应该能看到 S-box 常量” → 去查
- “如果是 XOR 0x42，output[0] 应该是...” → 用例子验证
- “如果这是比较点，改这个字节��该...” → 动态验证

## 常见 CTF 题型（Common CTF Challenge Types）

### Crackme / 序列号校验
**题意：** 找到能通过校验的输入  
**方法：** 追数据流（input → validate）  
**关键：** 盯校验函数，提约束

### 算法还原（Algorithm Recovery）
**题意：** 还原/实现一个未知算法  
**方法：** 模式识别 + 理解运算  
**关键：** 找数学结构与数据变换链

### 密码题（Crypto Challenge）
**题意：** 解密密文或找 key  
**方法：** 识别算法，提取 key/IV，解密  
**关键：** 识别标准密码模式（见 patterns.md）

### 代码混淆（Code Obfuscation）
**题意：** 看懂混淆/壳/自解密代码  
**方法：** 动态观察解混淆后的状态  
**关键：** 让程序“自己跑出来”，你负责把结果抓出来

### Binary Bomb
**题意：** 多阶段输入，每阶段都要给对，否则“爆炸”  
**方法：** 分阶段分析，静态+动态结合  
**关键：** 每阶段通常考不同知识点，别硬刚一个阶段

### 自定义编码（Custom Encoding）
**题意：** 解码 flag 或正确编码输入  
**方法：** 识别编码方案，逆或复刻  
**关键：** 找变换循环与字符映射

## 与其他技能的结合（Integration with Other Skills）

### 二进制初筛之后（After Binary Triage）
**初筛标出可疑点 → CTF 视角深挖**

```
From triage bookmarks:
- "Crypto function at 0x401234" → Identify algorithm, extract key
- "Input validation at 0x402000" → Understand constraints, solve
- "Suspicious string XOR" → Decode to find flag or hint
```

### 配合深度分析（Using Deep Analysis）
**当你需要把某个函数彻底看懂时**

```
CTF skill identifies: "Validation at validate_key function"
Deep analysis answers: "What exactly does validate_key do?"
CTF skill uses result: Apply findings to extract flag
```

**工作流：**
1. CTF skill：给整体策略，定位关键函数
2. Deep analysis：把关键函数讲清楚
3. CTF skill：综合结论，产出最终解法/flag

## 成功标准（Success Criteria）

**你解出题的标志是：**

1. **能讲清楚机制：**
   - 输入如何变成输出
   - 校验机制是什么
   - 核心算法/套路是什么

2. **能给出答案：**
   - flag/key/password
   - 如何推出来的
   - 能验证则验证通过

3. **能复盘路径：**
   - 关键函数与地址
   - 关键变换/比较
   - 解法（逆/推/爆破/绕过）

## 记住（Remember）

CTF 逆向是**在约束下解题**：
- 时间有限
- 追求够用的理解，不追求完美
- 目标是 flag，不是写论文
- 卡住就换策略
- 多用模式与经验
- 静态/动态结合

**聚焦三问：**
1. 程序要什么输入？（格式/结构）
2. 程序做了什么？（变换/校验）
3. 怎么逆回来？（推/解/爆破/绕过）

答完这三问，你就离 flag 不远了。