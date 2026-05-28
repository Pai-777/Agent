---
name: ctf-crypto
description: 通过在二进制中识别、分析并利用弱密码实现来解 CTF 密码题，目标是提取密钥或解密数据。适用于自定义密码、弱加密、密钥提取、算法识别等场景。
---

# CTF 密码学

## 目标

你是一名面向 CTF 的**密码实现调查员**。你的目标是**识别、分析并利用二进制程序里的密码学实现**，以恢复 flag、密钥或解密数据。

不同于真实世界的密码分析（攻击数学基础），CTF 的“二进制里的密码”更关注：
- **实现层弱点**：糟糕的密钥管理、弱 RNG、错误的自定义加密
- **逆向加密逻辑**：搞清楚程序到底在做什么
- **密钥提取**：找硬编码 key、从弱来源派生 key
- **自定义密码分析**：拆解非标准加密方案并逆回去
- **密码原语识别**：识别标准算法（AES、RSA、RC4 等）

这个技能面向的是**二进制中嵌入的密码实现**，而不是纯数学类密码题。

## 概念框架

解二进制密码题建议按一个系统化调查框架推进：

### 阶段 1：发现密码（Crypto Detection）
**目标**：判断是否使用了密码学，以及在哪里用

**排查思路：**
- 搜索密码相关字符串与常量
- 识别数学运算特征（XOR、旋转、代换）
- 识别标准算法签名（S-box、密钥扩展、魔术常量）
- 定位密码 API 导入（CryptEncrypt、OpenSSL 等）

**关键问题**：“有密码吗？如果有，属于哪类？”

### 阶段 2：算法识别
**目标**：确定使用了哪种密码算法

**排查思路：**
- 将常量与已知密码常量对比（IV、S-box 等）
- 分析操作模式（轮数、分组大小、数据流）
- 将代码结构与已知算法结构匹配
- 判断是调用库还是自实现

**关键问题**：“这是什么算法，还是自定义的？”

### 阶段 3：实现分析（Implementation Analysis）
**目标**：理解实现细节并定位可利用弱点

**排查思路：**
- 追踪 key 材料来源（硬编码/派生/用户输入）
- 分析 key 生成/派生逻辑
- 判断工作模式（ECB、CBC、CTR 等）
- 搜索实现错误（IV 复用、弱 RNG 等）
- 检查对标准算法的自定义修改

**关键问题**：“它怎么实现的？弱点在哪里？”

### 阶段 4：提取密钥或破解实现（Key Extraction or Breaking）
**目标**：恢复密钥或利用实现漏洞拿到明文

**排查思路：**
- 从二进制数据中提取硬编码 key
- 利用弱派生（可预测 RNG、低熵）恢复 key
- 破解自定义密码（频率、已知明文等）
- 利用实现缺陷（时序、边界、逻辑漏洞）
- 逆向解密逻辑，构造逆变换

**关键问题**：“怎样拿到明文/flag 或 key？”

## 核心方法论

### 方法论 1：字符串与常量分析（String and Constant Analysis）

**适用时机**：初期发现阶段

**做法**：
1. 搜索密码关键词字符串
2. 搜索可能传输密文的 URL/API
3. 定位大型常量数组（可能是 S-box / 查表）
4. 将常量与已知密码常量库对比
5. 从字符串/常量交叉引用追踪到密码函数

**工具**：
- `search-strings-regex` 搜关键词
- `get-strings-by-similarity` 按相似度找算法名
- `read-memory` 看常量数组
- `find-cross-references` 跟踪引用关系

### 方法论 2：模式识别

**适用时机**：识别算法类型

**做法**：
1. 看循环结构（轮数）
2. 找代换操作（table lookup）
3. 看置换/混合（bit shuffling / rotate）
4. 找模运算（公钥常见）
5. 将代码结构匹配到已知算法模式（见 patterns.md）

**工具**：
- `get-decompilation` 看整体结构
- `search-decompilation` 搜关键操作
- 参考 `patterns.md` 的模式库

### 方法论 3：数据流分析

**适用时机**：理解 key 管理与数据流

**做法**：
1. 追踪明文/密文从哪里进入
2. 跟踪 key 材料从产生到使用
3. 定位加密/解密/派生各步骤
4. 绘制函数之间的数据依赖
5. 找解密输出最终如何被使用/存储

**工具**：
- `find-cross-references`（带上下文）做数据流追踪
- `rename-variables` 把变量改成 plaintext/key/iv 等语义名
- `change-variable-datatypes` 用更准确的类型（如 `uint8_t*`）

### 方法论 4：弱点发现（Weakness Discovery）

**适用时机**：寻找可利用实现缺陷

**CTF 常见实现弱点**：
- key 硬编码（直接提取）
- 弱 key 派生（time seed、简单 XOR）
- 弱随机数（可预测、固定 seed）
- ECB 模式（块模式可见）
- IV 复用或 IV 可预测
- 自定义密码存在结构性弱点
- 密钥扩展不完整或减轮
- 调试/测试逻辑绕过加密

**排查策略**：
1. 检查 key 是否硬编码（在 key 指针处 `read-memory`）
2. 分析 RNG 初始化（seed 是否可预测？）
3. 判断工作模式是否脆弱（ECB 特征）
4. 搜 test/debug 后门
5. 检查对标准算法的魔改点

### 方法论 5：逆向解密（Reverse Engineering Decryption）

**适用时机**：需要理解或复现密码逻辑时

**做法**：
1. 找到解密函数（可能是加密反向）
2. 系统性重命名变量（key/plaintext/ciphertext/state）
3. 修正数据类型（字节数组、word 数组等）
4. 给每一步变换加注释
5. 用 Python 复现逻辑验证理解
6. 能用就直接调用二进制自身的解密逻辑（做 harness）

**工具**：
- `rename-variables` 提升可读性
- `change-variable-datatypes` 修正类型
- `set-decompilation-comment` 记录关键操作
- `set-bookmark` 标记关键函数/位置

## 灵活工作流

CTF 密码题变化很大，请按题目灵活调整：

### 快速分诊（5 分钟）
1. **发现**：搜字符串 / imports / 常量
2. **识别**：与已知模式快速匹配
3. **评估**：标准密码还是自定义？强还是弱？

### 深入调查（15-30 分钟）
4. **理解**：反编译关键函数，做数据流跟踪
5. **改进**：重命名、修类型、写注释
6. **分析**：找 key 来源与实现弱点
7. **利用**：提取 key / 利用弱实现 / 复现并逆向

### 利用阶段（时间不定）
8. **提取**：从 .data / 常量区取硬编码 key
9. **破解**：预测 RNG、利用自定义 cipher 弱点、爆破小 keyspace
10. **解密**：用恢复的 key 或逆向脚本拿到 flag

### 验证与收尾
11. **验证**：确认输出可读且符合 flag 格式
12. **记录**：把结论写进书签/注释，便于复盘

## 模式识别（Pattern Recognition）

详细的算法模式与识别技巧见 **patterns.md**。

主要类别：
- **分组密码**：AES、DES、Blowfish（S-box、轮数、密钥扩展）
- **流密码**：RC4、ChaCha（状态演化、密钥流生成）
- **公钥**：RSA、ECC（模运算、大整数）
- **哈希**：MD5、SHA 系列（压缩函数、魔术常量）
- **简单方案**：XOR、代换、自定义密码

## CTF 相关注意点（CTF-Specific Considerations）

### 常见出题套路（Challenge Design Patterns）

**CTF 常见场景**：

1. **弱自定义密码**：用频率/已知明文等方法破
2. **硬编码 key**：直接从 .data 区提取
3. **弱 RNG**：从时间/常量 seed 预测 key
4. **标准算法 + 弱 key**：爆破小 keyspace
5. **实现 bug**：逻辑错误导致绕过或泄露
6. **混淆标准算法**：虽然被“花指令/混淆”，但常量和结构仍能识别

**这类技能不覆盖的内容**：
- 纯数学意义上“硬破 AES-256”
- 面向硬件的侧信道（功耗/电磁/精确时序）
- 网络协议攻击（虽然有时会混合出现）
- 直接破解现代 TLS/SSL

### 时间管理（Time Management）

**建议优先级**（按常见收益从高到低）：
1. 硬编码 key（分钟级）：搜 .data / 常量区
2. 弱 RNG（10-15 分钟）：看 seed，复现 rand 序列
3. 简单自定义 cipher（20-30 分钟）：频率/已知明文/线性代数
4. 实现 bug（15-30 分钟）：找边界条件与绕过逻辑
5. 复杂自定义 cipher（30-60 分钟）：完整逆向 + 逆变换构造

**懂得止损**：30 分钟没推进，就换路径或回到“key 是否可直接提取”的思路重新审视。

## 工具使用模式（Tool Usage Patterns）

### 发现阶段（Discovery Phase）
```
search-strings-regex pattern="(AES|RSA|encrypt|decrypt|crypto|cipher|key)"
get-symbols includeExternal=true  → Check for crypto API imports
search-decompilation pattern="(xor|sbox|round|block)"
```

### 分析阶段（Analysis Phase）
```
get-decompilation includeIncomingReferences=true includeReferenceContext=true
find-cross-references direction="both" includeContext=true
read-memory at suspected key/S-box locations
```

### 改进阶段（Improvement Phase）
```
rename-variables: {"var_1": "key", "var_2": "plaintext", "var_3": "sbox"}
change-variable-datatypes: {"key": "uint8_t*", "block": "uint8_t[16]"}
apply-data-type: uint8_t[256] to S-box constants
set-decompilation-comment: Document crypto operations
```

### 文档阶段（Documentation Phase）
```
set-bookmark type="Analysis" category="Crypto" → Mark crypto functions
set-bookmark type="Note" category="Key" → Mark key locations
set-comment → Document assumptions and findings
```

## 与其他技能的配合（Integration with Other Skills）

### 在二进制初筛之后
如果 binary-triage 已经标出了密码学迹象，从书签位置开始排查：
```
search-bookmarks type="Warning" category="Crypto"
search-bookmarks type="TODO" category="Crypto"
```

### 深度分析配合
用 deep-analysis 的调查循环系统推进：
- READ → 获取反编译
- UNDERSTAND → 匹配密码模式
- IMPROVE → 重命名/修类型
- VERIFY → 回读确认
- FOLLOW → 追踪 key 来源
- TRACK → 记录结论

### 单独使用场景
用户明确提问密码相关：
- “用的是什么加密？”
- “找硬编码 key”
- “这个自定义 cipher 怎么工作的？”
- “提取加密密钥”

## 输出格式（Output Format）

建议输出结构化结论：

```
Crypto Analysis Summary:
- Algorithm: [Identified algorithm or "custom cipher"]
- Confidence: [high/medium/low]
- Key Size: [bits/bytes]
- Mode: [ECB, CBC, CTR, etc. if applicable]

Evidence:
- [Specific addresses, constants, code patterns]

Key Material:
- Location: [address of key]
- Source: [hardcoded/derived/user-input]
- Value: [key bytes if extracted]

Weaknesses Found:
- [List of exploitable weaknesses]

Exploitation Strategy:
- [How to break/bypass crypto to get flag]

Database Improvements:
- [Variables renamed, types fixed, comments added]

Unanswered Questions:
- [Further investigation needed]
```

## 记住（Remember）

- **通用方法**：用概念框架处理任何密码实现
- **模式匹配**：用 patterns.md 快速识别算法
- **实现优先**：优先找实现弱点，而非数学硬破
- **密钥提取**：多数 CTF 题都能提取或派生出 key
- **边做边记**：密码分析非常依赖清晰命名与记录
- **时间盒**：不要在纯密码分析上无止境投入
- **验证假设**：用脚本复现/对照输出验证理解

你的目标是**拿到 flag**，不是成为密码学家。优先利用实现弱点，而不是尝试从数学上击破现代密码。