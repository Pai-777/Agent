# Deep Analysis Skill - 调查示例

本文档提供一些具体例子，展示如何使用 deep-analysis 技能去回答逆向中的特定问题。

## 示例 1："这个函数是干什么的？"

### 初始问题
用户："函数 `FUN_00401850` 是干什么的？"

### 调查流程

**阶段 1：初始上下文（2 次调用）**

1. 获取带上下文的反编译：
```
get-decompilation FUN_00401850 limit=30
  includeIncomingReferences=true
  includeReferenceContext=true
```

观察到：
- 循环迭代 32 次
- 位运算（XOR、移位）
- 通过计算下标访问数组
- 被 `process_buffer` 与 `send_encrypted_data` 调用

2. 查看交叉引用：
```
find-cross-references location="0x401850" direction="to"
  includeContext=true contextLines=3
```

观察到：
- 以 3 个参数调用：数据 buffer、长度、key buffer
- 返回值未检查
- 始终传入 32 字节 key buffer

**阶段 2：模式识别（2 次调用）**

3. 读取常量数据：
```
read-memory addressOrSymbol="0x404100" length=256
```

发现：以 `63 7c 77 7b f2 6b 6f c5...` 开头

对比：与 patterns.md 中 AES S-box 匹配

4. 设置初始书签：
```
set-bookmark type="Analysis" category="Crypto"
  addressOrSymbol="0x401850"
  comment="Investigating encryption function - appears to be AES"
```

**阶段 3：迭代改进（6 次调用）**

5. 重命名关键变量：
```
rename-variables FUN_00401850 {
  "param_1": "data",
  "param_2": "data_len",
  "param_3": "key",
  "local_10": "round",
  "local_14": "sbox_ptr"
}
```

6. 重新查看以验证：
```
get-decompilation FUN_00401850 limit=30
```

清晰很多！现在能看到：`data[i] = sbox_ptr[data[i] ^ key[round]]`

7. 修正数据类型：
```
change-variable-datatypes FUN_00401850 {
  "data": "uint8_t*",
  "data_len": "size_t",
  "key": "uint8_t*",
  "sbox_ptr": "uint8_t*"
}
```

8. 设置函数原型：
```
set-function-prototype location="0x401850"
  signature="void aes_encrypt_block(uint8_t* data, size_t len, uint8_t* key)"
```

9. 添加说明性注释：
```
set-decompilation-comment FUN_00401850 line=15
  comment="AES S-box substitution - confirms AES encryption"
```

10. 记录结论：
```
set-comment programPath="/malware.exe" addressOrSymbol="0x401850"
  type="pre"
  comment="AES encryption function: encrypts data in place using 32-round AES with S-box at 0x404100"
```

**阶段 4：返回结果**

### 回答
```json
{
  "question": "What does function FUN_00401850 do?",
  "answer": "Performs AES encryption on a data buffer in-place",
  "confidence": "high",
  "evidence": [
    "Uses standard AES S-box at 0x404100 (verified match: 63 7c 77 7b...)",
    "32-round loop structure typical of AES-256",
    "S-box substitution pattern at 0x401850:15",
    "Called with data, length, and 32-byte key parameters",
    "Invoked by send_encrypted_data and process_buffer functions"
  ],
  "assumptions": [
    {
      "assumption": "Function performs full AES encryption, not just one component",
      "evidence": "Complete 32-round structure with key schedule",
      "confidence": "high"
    }
  ],
  "improvements_made": [
    "Renamed 5 variables for clarity (data, data_len, key, round, sbox_ptr)",
    "Fixed 4 data types (uint8_t* for buffers, size_t for length)",
    "Set function prototype: void aes_encrypt_block(uint8_t* data, size_t len, uint8_t* key)",
    "Added decompilation comment on S-box substitution line",
    "Added address-level comment documenting AES usage"
  ],
  "unanswered_threads": [
    {
      "question": "Where does the 32-byte encryption key come from?",
      "starting_point": "Cross-references to aes_encrypt_block - check callers",
      "priority": "high",
      "context": "Key appears to be passed from calling functions, need to trace origin"
    },
    {
      "question": "What data is being encrypted?",
      "starting_point": "Functions process_buffer (0x402100) and send_encrypted_data (0x402500)",
      "priority": "high",
      "context": "These callers determine what data gets encrypted"
    },
    {
      "question": "Is this using proper AES mode (CBC, CTR, etc.) or just ECB?",
      "starting_point": "Examine calling context for IV usage or block chaining",
      "priority": "medium",
      "context": "Need to check if callers implement proper mode of operation"
    }
  ]
}
```

---

## 示例 2："这个二进制用了加密吗？"

### 初始问题
用户："这个二进制用了加密吗？"

### 调查流程

**阶段 1：广域发现（3 次调用）**

1. 搜索密码相关字符串：
```
search-strings-regex pattern="(AES|RSA|encrypt|decrypt|crypto|cipher|key)"
  caseSensitive=false
```

结果：没发现明显密码字符串

2. 在反编译中搜索模式：
```
search-decompilation pattern="(\^|\&\s*0x(FF|ff)|<<|>>).*loop"
  maxResults=20
```

发现：多个函数在循环里出现 XOR 与位运算

3. 查看可疑导入：
```
get-symbols includeExternal=true filterDefaultNames=true startIndex=0 maxCount=200
```

发现：没有明显的密码库导入

**阶段 2：调查候选点（4 次调用）**

4. 查看最可疑函数：
```
get-decompilation FUN_00402340 limit=40
  includeIncomingReferences=true
```

观察到：嵌套循环、数组索引、取模运算

5. 查常量数组引用：
```
find-cross-references location="0x402340" direction="from" limit=50
```

发现：引用了 0x405000（大数据段）

6. 读取可疑内存区域：
```
read-memory addressOrSymbol="0x405000" length=256
```

发现：数组先被初始化为 0-255 连续序列，然后被修改

模式匹配：像 RC4 初始化！

7. 书签记录：
```
set-bookmark type="Analysis" category="Crypto"
  addressOrSymbol="0x402340"
  comment="Suspected RC4 cipher - 256-byte state array"
```

**阶段 3：确认模式（3 次调用）**

8. 改进理解：
```
rename-variables FUN_00402340 {
  "local_10": "state_array",
  "local_14": "i",
  "local_18": "j",
  "param_1": "key",
  "param_2": "key_len"
}
```

9. 重新检查：
```
get-decompilation FUN_00402340 limit=40
```

清晰的 RC4 KSA 模式：
```c
for (i = 0; i < 256; i++) {
  state_array[i] = i;
}
j = 0;
for (i = 0; i < 256; i++) {
  j = (j + state_array[i] + key[i % key_len]) % 256;
  // swap state_array[i] and state_array[j]
}
```

10. 记录：
```
set-comment programPath="/binary.exe" addressOrSymbol="0x402340"
  type="pre"
  comment="RC4 Key Scheduling Algorithm (KSA) - initializes cipher state from key"
```

**阶段 4：返回结果**

### 回答
```json
{
  "question": "Does this binary use encryption?",
  "answer": "Yes, uses RC4 stream cipher",
  "confidence": "high",
  "evidence": [
    "RC4 KSA (Key Scheduling Algorithm) at 0x402340",
    "256-byte state array initialization (0-255 sequence)",
    "Characteristic RC4 swap operations with modulo arithmetic",
    "State array modified based on key input",
    "Pattern matches RC4 specification exactly"
  ],
  "assumptions": [
    {
      "assumption": "RC4 PRGA (encryption loop) exists in separate function",
      "evidence": "KSA alone doesn't encrypt, must have companion function",
      "confidence": "medium"
    }
  ],
  "improvements_made": [
    "Renamed 5 variables in RC4 KSA function",
    "Documented RC4 KSA at 0x402340",
    "Set bookmark for crypto analysis"
  ],
  "unanswered_threads": [
    {
      "question": "Where is the RC4 PRGA (actual encryption) function?",
      "starting_point": "Check cross-references from KSA, likely called next",
      "priority": "high",
      "context": "KSA initializes state, PRGA uses it to encrypt"
    },
    {
      "question": "What is the RC4 key and where does it come from?",
      "starting_point": "Analyze callers of RC4 KSA at 0x402340",
      "priority": "high",
      "context": "Key parameter origin determines if hardcoded or derived"
    },
    {
      "question": "What data is being encrypted with RC4?",
      "starting_point": "Find PRGA function, then check its callers",
      "priority": "medium",
      "context": "Need to identify what sensitive data is being protected"
    }
  ]
}
```

---

## 示例 3："C2 服务器地址是什么？"

### 初始问题
用户："C2 服务器地址是什么？"

### 调查流程

**阶段 1：搜索网络迹象（3 次调用）**

1. 搜索 URL 与 IP：
```
search-strings-regex pattern="(https?://|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|\.com|\.net)"
  caseSensitive=false
```

发现：没有明显域名/IP

2. 搜索网络相关字符串：
```
search-strings-regex pattern="(connect|server|host|port|callback|beacon)"
  caseSensitive=false
```

发现：在 0x404500 有字符串 "host"

3. 查看 "host" 周围内存：
```
read-memory addressOrSymbol="0x404500" length=64
```

发现："host" 后面跟着编码数据

**阶段 2：定位字符串使用点（3 次调用）**

4. 查可疑字符串的交叉引用：
```
find-cross-references location="0x404500" direction="to"
  includeContext=true contextLines=4
```

发现：被 FUN_00403000 引用，看起来像字符串解码

5. 调查解码函数：
```
get-decompilation FUN_00403000 limit=30
  includeIncomingReferences=true
```

观察到：XOR 循环解码 0x404500 区域的字符串

6. 书签记录解码函数：
```
set-bookmark type="Analysis" category="Obfuscation"
  addressOrSymbol="0x403000"
  comment="String decoding function - XOR with 0x42"
```

**阶段 3：理解解码逻辑（4 次调用）**

7. 改进解码函数：
```
rename-variables FUN_00403000 {
  "param_1": "encoded_str",
  "param_2": "output_buf",
  "local_8": "i",
  "local_c": "str_len"
}
```

8. 为解码逻辑加注释：
```
set-decompilation-comment FUN_00403000 line=8
  comment="XOR decode with key 0x42 - reveals hidden strings"
```

9. 找解码后的字符串被谁用：
```
find-cross-references location="0x403000" direction="to"
  includeContext=true
```

发现：被 FUN_00403500 调用（网络初始化函数）

10. 查看网络函数：
```
get-decompilation FUN_00403500 limit=40
  includeIncomingReferences=true
  includeReferenceContext=true
```

观察到：
```c
decode_string(encoded_c2, hostname_buf);  // 0x403000
connect_to_server(hostname_buf, 443);
```

**阶段 4：解码 C2 地址（3 次调用）**

11. 读取 C2 编码数据：
```
read-memory addressOrSymbol="0x404520" length=32
```

得到字节：`2b 37 37 33 1a 0e 0e 6f 63 6c 6c 67 69 67 77 79 1e 65 6d 6f 00`

手动解码（XOR 0x42）：
- 0x2b ^ 0x42 = 'i'
- 0x37 ^ 0x42 = 'u'
- 0x37 ^ 0x42 = 'u'
- 结果："iuuxy//evil-malware.com"

12. 记录 C2：
```
set-comment programPath="/malware.exe" addressOrSymbol="0x404520"
  type="pre"
  comment="Encoded C2 address (XOR 0x42): https://evil-malware.com"
```

13. 记录网络函数：
```
set-comment programPath="/malware.exe" addressOrSymbol="0x403500"
  type="pre"
  comment="C2 connection function: decodes and connects to https://evil-malware.com:443"
```

**阶段 5：返回结果**

### 回答
```json
{
  "question": "What is the command and control server address?",
  "answer": "https://evil-malware.com (port 443)",
  "confidence": "high",
  "evidence": [
    "Encoded string at 0x404520 decodes to domain",
    "String decode function at 0x403000 uses XOR key 0x42",
    "Network init function at 0x403500 decodes and uses domain",
    "Connection established on port 443 (HTTPS)",
    "Manual decode confirmed: iuuxy// → https:// (XOR 0x42)"
  ],
  "assumptions": [
    {
      "assumption": "This is the only C2 address",
      "evidence": "Only encoded network string found so far",
      "confidence": "medium",
      "note": "May have fallback/backup C2 addresses"
    }
  ],
  "improvements_made": [
    "Renamed variables in decode function (0x403000)",
    "Added comments on XOR decode logic",
    "Documented decoded C2 address at storage location",
    "Documented C2 connection function"
  ],
  "unanswered_threads": [
    {
      "question": "Are there backup/fallback C2 addresses?",
      "starting_point": "Search for other encoded strings, check for C2 lists",
      "priority": "high",
      "context": "Malware often has multiple C2 servers for redundancy"
    },
    {
      "question": "What protocol is used for C2 communication?",
      "starting_point": "Analyze functions called after connect_to_server",
      "priority": "medium",
      "context": "Connects on port 443, likely HTTPS but may be custom"
    },
    {
      "question": "Is the C2 address hardcoded or can it be updated?",
      "starting_point": "Check for config file reading or domain generation",
      "priority": "medium",
      "context": "Dynamic C2 would indicate more sophisticated malware"
    }
  ]
}
```

---

## 示例 4："把这个函数的类型修一下"

### 初始问题
用户："把函数 `FUN_00402800` 的类型修一下——反编译看着太乱了"

### 调查流程

**阶段 1：理解现状（2 次调用）**

1. 获取当前反编译：
```
get-decompilation FUN_00402800 limit=50
```

观察到很乱的代码：
```c
undefined4 FUN_00402800(int param_1, undefined4 param_2) {
  int iVar1;
  undefined4 *puVar2;
  undefined4 uVar3;

  iVar1 = *(int *)(param_1 + 4);
  puVar2 = (undefined4 *)(param_1 + 8);
  uVar3 = *puVar2;
  // ... more confusing code ...
}
```

2. 查看调用上下文：
```
find-cross-references location="0x402800" direction="to"
  includeContext=true contextLines=5
```

观察到：第一个参数像结构体指针，第二个参数像 size

**阶段 2：分析使用模式（3 次调用）**

3. 看访问的字段：
- `param_1 + 0`：按 int 读
- `param_1 + 4`：按 int 读
- `param_1 + 8`：按指针读  
结论：结构体布局像 `int, int, pointer`

4. 看第二参数的用途：
```
Search in decompilation for param_2 usage
```

发现：用于比较 `if (iVar1 < param_2)`，也用作循环上界  
结论：param_2 是 count/size，应该是 `size_t` 或 `uint32_t`

5. 看返回值用法：
```
Check caller context from xrefs
```

发现：返回值与 0/1 比较  
结论：返回成功/失败（bool 或状态码 int）

**阶段 3：迭代修类型（5 次调用）**

6. 先修函数签名：
```
set-function-prototype location="0x402800"
  signature="int process_items(struct item_list* list, uint32_t max_count)"
  createIfNotExists=false
```

7. 为 param_1 建结构体：
```
parse-c-structure programPath="/binary.exe"
  cDefinition="struct item_list { uint32_t current_count; uint32_t total_count; void** items; };"
```

8. 在调用处应用结构（检查一个 caller）：
```
Get address of a caller from xrefs: 0x403100
```

9. 修函数内变量类型：
```
change-variable-datatypes FUN_00402800 {
  "iVar1": "uint32_t",
  "puVar2": "void**"
}
```

10. 重命名变量：
```
rename-variables FUN_00402800 {
  "param_1": "list",
  "param_2": "max_count",
  "iVar1": "current_count",
  "puVar2": "items_array",
  "uVar3": "current_item"
}
```

**阶段 4：验证与记录（3 次调用）**

11. 重新查看反编译：
```
get-decompilation FUN_00402800 limit=50
```

清晰很多：
```c
int process_items(item_list* list, uint32_t max_count) {
  uint32_t current_count;
  void** items_array;
  void* current_item;

  current_count = list->total_count;
  items_array = list->items;
  current_item = *items_array;
  // ... clearer logic now ...
}
```

12. 添加说明：
```
set-decompilation-comment FUN_00402800 line=5
  comment="Iterates through item list up to max_count limit"
```

13. 记录结构体用途：
```
set-comment programPath="/binary.exe" addressOrSymbol="0x402800"
  type="pre"
  comment="Processes item_list structure: validates count and iterates items array"
```

**阶段 5：返回结果**

### 回答
```json
{
  "question": "Fix the types in function FUN_00402800",
  "answer": "Fixed - function processes item_list structure with count validation",
  "confidence": "high",
  "evidence": [
    "Structure pattern identified: int + int + pointer at offsets 0, 4, 8",
    "Second parameter used as loop bound (confirmed uint32_t)",
    "Return value used as boolean (0/1 success code)",
    "Cross-references confirm structure pointer usage",
    "Decompilation much clearer after type fixes"
  ],
  "improvements_made": [
    "Created item_list structure: { uint32_t current_count; uint32_t total_count; void** items; }",
    "Set function prototype: int process_items(item_list* list, uint32_t max_count)",
    "Fixed 2 variable types (uint32_t, void**)",
    "Renamed 5 variables for clarity (list, max_count, current_count, items_array, current_item)",
    "Added decompilation comment documenting behavior",
    "Added address-level comment on structure usage"
  ],
  "assumptions": [
    {
      "assumption": "items array contains void pointers (generic items)",
      "evidence": "No type-specific operations on items, just pointer manipulation",
      "confidence": "medium",
      "note": "Actual item type may be more specific"
    },
    {
      "assumption": "Structure is consistently used across codebase",
      "evidence": "Multiple callers use same access pattern",
      "confidence": "high"
    }
  ],
  "unanswered_threads": [
    {
      "question": "What is the actual type of items in the array?",
      "starting_point": "Check where items are allocated and how they're used",
      "priority": "medium",
      "context": "Currently typed as void** but may be more specific struct"
    },
    {
      "question": "Should item_list structure be applied at allocation sites?",
      "starting_point": "Find where item_list structures are created (malloc calls)",
      "priority": "low",
      "context": "Applying structure type at allocation improves consistency"
    },
    {
      "question": "Are there other functions using this structure that need fixing?",
      "starting_point": "Search for similar offset access patterns (param+0, param+4, param+8)",
      "priority": "medium",
      "context": "Consistent type usage across codebase aids understanding"
    }
  ]
}
```

---

## 示例中的关键总结（Key Takeaways from Examples）

### 调查中的共性模式

1. **先粗后细**
   - 先搜索/扫描
   - 找候选点
   - 再深入具体函数

2. **迭代：读 → 改 → 验**
   - 读反编译
   - 重命名/修类型
   - 再读确认更清晰

3. **跟证据走**
   - xref 看调用关系
   - 读内存看常量
   - 模式匹配确认算法

4. **边做边记录**
   - 书签做路标
   - 注释记录发现
   - 让调查有条理可复盘

5. **返回可执行的后续线索**
   - 总要有 next steps
   - 给明确起点
   - 按重要性排序

### 工具调用效率

每个示例都控制在 10-15 次工具调用：
- 示例 1：10 次
- 示例 2：10 次
- 示例 3：13 次
- 示例 4：13 次

这说明在保持聚焦的同时，仍然能拿到足够证据并做出有效改进。

### 基于证据的结论

每个答案都包含：
- 具体地址
- 发现的代码模式/常量
- 交叉引用证据
- 置信度与理由

这样结论才可验证、可信。

File name: patterns.md
Language: 
# 逆向式参考（Reverse Engineering Patterns Reference）

本文档包含在 deep analysis 中需要识别的更高层模式与概念。重点关注算法模式、行为模式与代码结构，而不是平台相关的实现细节。

## 密码算法模式（Cryptographic Algorithm Patterns）

### 分组密码识别（Block Cipher Recognition）

**概念特征：**
- **代换-置换网络（SPN）**：多轮代换（S-box）与置换（比特洗牌）重复执行
- **Feistel 网络**：数据分成左右两半，对一半做轮函数，另一半参与 XOR，然后交换并重复
- **固定分组大小**：通常 64 bit（DES、Blowfish）或 128 bit（AES）
- **多轮**：8-16+ 次核心变换迭代
- **密钥扩展（Key schedule）**：从主密钥派生轮密钥

**在反编译代码里要看的点：**
```
Nested loops:
  Outer: rounds (8, 10, 12, 14, 16, 32 iterations)
  Inner: processing blocks of fixed size

Array lookups (S-boxes):
  result = table[input_byte]
  Often 256-element arrays (0x100 size)

Bit manipulation:
  XOR, rotation (>> combined with <<), permutation

State updates:
  Array or struct representing current cipher state
  Transformed each round
```

**明显特征：**
- 大型常量数组（256+ 字节），看起来像随机数据
- 固定迭代次数（与数据无关）
- 大量 XOR
- 字节级索引：`array[data[i]]`

**排查策略：**
1. 对常量数组 `read-memory`，与已知 S-box 对比
2. 数外层循环轮数，推算法/密钥位数
3. `search-strings-regex` 搜算法名
4. 查常量交叉引用，找初始化逻辑

### 流密码识别（Stream Cipher Recognition）

**概念特征：**
- **生成密钥流**：从 key 生成伪随机字节流
- **组合简单**：明文 XOR 密钥流
- **状态驱动**：内部状态不断演化
- **无固定分组**：可处理任意长度

**在代码里要看的点：**
```
State initialization:
  Array or struct setup from key
  Often 256-byte arrays

Keystream generation loop:
  State updates via modular arithmetic
  Index computations: i = (i + 1) % N
  Swap operations common

XOR combination:
  output[i] = input[i] ^ keystream[i]
  Simple, obvious pattern
```

**明显特征：**
- swap：`temp = a[i]; a[i] = a[j]; a[j] = temp`
- 取模：`% 256` 或 `& 0xFF`
- 简单 XOR 循环
- 代码体量通常比分组密码小（无大表）

### 公钥密码识别（Public Key Cryptography Recognition）

**概念特征：**
- **大整数运算**：数值达到数百/数千 bit
- **模幂**：`result = base^exponent mod modulus`
- **性能**：明显慢（多用于交换密钥/签名，不用于大量数据）

**在代码里要看的点：**
```
Multi-precision arithmetic:
  Arrays representing big integers
  Functions for add/subtract/multiply on arrays

Square-and-multiply pattern:
  Loop over exponent bits
  Square operation each iteration
  Conditional multiply based on bit value

Modulo operations on large numbers:
  Division with large divisors
  Barrett reduction or Montgomery multiplication
```

**明显特征：**
- 很大的 buffer（128/256/512 字节以上）
- exponent 按 bit 处理
- 魔术常量（RSA 常见 e=0x10001）
- 执行很慢（每字节很多操作）

### 哈希函数识别（Hash Function Recognition）

**概念特征：**
- **压缩函数**：固定大小输入 → 固定大小输出
- **按块处理**：典型 512 bit
- **状态累积**：每块更新状态
- **padding**：追加 0x80、0、长度
- **单向**：强混合，不可逆

**在代码里要看的点：**
```
Initialization:
  Fixed magic constants
  MD5: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  SHA-1: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
  SHA-256: 8 different constants

Round function:
  Fixed iteration count (64, 80 rounds)
  Lots of bitwise operations (rotations, XOR, AND, OR)
  State mixing (each output bit depends on many input bits)

Padding logic:
  Append 0x80 byte
  Length encoding at end
```

**明显特征：**
- 典型初始化常量
- 固定 64/80 轮循环
- 位旋转：`(x << n) | (x >> (32-n))`
- message schedule（W 数组扩展）

### 简单 XOR 混淆（Simple XOR Obfuscation）

**概念特征：**
- **操作极其简单**：`output = input XOR key`
- **对称**：加解密相同
- **安全性弱**：用于混淆而非保护

**在代码里要看的点：**
```
Single-byte key:
  for (i = 0; i < len; i++)
    data[i] ^= 0x42;

Multi-byte key:
  for (i = 0; i < len; i++)
    data[i] ^= key[i % keylen];

Rolling key:
  key = seed;
  for (i = 0; i < len; i++) {
    data[i] ^= key;
    key = update_key(key);  // LCG or similar
  }
```

**明显特征：**
- 函数很短（5-10 行）
- XOR 常量或简单 key
- 常用于字符串/配置解码
- 搭配静态数据数组（要解码才能看到）

---

## 控制流模式（Control Flow Patterns）

### 状态机识别（State Machine Recognition）

**概念特征：**
- **显式状态**：枚举或整数表示当前状态
- **状态跳转**：基于 state 变量的 switch/if-else
- **事件驱动**：外部输入触发转移

**在代码里要看的点：**
```
State variable:
  int state = INITIAL_STATE;

Dispatch loop:
  while (running) {
    switch (state) {
      case STATE_A: /* handle A, maybe transition to B */
      case STATE_B: /* handle B, maybe transition to C */
      ...
    }
  }

State tables (more advanced):
  next_state = transition_table[current_state][input];
  action = action_table[current_state][input];
```

**明显特征：**
- 很大的 switch，case 很多
- state 变量反复被赋新值
- 有枚举或 #define 的状态常量
- 常见状态名：IDLE/CONNECTING/CONNECTED/DISCONNECTED 等

**常见用途：**
- 网络协议处理
- 解析器（parser）实现
- UI 事件处理
- 命令处理

### 命令分发器识别（Command Dispatcher Recognition）

**概念特征：**
- **命令码**：用���字 ID 标识不同操作
- **handler 查找**：命令 ID → 处理函数
- **可扩展**：易于新增命令

**在代码里要看的点：**
```
Command dispatch table:
  switch (command_id) {
    case CMD_EXECUTE:  handle_execute(params); break;
    case CMD_UPLOAD:   handle_upload(params); break;
    case CMD_DOWNLOAD: handle_download(params); break;
    ...
  }

Function pointer table:
  handler = command_table[command_id];
  handler(params);

String-based dispatch:
  if (strcmp(cmd, "exec") == 0) handle_execute();
  else if (strcmp(cmd, "upload") == 0) handle_upload();
```

**明显特征：**
- 对整数或字符串做大 switch
- 函数指针数组
- 命令 ID 常量或字符串
- 常见命令名：exec/upload/download/shell/sleep 等

**常见用途：**
- 远控（RAT）/后门命令处理
- 插件系统
- IPC/RPC

### 回调模式识别（Callback Pattern Recognition）

**概念特征：**
- **控制反转**：库/框架调用你的函数
- **函数指针**：把函数地址传给框架
- **异步**：常见于异步事件

**在代码里要看的点：**
```
Callback registration:
  library_set_callback(MY_EVENT, my_handler_function);

Callback function signature:
  void my_callback(event_type, data, user_context)

Common callback contexts:
  - Network data received
  - Timer expired
  - File I/O complete
  - User interaction
```

**明显特征：**
- 参数里出现函数指针
- 函数名像 handler/callback/on_event
- 常带 `void* user_data` 这类不透明指针

### 循环模式（Loop Patterns）

**简单迭代：**
```
for (i = 0; i < count; i++)
  - Linear processing
  - Transform/encrypt each element
```

**嵌套循环（2D 处理）：**
```
for (i = 0; i < height; i++)
  for (j = 0; j < width; j++)
    - Image processing
    - Matrix operations
    - Block cipher on 2D state
```

**do-while：**
```
do {
  read_chunk();
  process_chunk();
} while (more_data);
  - File/network processing
  - Guaranteed first execution
```

**while(true)+break：**
```
while (1) {
  if (condition) break;
  process();
}
  - Server loops
  - State machines
  - Event loops
```

---

## 数据结构模式（Data Structure Patterns）

### 缓冲区管理（Buffer Management）

**定长缓冲区：**
```
char buffer[1024];
read(fd, buffer, sizeof(buffer));
  - Stack-allocated
  - Size known at compile time
  - Often seen with unsafe functions (strcpy, sprintf)
```

**动态缓冲区：**
```
size = calculate_size();
buffer = malloc(size);
  - Heap-allocated
  - Size determined at runtime
  - Look for malloc/free pairs or memory leaks
```

**环形缓冲区（Ring Buffer / Circular Buffer）：**
```
write_pos = (write_pos + 1) % BUFFER_SIZE;
read_pos = (read_pos + 1) % BUFFER_SIZE;
  - Fixed-size, reusable
  - Modulo arithmetic for wrap-around
  - Used in queues, streaming
```

### 链式结构（Linked Structures）

**链表（Linked list）：**
```
struct node {
  data_type data;
  struct node* next;  // singly-linked
  struct node* prev;  // doubly-linked (optional)
};
```

**识别：**
- 结构体里有指针字段
- 遍历：`while (node != NULL) { node = node->next; }`
- 插入/删除操作

**树结构（Tree structures）：**
```
struct tree_node {
  data_type data;
  struct tree_node* left;
  struct tree_node* right;
};
```

**识别：**
- 两个指针字段（left/right）
- 递归函数
- 用比较操作维持有序

### 字符串处理模式（String Handling Patterns）

**长度前缀字符串（Length-prefixed strings）：**
```
struct {
  uint32_t length;
  char data[];
}
```

**以 0 结尾的字符串（Null-terminated strings）：**
```
while (*str != '\0') str++;  // strlen pattern
```

**宽字符串（Wide strings）：**
```
wchar_t* wstr;
uint16_t* utf16_str;
  - 2 or 4 bytes per character
  - String operations work on larger units
```

**检测：**
- 逐字符循环
- `\0` 检查
- 字符串操作函数调用
- UTF-8/UTF-16 编解码

---

## 网络协议模式（Network Protocol Patterns）

### 协议结构识别（Protocol Structure Recognition）

**请求-响应（Request-Response）：**
```
send_request(command, params);
response = receive_response();
process_response(response);
```

**特征：**
- 客户端先发起
- 服务端响应
- 阻塞或轮询等待
- 例：HTTP、DNS、RPC

**持续流（Continuous Stream）：**
```
while (connected) {
  data = receive_data();
  process_chunk(data);
}
```

**特征：**
- 长连接
- 数据持续流动
- 无严格请求响应配对
- 例：视频流、日志流

**消息型（Message-Oriented）：**
```
while (true) {
  message = receive_message();  // reads length, then payload
  dispatch_message(message);
}
```

**特征：**
- 有明确消息边界
- 长度前缀或分隔符
- 消息类型/ID 字段
- 例：自定义 C2、消息队列

### 序列化模式（Serialization Patterns）

**二进制序列化：**
```
Write primitives in sequence:
  write_uint32(length);
  write_bytes(data, length);
  write_uint8(flags);
```

**特征：**
- 紧凑高效
- 固定字节序
- 魔数用于识别结构
- 版本字段用于兼容

**文本序列化：**
```
JSON: {"key": "value", "num": 42}
XML: <root><item>value</item></root>
```

**特征：**
- 可读性强
- 有明显分隔符（{}, <>, 引号）
- 相关字符串解析/拼接代码
- 效率较低但灵活

**检测策略：**
1. 看是否大量用 sprintf/snprintf 拼文本
2. 是否有 JSON/XML 库
3. 是否有 memcpy 序列打包
4. 是否出现字节序转换（htonl/ntohl 类）

### 连接管理（Connection Management）

**建连流程：**
```
Create socket
→ Connect to server
→ Send handshake/authentication
→ Receive acknowledgment
→ Enter main communication loop
```

**连接池：**
```
maintain pool of N connections
when request arrives:
  if free_connection available:
    use it
  else:
    create new connection (up to max)
after request:
  return connection to pool
```

**重连模式：**
```
max_retries = 5;
while (retries < max_retries) {
  if (connect_success) break;
  sleep(backoff_time);
  backoff_time *= 2;  // exponential backoff
  retries++;
}
```

**明显特征：**
- 带 sleep 的重试循环
- 连接状态检查
- 超时处理
- fallback 服务器列表

---

## 行为模式（Behavioral Patterns）

### 加密 + 网络（数据外传 / 上报）

**模式序列：**
```
1. Collect files/data
2. Compress (optional)
3. Encrypt
4. Send over network
5. Clean up local copies
```

**要看的点：**
- 文件枚举 → 加密函数 → 网络发送
- 临时文件创建 → 处理 → 删除
- 跟踪加密函数与网络函数的交叉引用

### 解密 + 执行（Payload 加载）

**模式序列：**
```
1. Read encrypted payload from resource/file/network
2. Decrypt in memory
3. Execute (direct call, injection, or create process)
```

**要看的点：**
- 分配带执行权限的内存
- 解密函数 → 强转函数指针 → 间接调用
- XOR 循环 → memcpy → 跳转执行

### 基于时间的触发（Time-Based Triggering）

**模式：**
```
while (true) {
  current_time = get_time();
  if (current_time >= trigger_time) {
    execute_payload();
    break;
  }
  sleep(check_interval);
}
```

**要看的点：**
- 时间/日期 API
- 与具体日期比较
- 循环里的 sleep/delay
- 基于时间逻辑的激活条件

### 多态行为（Polymorphic Behavior）

**模式：**
```
code_variant = select_variant(seed);
decrypt_code(code_variant);
execute_decrypted_code();
re-encrypt_code(new_seed);
```

**要看的点：**
- 自修改代码
- 多个代码变体
- 执行前解密
- 执行后再加密
- 改内存权限（RWX 切换）

---

## 代码质量指示器（Code Quality Indicators）

### 手写 vs 生成代码（Hand-Written vs. Generated Code）

**手写特征：**
- 格式不一致
- 可能有注释（未 strip 时）
- 若有符号，变量名更语义化
- 更符合语言习惯（idiomatic）
- 错误处理与逻辑混在一起

**生成/编译特征：**
- 结构非常一致
- 编译器优化痕迹明显
- 若 strip，变量名很系统化（local_XX）
- 错误处理更统一
- 更容易识别出库代码模式

### 混淆代码指示器（Obfuscated Code Indicators）

**刻意混淆：**
- 无意义变量/函数名
- 无必要复杂度
- 死分支
- 不透明谓词（永真/永假）
- 通过指针操作做间接调用
- 字符串混淆

**正常优化（良性）：**
- 循环展开
- 内联
- 常量折叠
- 死代码消除
- 寄存器分配导致的复杂形式

**区分点：** 混淆制造“无收益的复杂度”；优化制造“为性能服务的复杂度”。

### 库代码 vs 自定义代码（Library Code vs. Custom Code）

**库代码：**
- 标准算法（qsort、hash）
- 与开源实现相似
- 结构清晰、参数化
- 与周边业务逻辑耦合少

**自定义代码：**
- 独特模式
- 与应用逻辑强耦合
- 应用特定的数据结构
- 更可能存在 bug/利用点

**调查优先级：** 优先看自定义代码——“题眼/行为”通常在这里。

---

## 如何使用本参考（Using This Reference）

### 模式匹配工作流

1. **观察结构**：出现了哪些循环/分支/数据结构？
2. **对照模式**：是否匹配已知算法/行为模式？
3. **证据验证**：查典型常量、关键操作、结构特征
4. **记录模式**：用书签标注模式名，便于回查
5. **改进代码**：按识别到的模式重命名（如 `aes_encrypt`、`rc4_keystream`）

### 示例调查（Example Investigation）

```
Observation: Function with nested loops, array lookups, XOR operations

Compare: Matches "Block Cipher" or "Stream Cipher" patterns

Verify:
  - Check for large constant array (S-box?)
  - Count outer loop iterations (rounds?)
  - Look for key schedule function

Find: 256-byte array starting 63 7c 77 7b...
      14 iterations in outer loop

Conclusion: AES-256 (14 rounds, standard S-box)

Improve:
  rename-variables: state→aes_state, table→aes_sbox
  set-function-prototype: void aes_encrypt(uint8_t* data, uint8_t* key)
  set-comment: "AES-256 encryption using standard S-box"
```

### 模式组合（Pattern Combination）

真实代码经常组合多个模式：

**示例：恶意样本 C2 通信**
```
[Command Dispatcher] receives command from network
  ↓
[State Machine] tracks connection state
  ↓
[Callback Functions] handle specific commands
  ↓
[Buffer Management] manages received data
  ↓
[Encryption] protects command payloads
```

识别出一个模式后，继续在以下位置找相关模式：
- 调用它的函数（更上层的编排/流程）
- 它调用的函数（更底层的原语）
- 对共享数据结构的交叉引用

### 渐进式理解（Progressive Understanding）

不需要一上来就把所有模式都识别到位：

**第一遍**："像是 crypto（大量 XOR 和循环）"
**第二遍**："更像流密码（状态简单，没有大表）"
**第三遍**："符合 RC4（256 初始化 + swap）"
**第四遍**："确认 RC4（KSA 与 PRGA 都找到了）"

每一遍都在收敛理解并指导下一步调查。