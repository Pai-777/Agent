# CTF 逆向模式识别

本文档提供常见 CTF 逆向题的模式识别指南。重点在于**快速识别模式**，以便选择正确的解题策略。

## 密码学模式

### 简单 XOR 模式

**识别特征：**
```
Single-byte XOR:
  for (i = 0; i < len; i++)
    output[i] = input[i] ^ 0xKEY;

Multi-byte XOR (repeating key):
  for (i = 0; i < len; i++)
    output[i] = input[i] ^ key[i % keylen];

Rolling XOR:
  xor_val = seed;
  for (i = 0; i < len; i++) {
    output[i] = input[i] ^ xor_val;
    xor_val = next_value(xor_val);  // Linear congruential or similar
  }
```

**在代码里要看的点：**
- 函数很短（反编译后大约 5-15 行）
- 循环中出现 XOR
- 常量 XOR 或小数组作为 key
- 用取模控制 key 下标（`i % keylen`）

**ReVa 侧的定位方式：**
```
search-decompilation pattern="\\^" caseSensitive=false
→ Find XOR operations

get-decompilation of suspicious function
→ Look for loop with XOR

read-memory at key location
→ Extract XOR key
```

**解题思路：**
- XOR 可逆且自反：`decrypt(x) = encrypt(x)`
- 若有密文 + key：明文 = 密文 XOR key
- 若有明文 + 密文：key = 明文 XOR 密文
- 若有部分已知明文：先推 key，再解剩余部分

### Base64 及变种

**识别特征：**
```
Character lookup table (64-character alphabet):
  Standard: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
  Custom: May use different alphabet

Bit manipulation:
  3 bytes → 4 encoded characters
  Shifting and masking: (data >> 18) & 0x3F

Padding:
  '=' characters or custom padding
```

**在代码里要看的点：**
- 64 字符串常量（查表 alphabet）
- 位移：`>> 6`、`>> 12`、`>> 18`
- 掩码：`& 0x3F`（6 bit）
- 3→4 或 4→3 的字节转换比例
- padding 逻辑（`=` 或自定义填充）

**ReVa 侧的定位方式：**
```
search-strings-regex pattern="[A-Za-z0-9+/]{64}"
→ Find base64 alphabet

search-decompilation pattern="& 0x3f"
→ Find 6-bit masking (base64 characteristic)

get-decompilation of encoding function
→ Confirm 3→4 byte transformation
```

**解题思路：**

- 标准 base64：直接用标准解码器
- 自定义 alphabet：先把自定义映射回标准 alphabet，再解码
- 若要逆向实现：识别 alphabet，自己实现 decoder

### 分组密码模式（AES、DES 等）

**识别特征：**
```
AES characteristics:
  - 128-bit (16-byte) blocks
  - 10, 12, or 14 rounds (for 128, 192, 256-bit keys)
  - S-box: 256-byte constant array starting 63 7c 77 7b f2 6b 6f c5...
  - Mix columns, shift rows operations
  - Key schedule expansion

DES characteristics:
  - 64-bit (8-byte) blocks
  - 16 rounds
  - Permutation tables (IP, FP, E, P, S-boxes)
  - Feistel structure (split, swap, repeat)
```

**在代码里要看的点：**
```
Nested loops:
  for (round = 0; round < NUM_ROUNDS; round++)
    for (i = 0; i < BLOCK_SIZE; i++)
      state[i] = transform(state[i], key[round]);

Large constant arrays:
  uint8_t sbox[256] = {0x63, 0x7c, 0x77, ...};

Block processing:
  Fixed-size chunks (16 bytes for AES, 8 for DES)

Key schedule:
  Function deriving round keys from master key
```

**ReVa 侧的定位方式：**
```
search-decompilation pattern="(for.*round|for.*0x10)"
→ Find round loops

read-memory at constant arrays
→ Compare first bytes to known S-boxes:
   AES: 63 7c 77 7b f2 6b 6f c5
   DES S1: 0e 04 0d 01 02 0f 0b 08

get-decompilation with focus on nested loops
→ Count iterations (round count indicates key size)
```

**解题思路：**

- 通过 S-box 或特征常量识别算法
- 从内存或 key schedule 中提取 key
- 用标准库/标准实现做解密
- 若是魔改实现：在 Python/C 中复刻算法再逆回去

### 流密码模式（RC4 等）

**识别特征：**
```
RC4 characteristics:
  KSA (Key Scheduling Algorithm):
    for i = 0 to 255: S[i] = i
    for i = 0 to 255: swap S[i] with S[(S[i] + key[i % keylen]) % 256]

  PRGA (Pseudo-Random Generation Algorithm):
    i = 0, j = 0
    while generating:
      i = (i + 1) % 256
      j = (j + S[i]) % 256
      swap(S[i], S[j])
      output = S[(S[i] + S[j]) % 256]
```

**在代码里要看的点：**
```
State array initialization:
  for (i = 0; i < 256; i++) state[i] = i;

Swap operations:
  temp = arr[i];
  arr[i] = arr[j];
  arr[j] = temp;

Modulo arithmetic:
  (i + 1) % 256
  index & 0xFF  (equivalent to % 256)

Simple XOR with keystream:
  output[i] = input[i] ^ keystream[i];
```

**ReVa 侧的定位方式：**
```
search-decompilation pattern="(swap|temp.*=.*\\[)"
→ Find array swap operations

get-decompilation of initialization
→ Look for 0-255 loop filling array

find-cross-references to state array
→ Trace usage through KSA and PRGA
```

**解题思路：**

- 从初始化逻辑里提取 key
- 复刻 KSA 得到初始状态
- 复刻 PRGA 生成 keystream
- 密文 XOR keystream 还原明文

### 哈希函数模式（Hash Function）

**识别特征：**
```
MD5/SHA characteristics:
  - Fixed initialization vectors (magic constants)
  - Block processing (512 bits / 64 bytes)
  - Multiple rounds (64 for MD5/SHA-256, 80 for SHA-1)
  - Bitwise operations: rotations, XOR, AND, OR, NOT
  - Padding: append 0x80, then zeros, then length

Magic constants:
  MD5: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  SHA-1: adds 0xc3d2e1f0
  SHA-256: Eight 32-bit constants derived from square roots
```

**在代码里要看的点：**
```
Characteristic constants:
  Search for 0x67452301 (MD5/SHA-1 IV)

Fixed round counts:
  for (round = 0; round < 64; round++)  // MD5, SHA-256
  for (round = 0; round < 80; round++)  // SHA-1

Bitwise rotation macros:
  ROTL(x, n) = (x << n) | (x >> (32-n))

Message schedule (W array):
  Expands 16 input words to 64/80 words

Padding logic:
  Append 0x80, zeros, then 64-bit length
```

**ReVa 侧的定位方式：**
```
search-decompilation pattern="0x67452301"
→ Find MD5/SHA initialization

read-memory at round constants
→ Identify specific hash variant

get-decompilation of hash function
→ Count rounds, identify structure
```

**解题思路：**

- 哈希不可逆（不“解密”）
- 若只有 flag 的 hash：通常要爆破/字典/结合其他线索
- 若是 compare：提取期望 hash，再尝试常见 flag 结构
- 注意弱哈希（MD5、SHA1）或输入很短（可爆破）

## 编码模式（Encoding Patterns）

### 字符代换（Character Substitution）

**识别特征：**
```
Lookup table mapping:
  output[i] = table[input[i]];

Caesar cipher (shift):
  output[i] = (input[i] - 'A' + shift) % 26 + 'A';

Custom alphabet:
  const char* alphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba";
  output[i] = alphabet[input[i] - 'A'];
```

**在代码里要看的点：**
- 字符数组常量（alphabet/代换表）
- 按字符处理的循环
- 范围判断：`if (c >= 'A' && c <= 'Z')`
- 字符码运算：`c - 'A'`、`c + shift`

**ReVa 侧的定位方式：**
```
search-strings-regex pattern="[A-Z]{26}"
→ Find alphabet strings

search-decompilation pattern="(- 'A'|% 26)"
→ Find character arithmetic

get-decompilation of encoding function
→ Identify substitution pattern
```

**解题思路：**
- 提取代换表或 shift
- 构造逆映射（反查表）
- 对编码结果做逆变换

### 二进制到文本编码（Binary-to-Text Encodings）

**识别特征：**
```
Hex encoding:
  "0123456789abcdef"
  nibble_high = (byte >> 4) & 0xF;
  nibble_low = byte & 0xF;

Binary/ASCII:
  Converting to "01011010" strings

Custom encodings:
  Mapping bytes to multi-character sequences
```

**在代码里要看的点：**
- 十六进制字符表字符串
- 位提取：`>> 4`、`& 0xF`、`& 1`
- 生成字符码的循环
- 1→2 或 1→8 的膨胀比例

**ReVa 侧的定位方式：**
```
search-decompilation pattern="(>> 4|& 0xf)"
→ Find nibble extraction (hex encoding)

get-strings to find encoding alphabets
→ Check for hex, binary digit strings
```

**解题思路：**

- 识别编码方案
- 实现 decoder
- 解出编码的 flag

## 输入校验模式（Input Validation Patterns）

### 逐字符比较（Character-by-Character Comparison）

**识别特征：**
```
Direct comparison:
  for (i = 0; i < len; i++)
    if (input[i] != expected[i])
      return 0;
  return 1;

Comparison with transformation:
  for (i = 0; i < len; i++)
    if (transform(input[i]) != expected[i])
      return 0;
```

**在代码里要看的点：**
- 按输入长度循环
- 循环内比较：`!=`、`==`
- 不匹配直接 return（早退）
- 全部比完才成功

**ReVa 侧的定位方式：**
```
search-decompilation pattern="(if.*!=|if.*==)"
→ Find comparison operations

get-decompilation of validation function
→ Identify loop structure

read-memory at expected value array
→ Extract expected bytes
```

**解题思路：**
- 直接比较：把 expected 数组读出来，往往就是 flag/密码
- 带变换比较：逆变换即可
- 变换复杂：逐字符跟踪每一步

### 校验和校验（Checksum Validation）

**识别特征：**
```
Sum check:
  sum = 0;
  for (i = 0; i < len; i++)
    sum += input[i];
  return (sum == EXPECTED_SUM);

XOR check:
  xor = 0;
  for (i = 0; i < len; i++)
    xor ^= input[i];
  return (xor == EXPECTED_XOR);

Custom accumulation:
  result = SEED;
  for (i = 0; i < len; i++)
    result = (result * MULT + input[i]) % MOD;
  return (result == EXPECTED);
```

**在代码里要看的点：**
- 累加器变量（sum/product/xor/result）
- 循环里更新累加器
- 末尾与常量比较
- 可能和其他校验组合出现

**ReVa 侧的定位方式：**
```
search-decompilation pattern="(\\+=|\\*=|\\^=)"
→ Find accumulator updates

get-decompilation of validation
→ Identify accumulation pattern

read-memory at expected value
→ Extract target checksum
```

**解题思路：**
- 单一 checksum：约束太弱（解不唯一）
- 多个 checksum：可能约束到唯一输入
- 把所有约束提出来，当方程组/约束系统来解

### 约束型校验（Constraint-Based Validation）

**识别特征：**
```
Multiple independent checks:
  if (input[0] + input[1] != 0x64) return 0;
  if (input[0] - input[1] != 0x14) return 0;
  if (input[2] ^ 0x42 != 0x33) return 0;
  if (input[3] * 2 == input[4]) return 0;
  return 1;

Relational constraints:
  if (input[i] != input[j] + 5) return 0;
```

**在代码里要看的点：**
- 多条 if 比较语句
- 对 input 下标做算术运算
- 不同位置之间的关系约束
- 比较中的常量

**ReVa 侧的定位方式：**
```
get-decompilation of validation function
→ Identify all comparison statements

set-decompilation-comment on each constraint
→ Document relationships

Extract to external solver:
→ List all constraints, solve with z3 or similar
```

**解题思路：**
- 提取所有约束
- 建模为方程/约束系统
- 用 z3/SMT 求解
- 回填到程序里验证

## 算法模式

### 数学序列（Mathematical Sequences）

**识别特征：**
```
Fibonacci:
  a = 0, b = 1;
  while (...) {
    next = a + b;
    a = b;
    b = next;
  }

Factorial:
  result = 1;
  for (i = 1; i <= n; i++)
    result *= i;

Prime checking:
  for (i = 2; i < sqrt(n); i++)
    if (n % i == 0) return 0;
  return 1;
```

**在代码里要看的点：**
- 迭代或递归结构
- 等差/等比推进
- 数论操作（取模、整除）
- 典型序列生成结构

**ReVa 侧的定位方式：**
```
search-decompilation pattern="(fibonacci|factorial|prime)"
→ Find named functions (if not stripped)

get-decompilation of suspicious function
→ Identify mathematical pattern

Recognize by structure:
→ Two-variable update (Fibonacci)
→ Multiplication accumulator (factorial)
→ Modulo divisibility (prime check)
```

**解题思路：**
- 先识别算法是什么
- 理解它如何校验输入
- 推导输入条件或直接复刻逻辑求解

### 矩阵运算（Matrix Operations）

**识别特征：**
```
Matrix multiplication:
  for (i = 0; i < rows; i++)
    for (j = 0; j < cols; j++)
      for (k = 0; k < inner; k++)
        result[i][j] += a[i][k] * b[k][j];

Linear transformations:
  output[i] = matrix[i][0] * input[0] + matrix[i][1] * input[1] + ...;
```

**在代码里要看的点：**
- 三重循环（矩阵乘）
- 2D 下标：`array[i][j]` 或 `array[i * width + j]`
- 内层循环累加器
- 输入的线性组合

**ReVa 侧的定位方式：**
```
search-decompilation pattern="\\[.*\\]\\[.*\\]"
→ Find 2D array access

get-decompilation showing nested loops
→ Count loop depth (3 = likely matrix multiply)

read-memory at matrix constants
→ Extract transformation matrix
```

**解题思路：**
- 提取矩阵
- 若为方阵且可逆：求逆矩阵
- 用逆矩阵对期望输出做逆变换得到输入

### 状态机模式（State Machine Patterns）

**识别特征：**
```
Explicit state variable:
  int state = STATE_INIT;
  while (running) {
    switch (state) {
      case STATE_INIT: /* ... */ state = STATE_READY; break;
      case STATE_READY: /* ... */ state = STATE_PROCESS; break;
      case STATE_PROCESS: /* ... */ state = STATE_DONE; break;
    }
  }

Implicit state (position in input):
  for (i = 0; i < len; i++) {
    if (/* condition based on i and input */)
      /* different processing for different positions */
  }
```

**在代码里要看的点：**
- state 变量取多个值
- 很大的 switch(state)
- 状态跳转（`state = NEW_STATE`）
- 随状态不同执行不同逻辑

**ReVa 侧的定位方式：**
```
search-decompilation pattern="(case|switch)"
→ Find switch statements

get-decompilation of state machine
→ Map state transitions

rename-variables to clarify states
→ current_state, next_state, etc.
```

**解题思路：**
- 画出状态转移图
- 找接受态（成功态）
- 构造能到达接受态的输入序列

## 混淆模式（Obfuscation Patterns）

### 控制流混淆（Control Flow Obfuscation）

**识别特征：**
```
Opaque predicates (always true/false):
  if (x * x >= 0)  // Always true
    real_code();
  else
    never_executed();

Dispatcher loops:
  while (1) {
    switch (dispatch_value) {
      case 0: /* block A */; dispatch_value = 5; break;
      case 5: /* block B */; dispatch_value = 2; break;
      case 2: /* block C */; dispatch_value = -1; break;
      case -1: return;
    }
  }
```

**在代码里要看的点：**
- 多余的条件分支
- 控制流很复杂但逻辑很简单
- dispatcher 风格执行（switch 跳转）
- 大量死分支

**ReVa 侧的定位方式：**
```
get-decompilation of obfuscated function
→ Look for unusual control flow

set-bookmark type="Warning" for suspicious patterns
→ Mark opaque predicates, dispatchers

Focus on data flow, ignore control flow complexity
→ Track input transformation regardless of jumps
```

**解题思路：**
- 不要被控制流绕晕，盯住数据流
- 结合动态调试观察真实路径
- 手动简化或用去混淆工具辅助

### 字符串混淆（String Obfuscation）

**识别特征：**
```
Stack strings (character-by-character):
  str[0] = 'f'; str[1] = 'l'; str[2] = 'a'; str[3] = 'g';

Encrypted strings (decrypted at runtime):
  decrypt_string(encrypted_data, key, output);

Computed strings:
  for (i = 0; i < len; i++)
    str[i] = base[i] ^ key;
```

**在代码里要看的点：**
- 对数组逐字符赋值
- 字符串解密函数
- 对字符数组做 XOR/算术
- 静态字符串列表里看不到明文

**ReVa 侧的定位方式：**
```
get-strings may not show obfuscated strings
→ Use decompilation to find construction

search-decompilation pattern="\\[0\\] = "
→ Find character-by-character assignments

find-cross-references to decryption functions
→ Locate where strings are revealed
```

**解题思路：**
- 定位解混淆/解密例程
- 提取密文数据与 key
- 手动解密或动态跑到解密点直接拿明文

### 反调试（CTF 场景）

**识别特征：**
```
Debugger detection:
  if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) exit(1);  // Linux
  if (IsDebuggerPresent()) exit(1);  // Windows

Timing checks:
  start = time();
  /* short operation */
  end = time();
  if (end - start > THRESHOLD) exit(1);  // Detected breakpoint delay

Self-modification:
  Decrypt code section at runtime
  Execute decrypted code
  Re-encrypt afterwards
```

**在代码里要看的点：**
- 反调试 API
- 计时检测
- 修改内存权限
- 运行时改代码（自修改/解密执行）

**ReVa 侧的定位方式：**
```
get-symbols includeExternal=true
→ Look for: ptrace, IsDebuggerPresent, time, gettimeofday

search-decompilation pattern="(ptrace|IsDebugger|time)"
→ Find anti-debug checks

find-cross-references to VirtualProtect, mprotect
→ Identify self-modifying code
```

**解题思路：**
- patch 掉反调试（把 exit/NOP 掉）
- 用反反调试手段/插件
- 在能隐藏调试器的环境里分析
- CTF 场景通常允许 patch（先过题为主）

## CTF 常见套路

### Flag 格式校验

**模式：**
```
Check prefix:
  if (strncmp(input, "flag{", 5) != 0) return 0;

Check suffix:
  if (input[len-1] != '}') return 0;

Check length:
  if (strlen(input) != EXPECTED_LEN) return 0;
```

**在代码里要看的点：**
- 与字面量 `"flag{"` 或 `"CTF{"` 比较
- 左右括号/大括号校验
- 长度校验

**ReVa 侧的定位方式：**
```
search-strings-regex pattern="(flag\\{|CTF\\{)"
→ Find flag format strings

get-decompilation of validation
→ Extract format requirements
```

**解题思路：**
- 先把格式要求记下来
- 重点解 `{}` 中间的内容
- 最后拼回完整 flag（符合格式）

### 多阶段校验（Multi-Stage Validation）

**模式：**
```
Stage 1: Check format (flag{...})
Stage 2: Check length (must be 32 characters)
Stage 3: Check checksum (sum must equal X)
Stage 4: Check encryption (encrypted content matches Y)
```

**在代码里要看的点：**
- 多个校验函数串行调用
- 失败早退
- 约束逐步叠加

**ReVa 侧的定位方式：**
```
find-cross-references to validation function
→ See if called from multi-stage validator

get-decompilation of main validator
→ Identify call sequence

Analyze each stage separately
→ Understand cumulative constraints
```

**解题思路：**
- 分阶段逐个解约束
- 最终输入必须同时满足所有阶段
- 一般从“约束最强”的阶段倒推会更快

### 隐藏成功路径（Hidden Success Path）

**模式：**
```
Obvious failure message:
  printf("Wrong!\n");

Hidden success logic:
  if (/* complex condition */)
    system("cat /flag.txt");  // No message, just action
```

**在代码里要看的点：**
- 成功行为可能不打印“Correct!”
- 读文件（cat flag/open flag.txt）
- 网络发送 flag
- 成功可能表现为“没有 Wrong”，而不是“有 Right”

**ReVa 侧的定位方式：**
```
search-strings-regex pattern="(flag|/flag|flag\\.txt)"
→ Find flag file references

find-cross-references to flag file
→ Locate success path

get-decompilation of success condition
→ Understand requirements
```

**解题思路：**
- 不要只盯着 “Correct!” 字符串
- 直接找“输出 flag 的动作”
- 查文件读写/网络 send
- 成功可能是静默的

## 如何使用这些模式（Using These Patterns）

### 模式匹配工作流（Pattern Matching Workflow）

1. **观察代码结构**
   - 循环、条件、函数调用
   - 数据类型、数组大小
   - 常量与字面量

2. **对照模式库**
   - 像密码算法吗？
   - 像编码吗？
   - 像校验逻辑吗？

3. **用具体检查去验证**
   ```
   Hypothesis: This is AES
   Check 1: read-memory at constant array → Matches AES S-box? ✓
   Check 2: Count loop iterations → 10, 12, or 14? ✓
   Check 3: Block size 16 bytes? ✓
   Conclusion: AES confirmed
   ```

4. **套用对应解法**
   - AES → 提 key 解密
   - XOR → 提 key 再 XOR
   - 约束校验 → 提约束上 z3

### 快速决策树（Quick Reference Decision Tree）

```
Does it have loops with XOR?
  → Check Simple XOR Patterns

Does it have large constant arrays?
  → Check Block Cipher or Hash Patterns

Does it have swap operations and modulo?
  → Check Stream Cipher Patterns

Does it have character-by-character comparison?
  → Check Input Validation Patterns

Does it have 64-character lookup table?
  → Check Base64 Pattern

Does it have mathematical operations (factorial, fibonacci)?
  → Check Algorithm Patterns

Is control flow overly complex?
  → Check Obfuscation Patterns
```

### 组合模式（Combining Patterns）

真实题目经常组合多种模式：

**示例：密码 + 校验**
```
Input → Format Check (flag{...}) → XOR Decode → AES Decrypt → Compare to Expected
```

**解法：**
1. 提取格式要求
2. 识别 XOR key
3. 识别 AES key
4. 提取 expected 值
5. 逆向回推：用已知 key 做 AES_decrypt，再做 XOR 还原

**示例：编码 + 约束**
```
Input → Base64 Decode → Constraint Check (sum == X, product == Y)
```

**解法：**
1. 提取 decoded 值上的约束
2. 解约束
3. 把解出的结果再 base64 编回去

## 记住（Remember）

模式是**识别捷径**，不是死规则：
- 用模式快速判断题型
- 解法要根据实现细节灵活调整
- 模式不匹配时，回到基本功从数据流/比较点入手
- 用书签/注释记录你的模式匹配证据
- 多复盘总结，形成自己的“题型库”

识别出模式，就能少走很多弯路，直接切到解题策略。