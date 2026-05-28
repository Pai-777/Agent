# 密码学模式识别参考

本文档提供用于在编译后的二进制中识别与分析密码学实现的模式识别指南。这些模式是通用的，适用于不同算法——重点关注**概念特征**，而非某个特定实现细节。

## 通用密码学识别

### 密码学存在性指示器

**高置度指示器：**

- 密码相关字符串："encrypt"、"decrypt"、"cipher"、"AES"、"RSA"、"key"、"hash"
- 密码库导入：CryptEncrypt、OpenSSL 函数、libcrypto
- 大型常量数组（256+ 字节），数据看起来随机
- 大量使用 XOR 运算
- 位旋转模式：`(x << n) | (x >> (32-n))`
- 固定迭代次数（轮数）：8、10、12、14、16、32、64、80
- 大整数上的模运算

**中等置信度指示器：**
- 嵌套循环配合数组操作
- 字节级数组索引模式
- 类 S-box 查表：`output = table[input]`
- 固定大小分组的状态变换

**检查要点：**
```
search-strings-regex pattern="(encrypt|decrypt|crypto|cipher|AES|DES|RSA|RC4|key|hash|salt|iv)"
get-symbols includeExternal=true → Look for crypto API imports
search-decompilation pattern="(xor|sbox|round|permut)"
```

## 分组密码模式（Block Cipher）

### 概念特征

**核心概念**：将固定大小的数据块通过多轮的代换与置换进行变换。

**关键识别特征：**
1. **固定分组大小**：按块处理数据（64 位、128 位等）
2. **轮结构**：外层循环具有固定迭代次数
3. **代换**：表查找（S-box）替换输入字节
4. **置换**：比特洗牌、旋转、混合操作
5. **密钥扩展（key schedule）**：从主密钥派生每轮子密钥的函数

**通用代码结构：**
```c
// Simplified conceptual pattern
void block_cipher_encrypt(uint8_t* data, uint8_t* key) {
    uint8_t round_keys[NUM_ROUNDS][KEY_SIZE];
    generate_round_keys(key, round_keys);

    for (int round = 0; round < NUM_ROUNDS; round++) {
        substitute_bytes(data);      // S-box lookups
        permute_bits(data);          // Bit shuffling
        mix_columns(data);           // Linear transformation
        add_round_key(data, round_keys[round]);  // XOR with round key
    }
}
```

### 代换-置换网络（SPN）

**是什么**：多数现代分组密码（AES、PRESENT 等）采用的结构。

**识别模式：**
```
Loop structure:
  for round in 0..NUM_ROUNDS:
    1. SubBytes (S-box lookup)
    2. ShiftRows/PermuteBits (positional change)
    3. MixColumns (linear transformation)
    4. AddRoundKey (XOR with round key)

Characteristics:
  - Large constant arrays (S-boxes, typically 256 bytes)
  - Heavy XOR usage
  - Byte/word array indexing
  - State array (16+ bytes)
```

**AES 特征签名：**
- S-box 起始：0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5...
- 轮数：10（AES-128）、12（AES-192）、14（AES-256）
- 128-bit 状态（16 字节，常表示为 4x4 矩阵）
- 用于密钥扩展的 Rcon（轮常量）数组

**DES 特征签名：**
- 64-bit 分组（8 字节）
- 16 轮
- 置换表（IP、FP）
- S-box 数组（8 个盒子，每个 64 项）
- Feistel 结构（见下文）

### Feistel 网络

**是什么**：较早的分组密码设计（DES、Blowfish、TEA）。

**识别模式：**
```
Loop structure:
  Split data into left and right halves
  for round in 0..NUM_ROUNDS:
    temp = right
    right = left XOR F(right, round_key[round])
    left = temp
  Swap and combine halves

Characteristics:
  - Data split in half
  - Swap operation each round
  - F-function (round function) operating on half the data
  - Other half XORed with F-function output
```

**典型代码模式：**
```c
// Feistel structure
uint32_t left = data[0];
uint32_t right = data[1];

for (int i = 0; i < rounds; i++) {
    uint32_t temp = right;
    right = left ^ f_function(right, key[i]);
    left = temp;
}
```

### 分组密码排查策略

1. **数轮数**：外层循环迭代次数 → 提示密码类型与密钥长度
2. **测分组大小**：每次迭代处理多少数据 → 64-bit（DES）或 128-bit（AES）
3. **定位 S-box**：大型常量数组 → 用 `read-memory` 读取并对比已知 S-box
4. **检查密钥扩展**：寻找从主密钥派生多轮子密钥的函数
5. **识别结构**：SPN（并行变换） vs Feistel（左右交换模式）

**常用工具：**
```
get-decompilation limit=50 includeIncomingReferences=true
read-memory at constant array addresses
rename-variables: var_1 → sbox, var_2 → state, var_3 → round_key
```

## 流密码模式（Stream Cipher）

### 概念特征

**核心概念**：从密钥生成伪随机密钥流（keystream），再与明文做 XOR。

**关键识别特征：**
1. **基于状态的生成**：内部状态不断演化以产生密钥流字节
2. **组合方式简单**：`ciphertext = plaintext XOR keystream`
3. **无固定分组**：可加密任意长度
4. **代码通常更短**：比分组密码更简单（一般不需要大 S-box）
5. **初始化阶段**：从密钥初始化状态（KSA - Key Scheduling Algorithm）

**通用代码结构：**
```c
// Simplified conceptual pattern
void stream_cipher(uint8_t* data, size_t len, uint8_t* key) {
    uint8_t state[STATE_SIZE];
    initialize_state(state, key);  // KSA

    for (size_t i = 0; i < len; i++) {
        uint8_t keystream_byte = generate_next_byte(state);  // PRGA
        data[i] ^= keystream_byte;
    }
}
```

### RC4 模式（在国内外 CTF 都很常见）

**识别模式：**
```
Initialization (KSA):
  state = [0, 1, 2, ..., 255]  // 256-byte array
  j = 0
  for i in 0..255:
    j = (j + state[i] + key[i % key_len]) % 256
    swap(state[i], state[j])

Keystream generation (PRGA):
  i = 0; j = 0
  for each byte:
    i = (i + 1) % 256
    j = (j + state[i]) % 256
    swap(state[i], state[j])
    keystream_byte = state[(state[i] + state[j]) % 256]
    output ^= keystream_byte
```

**明显特征：**
- 256 字节状态数组
- swap 操作：`temp = a[i]; a[i] = a[j]; a[j] = temp`
- 模 256（`% 256` 或 `& 0xFF`）
- 索引由累加变量驱动
- 两阶段结构（初始化 + 生成）

### ChaCha/Salsa 模式

**识别模式：**
- 512-bit 状态（16 个 32-bit word）
- Quarter-round 函数（ARX：加法-旋转-XOR）
- 魔术常量："expand 32-byte k" 或 "expand 16-byte k"
- ChaCha20 为 20 轮（10 次 double-round）
- 大量 32-bit 旋转

### 流密码排查策略

1. **找状态初始化**：寻找从 key 初始化数组/状态的逻辑
2. **识别更新函数**：状态如何演化（swap、ARX、LCG 等）
3. **定位 XOR**：典型的 `output = input ^ keystream`
4. **检查复用**：是否重复使用同一密钥流？（常见弱点）
5. **分析状态大小**：256 字节（RC4）、64 字节（ChaCha）、可变（自研）

**常用工具：**
```
search-decompilation pattern="swap|xor"
get-decompilation to see state evolution loop
rename-variables: var_1 → state, var_2 → keystream, var_3 → index
```

## 公钥密码模式（Public Key Cryptography）

### 概念特征

**核心概念**：基于数学陷门函数的非对称加密。

**关键识别特征：**
1. **大整数运算**：数值通常达到数百/数千 bit
2. **模幂运算**：`result = base^exponent mod modulus`
3. **速度很慢**：比对称密码慢几个数量级
4. **多精度运算**：用数组表示大整数

**通用代码结构：**
```c
// Simplified modular exponentiation (square-and-multiply)
bigint modexp(bigint base, bigint exponent, bigint modulus) {
    bigint result = 1;
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;  // Multiply
        }
        base = (base * base) % modulus;  // Square
        exponent >>= 1;
    }
    return result;
}
```

### RSA 模式

**识别模式：**

```
Key components:
  - Large modulus N (1024, 2048, 4096+ bits)
  - Public exponent e (often 65537 = 0x10001)
  - Private exponent d

Encryption: c = m^e mod N
Decryption: m = c^d mod N

Operations:
  - Modular exponentiation (square-and-multiply)
  - Multi-precision multiplication
  - Barrett or Montgomery reduction for modulo
```

**明显特征：**
- 很大的缓冲区（128、256、512 字节以上）
- 常量 0x10001（常见 RSA 公钥指数）
- 逐 bit 处理 exponent
- 执行很慢（迭代次数多）
- 用于数组加/减/乘的函数

### 椭圆曲线（ECC）模式

**识别模式：**
- 点加/倍点运算
- 仿射或射影坐标（x, y）或（x, y, z）
- 有限域运算（素域上的模运算）
- 曲线参数（a, b, p, G, n）
- 标量乘（点加自己 k 次）

### 公钥排查策略

1. **识别大整数运算**：查找基于数组的算术逻辑
2. **定位幂运算模式**：square-and-multiply 循环
3. **提取参数**：从常量中找 modulus、exponent
4. **判断密钥位数**：缓冲区大小提示安全级别
5. **寻找弱参数**：小指数、可分解 modulus（国内 CTF 常见套路）

**CTF 常见弱点：**
- 小 modulus（可直接分解）
- 小私钥指数（Wiener 攻击）
- 多把密钥复用素数
- 教科书 RSA（无填充，易被利用）

## 哈希函数模式（Hash Function）

### 概念特征

**核心概念**：将任意长度数据单向压缩为固定长度摘要。

**关键识别特征：**
1. **初始化常量**：算法特有的固定魔术数
2. **按块处理**：输入按固定大小分组（常见 512 bit）
3. **状态累积**：运行状态随每个块更新
4. **填充（padding）**：追加比特使长度满足块对齐
5. **强混合**：大量位运算（不可逆）

**通用代码结构：**
```c
// Simplified hash structure
void hash(uint8_t* data, size_t len, uint8_t* digest) {
    uint32_t state[STATE_SIZE];
    initialize_state(state);  // Magic constants

    // Process each block
    for (each block in data) {
        process_block(state, block);  // Compression function
    }

    finalize(state, digest);  // Output transformation
}
```

### MD5/SHA 识别

**MD5 初始化常量：**
```c
state[0] = 0x67452301;
state[1] = 0xefcdab89;
state[2] = 0x98badcfe;
state[3] = 0x10325476;
```

**SHA-1 初始化常量：**
```c
state[0] = 0x67452301;
state[1] = 0xefcdab89;
state[2] = 0x98badcfe;
state[3] = 0x10325476;
state[4] = 0xc3d2e1f0;
```

**SHA-256 初始化常量：**
```c
// First 32 bits of fractional parts of square roots of first 8 primes
state[0] = 0x6a09e667;
state[1] = 0xbb67ae85;
state[2] = 0x3c6ef372;
// ... 5 more
```

**明显特征：**
- 典型初始化常量（优先搜这些！）
- 固定轮数：64（MD5、SHA-256）、80（SHA-1、SHA-512）
- 位旋转：`(x << n) | (x >> (32-n))`
- 消息扩展（W 数组）
- 混合函数（MD5 的 F/G/H 等）

### 哈希排查策略

1. **搜魔术常量**：哈希的初始向量很有辨识度
2. **数轮数**：64 或 80 次迭代 → 对应具体哈希
3. **看分组大小**：512 bit（MD5、SHA-1、SHA-256）或 1024 bit（SHA-512）
4. **识别混合运算**：AND、OR、XOR、NOT、旋转
5. **找 padding 逻辑**：追加 0x80，然后 0，再追加长度

**常用工具：**
```
search-decompilation pattern="0x67452301|0xefcdab89|0x98badcfe"
get-decompilation to see round structure
read-memory at initialization constants
```

## 简单混淆模式（Simple Obfuscation）

### XOR “加密”

**是什么**：常用于混淆（obfuscation）的低强度方案，不具备安全性。

**识别模式：**
```
Single-byte key:
  for (i = 0; i < len; i++)
    data[i] ^= 0x42;  // Fixed constant

Multi-byte key:
  for (i = 0; i < len; i++)
    data[i] ^= key[i % keylen];  // Repeating key

Rolling key (LCG-based):
  key = seed;
  for (i = 0; i < len; i++) {
    data[i] ^= key;
    key = (key * A + C) % M;  // Linear congruential generator
  }
```

**明显特征：**
- 函数很短（5-10 行）
- XOR 常量或简单模式
- 常用于字符串/配置数据
- 没有复杂状态与多轮结构

**破解思路：**
- 单字节：暴力（256 种）
- 多字节：频率分析或已知明文
- 滚动 key：若 LCG 参数可得，可复现序列

### 代换密码（Substitution Cipher）

**识别模式：**
```
Simple substitution:
  for (i = 0; i < len; i++)
    output[i] = substitution_table[input[i]];

Caesar cipher (special case):
  for (i = 0; i < len; i++)
    output[i] = (input[i] + shift) % 256;
```

**破解思路：**
- 频率分析（密文足够长时）
- 已知明文攻击
- 暴力枚举代换表（难度取决于约束）

### 自定义密码（Custom Cipher）模式

**是什么**：题目特制的加密方案，不是标准算法。

**识别指示器：**
- 与已知密码模式不匹配
- 运算/数据流很“怪”
- 以非标准方式混合加法、XOR、位移
- 通常比真实密码更简单（便于解题）

**排查策略：**
1. **记录操作**：对数据做了哪些变换、顺序是什么？
2. **判断可逆性**：这些操作能否逐步逆回去？
3. **寻找弱点**：
   - 密钥空间过小（可爆破）
   - 线性运算占比高（可用代数解）
   - 重复结构明显（可利用）
4. **已知明文**：若有明密文对，从输出倒推
5. **用 Python 复现**：先复刻加密，再构造逆过程

**国内 CTF 常见自定义密码弱点：**
- 混合不足（可部分恢复明文）
- 弱密钥派生（可预测）
- 操作可逆（按逆操作直接解密）
- 状态空间小（可爆破）

## 识别工作流（Workflow）

### 第 1 步：初始检测
```
1. Search for crypto strings
   search-strings-regex pattern="(encrypt|decrypt|aes|rsa|md5|sha|key)"

2. Check for crypto API imports
   get-symbols includeExternal=true → Look for OpenSSL, Windows Crypto API

3. Search for crypto patterns in code
   search-decompilation pattern="(xor|sbox|round)"
```

### 第 2 步：模式匹配
```
4. Get decompilation of suspected function
   get-decompilation includeIncomingReferences=true

5. Compare to pattern categories:
   - Block cipher? (rounds, S-boxes, fixed blocks)
   - Stream cipher? (state, swap, XOR)
   - Hash? (magic constants, compression)
   - Public key? (big integers, modexp)
   - Simple obfuscation? (short, simple XOR)
```

### 第 3 步：深入分析
```
6. Read constant arrays
   read-memory at suspected S-box/constant locations

7. Compare to known values
   - AES S-box: 63 7c 77 7b...
   - MD5 init: 67452301 efcdab89...
   - RSA exponent: 0x10001

8. Count iterations
   - 10/12/14 rounds → AES
   - 16 rounds → DES
   - 64/80 rounds → Hash function
```

### 第 4 步：验证
```
9. Rename variables for clarity
   rename-variables: var_1 → sbox, var_2 → key, var_3 → state

10. Document findings
    set-bookmark type="Analysis" category="Crypto"
    set-decompilation-comment line=N "AES encryption round"

11. Cross-check with usage
    find-cross-references → See where crypto is called, what data it processes
```

## CTF 专项模式

### 密钥管理反模式

**硬编码密钥（最常见）：**

```c
uint8_t key[] = {0x41, 0x42, 0x43, ...};  // Key in .data section
encrypt(data, key);
```
**定位方法**：在 key 数组地址处 `read-memory`

**弱派生：**
```c
// Time-based (predictable)
srand(time(NULL));
for (i = 0; i < keylen; i++)
    key[i] = rand() % 256;

// Constant seed (always same key)
srand(12345);
...
```
**定位方法**：分析 RNG 初始化，预测或复现

**用户输入作为 key（可爆破）：**
```c
scanf("%s", key);  // Short password
if (strlen(key) < 8) ...
```
**定位方法**：keyspace 小，适合爆破

### 可利用的实现 Bug

**ECB 模式（块模式可见）：**
```c
for (i = 0; i < len; i += BLOCK_SIZE)
    encrypt_block(data + i, key);  // No chaining
```
**弱点**：相同明文块 → 相同密文块

**IV 复用或全 0 IV：**
```c
uint8_t iv[16] = {0};  // Should be random!
```
**弱点**：破坏 CBC 安全性，易被攻击

**减轮（弱变种）：**
```c
#define ROUNDS 4  // Should be 10+ for AES
```
**弱点**：可能可被现成工具/差分思路打穿

**调试后门：**
```c
if (strcmp(password, "DEBUG") == 0)
    return decrypt_without_key(data);
```
**定位方法**：搜调试字符串、测试/admin 后门逻辑

## 如何使用本参考

### 快速查阅流程

1. **先确定大类**：分组/流/哈希/公钥/简单混淆
2. **匹配具体模式**：将代码结构与示例对照
3. **用证据验证**：常量、轮数、操作类型
4. **在 Ghidra 里记录**：重命名、重类型、注释
5. **寻找弱点**：优先找 CTF 常见反模式

### 示例排查流程

```
Observation: Function with loop, array access, XOR

1. Compare to patterns:
   - Block cipher? (Check for S-boxes, rounds)
   - Stream cipher? (Check for swap, state evolution)
   - Simple XOR? (Check function length)

2. Verify:
   - Read memory at constant array (if exists)
   - Count loop iterations
   - Check for characteristic operations

3. Identify:
   - Found 256-byte array with specific pattern
   - Swap operations in initialization
   - Simple XOR in second phase

4. Conclude: RC4 stream cipher

5. Improve:
   rename-variables: state, keystream, plaintext
   set-comment: "RC4 encryption with hardcoded key"

6. Exploit:
   Extract key from initialization
   Replicate RC4 in Python to decrypt
```

### 渐进式收敛（Progressive Refinement）

**第一遍**："看起来像密码（XOR、循环、常量）"  
**第二遍**："更像分组密码（轮结构、S-box 模式）"  
**第三遍**："匹配 AES（S-box 特征、10/12/14 轮）"  
**第四遍**："AES-128，key 硬编码在 0x405000"  
**第五遍**："提取 key，成功解出 flag"

每一遍都在缩小范围，推动下一步动作。

## 记住

- **模式是指南**，不是死规则——CTF 题可能会有变体
- **常量是最强证据**——魔术数能唯一标识算法
- **结构暴露意图**——循环/数据流形态能提示算法类型
- **CTF 密码题更多是实现问题**——优先找弱点，而非“硬破算法”
- **边分析边记录**——重命名变量能显著提升理解速度
- **用证据说话**——不要猜，去对常量、数轮数、看操作

结合 SKILL.md 的概念框架一起使用本参考，可以更系统地识别与分析二进制中的密码实现。