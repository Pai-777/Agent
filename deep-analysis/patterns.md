# 逆向模式参考（Reverse Engineering Patterns Reference）

本文档包含在 deep analysis 过程中需要识别的更高层模式与概念。重点关注**算法模式**、**行为模式**与**代码结构**，而不是平台相关的实现细节。

## 密码算法模式（Cryptographic Algorithm Patterns）

### 分组密码识别（Block Cipher Recognition）

**概念特征：**
- **代换-置换网络（SPN）**：多轮代换（S-box）与置换（比特洗牌）重复执行
- **Feistel 网络**：数据分成左右两半，对一半做轮函数，另一半参与 XOR，然后交换并重复
- **固定分组大小**：通常为 64 bit（DES、Blowfish）或 128 bit（AES）
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
- 大量使用 XOR
- 字节级数组索引：`array[data[i]]`

**排查策略：**
1. 对常量数组使用 `read-memory`，对比已知 S-box
2. 数外层循环迭代次数（轮数）——通常能提示算法类型/密钥位数
3. 用 `search-strings-regex` 搜算法名（AES/DES/Blowfish 等）
4. 查常量的交叉引用（xrefs），定位密码初始化/上下文设置位置

### 流密码识别（Stream Cipher Recognition）

**概念特征：**
- **生成密钥流（Keystream generation）**：从 key 生成伪随机字节流
- **组合简单**：明文 XOR 密钥流
- **状态驱动**：内部状态随生成过程不断演化
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
- 数组 swap：`temp = a[i]; a[i] = a[j]; a[j] = temp`
- 取模：`% 256` 或 `& 0xFF`
- 简单 XOR 循环
- 代码体量通常比分组密码小（一般没有大常量表）

### 公钥密码识别（Public Key Cryptography Recognition）

**概念特征：**
- **大整数运算**：数值达到数百/数千 bit
- **模幂运算**：`result = base^exponent mod modulus`
- **性能**：比对称密码慢很多（常用于密钥交换/签名，而非大数据加密）

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
- 很大的 buffer（128、256、512 字节以上）
- exponent 按 bit 处理
- 特征常量（例如 RSA 常用 e=0x10001=65537）
- 执行很慢（每字节要做大量运算）

### 哈希函数识别（Hash Function Recognition）

**概念特征：**
- **压缩函数**：固定大小输入 → 固定大小输出
- **按块处理**：典型为 512 bit（64 字节）
- **状态累积**：每个块都会更新运行状态
- **填充（Padding）**：补齐到块大小（0x80、0、长度）
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
- 典型初始化常量（IV）
- 固定 64 或 80 轮循环
- 位旋转：`(x << n) | (x >> (32-n))`
- 消息调度/扩展（W 数组扩展）

### 简单 XOR 混淆（Simple XOR Obfuscation）

**概念特征：**
- **操作极其简单**：`output = input XOR key`
- **对称**：加解密相同
- **安全性弱**：非常容易破，常用于混淆而非真正保护

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
- XOR 常量或简单 key 模式
- 常用于字符串/配置解码
- 搭配静态数据数组（需要先解码才看到明文）

---

## 控制流模式（Control Flow Patterns）

### 状态机识别（State Machine Recognition）

**概念特征：**
- **显式状态**：用枚举或整数表示当前状态
- **状态跳转**：对 state 变量做 switch/if-else
- **事件驱动**：外部输入触发状态转移

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
- 很大的 switch（case 很多）
- state 变量反复被赋新值
- 有枚举或 #define 定义的状态常量
- 典型状态名：IDLE、CONNECTING、CONNECTED、DISCONNECTED

**常见用途：**
- 网络协议处理
- Parser/解析器实现
- UI 事件处理
- 命令处理

### 命令分发器识别（Command Dispatcher Recognition）

**概念特征：**
- **命令码**：用数字 ID 标识操作
- **处理器查找**：命令 ID → handler 函数
- **可扩展**：新增命令成本低

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
- 常见命令名：exec、upload、download、shell、sleep 等

**常见用途：**
- 远控（RAT）/后门命令处理
- 插件系统
- IPC/RPC

### 回调模式识别（Callback Pattern Recognition）

**概念特征：**
- **控制反转**：库/框架调用你的函数，而不是你调用库
- **函数指针**：把 handler 的地址传入框架
- **异步**：常用于异步事件/回调驱动逻辑

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
- 参数中出现函数指针
- 函数名像 handler/callback/on_event
- 常见不透明指针参数（`void* user_data`）

### 循环模式（Loop Patterns）

**简单迭代：**
```
for (i = 0; i < count; i++)
  - Linear processing
  - Transform/encrypt each element
```

**嵌套循环（二维处理）：**
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

**环形缓冲区（Ring buffers / circular）：**
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
- 结构体中存在指针字段
- 遍历：`while (node != NULL) { node = node->next; }`
- 插入/删除逻辑

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
- 通过比较来���持有序性

### 字符串处理模式（String Handling Patterns）

**长度前缀字符串（Length-prefixed strings）：**
```
struct {
  uint32_t length;
  char data[];
}
```

**以 0 结尾字符串（Null-terminated strings）：**
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
- 无严格请求-响应配对
- 例：视频流、日志上报

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
- Message type/ID 字段
- 例：自定义 C2 协议、消息队列

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
- 固定字节序（endianness）
- 结构识别用魔数
- 版本字段用于兼容

**文本序列化：**
```
JSON: {"key": "value", "num": 42}
XML: <root><item>value</item></root>
```

**特征：**
- 人可读
- 分隔符明显（{}, <>, 引号）
- 大量字符串解析/生成逻辑
- 低效但灵活

**检测策略：**
1. 搜是否大量 sprintf/snprintf 拼文本
2. 检查是否存在 JSON/XML 解析库
3. 寻找 memcpy 连续打包的代码段
4. 识别字节序转换（htonl/ntohl 这类）

### 连接管理（Connection Management）

**建连模式：**
```
Create socket
→ Connect to server
→ Send handshake/authentication
→ Receive acknowledgment
→ Enter main communication loop
```

**连接池模式：**
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
- 带 delay 的重试循环
- 连接状态检查
- 超时处理
- 备用服务器列表（fallback）

---

## 行为模式（Behavioral Patterns）

### 加密 + 网络（数据外传 / 上报）（Encryption + Network）

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

### 解密 + 执行（Payload 加载）（Decrypt + Execute）

**模式序列：**
```
1. Read encrypted payload from resource/file/network
2. Decrypt in memory
3. Execute (direct call, injection, or create process)
```

**要看的点：**
- 分配带执行权限的 buffer
- 解密函数 → 强转函数指针 → 间接调用
- XOR 循环 → memcpy → 转移执行流

### 基于时间触发（Time-Based Triggering）

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
- 时间/日期 API 调用
- 与特定日期比较
- 循环里的 sleep/delay
- 基于时间逻辑的触发条件

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
- 改内存权限（读写/执行切换）

---

## 代码质量指示器（Code Quality Indicators）

### 手写 vs 生成代码（Hand-Written vs. Generated Code）

**手写特征：**
- 格式不一致
- 可能有注释（未 strip 时）
- 若有符号，变量名更语义化
- 更符合语言习惯（idiomatic）
- 错误处理与逻辑混杂

**生成/编译特征：**
- 结构很一致
- 编译器优化痕迹明显
- 若 strip，变量名很系统化
- 错误处理更统一
- 库代码模式更容易识别

### 混淆代码指示器（Obfuscated Code Indicators）

**刻意混淆：**
- 无意义变量/函数名
- 无必要复杂度
- 死分支
- 不透明谓词（永真/永假）
- 指针操作导致的间接调用
- 字符串混淆

**编译器优化（良性）：**
- 循环展开
- 函数内联
- 常量折叠
- 死代码消除
- 寄存器分配导致的复杂形态

**区分：** 混淆制造“无收益复杂度”；优化制造“为性能服务的复杂度”。

### 库代码 vs 自定义代码（Library Code vs. Custom Code）

**库代码：**
- 标准算法（qsort、hash）
- 与开源实现一致或相似
- 结构化、参数化
- 与周边逻辑依赖少

**自定义代码：**
- 独特的模式
- 与业务逻辑耦合
- 应用特定数据结构
- 更可能有 bug/可利用点

**调查优先级：** 优先看自定义代码——题眼/关键行为通常在这里。

---

## 如何使用本参考（Using This Reference）

### 模式匹配工作流（Pattern Matching Workflow）

1. **观察结构**：出现了哪些循环、分支、数据结构？
2. **对照模式**：是否匹配已知算法模式？
3. **证据验证**：检查典型常量、操作与结构特征
4. **记录模式**：用书签把模式名记下来，便于回查
5. **改进代码**：按识别到的模式重命名变量/函数（如 `aes_encrypt`、`rc4_keystream`）

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

识别一个模式后，可在以下位置继续找相关模式：
- 调用它的函数（更上层的编排/流程）
- 它调用的函数（更底层的原语）
- 对共享数据结构的交叉引用

### 渐进式理解（Progressive Understanding）

不需要一开始就把所有模式都识别得很完美：

**第一遍：** “像是 crypto（大量 XOR 和循环）”
**第二遍：** “可能是流密码（状态简单，没有大表）”
**第三遍：** “符合 RC4（256 初始化 + swap）”
**第四遍：** “确认 RC4（KSA 和 PRGA 都找到了）”

每一遍都会让理解更收敛，并指导后续调查方向。