# CTF 二进制利用模式

本文档整理了在 CTF 题目中识别常见漏洞类型与利用原语（exploitation primitives）的模式。重点放在**概念理解**，而不是某个具体 exp 写法。

## 漏洞识别模式

### 不安全字符串操作模式

**概念特征**：
- 调用时不检查目标缓冲区大小
- 从源到目标进行无界拷贝
- 依赖 `\0` 结尾，但不验证长度
- 没有长度参数，或长度参数被忽略

**危险 API 模式**：

```c
// Unbounded copy (no size checking)
strcpy(dest, user_input);           // Copies until null byte
strcat(dest, user_input);           // Appends until null byte
sprintf(dest, "%s", user_input);    // Formats without bounds
gets(buffer);                       // Reads unlimited from stdin

// Underspecified bounds
strncpy(dest, src, sizeof(dest));   // Doesn't guarantee null termination
scanf("%s", buffer);                // No size limit specified
read(fd, buffer, 1024);             // May exceed buffer size if buffer < 1024
recv(sock, buffer, MAX, 0);         // May exceed buffer capacity
```

**在反编译代码里要看的点**：
```
Buffer declaration:
  char buffer[64];                  // Fixed-size local array

Unsafe operation on same buffer:
  strcpy(buffer, user_input);       // No size check
  read(fd, buffer, 256);            // Reads more than buffer holds

Distance to critical data:
  buffer[64]                        // Local variable at stack offset
  saved_rbp                         // Usually at buffer + buffer_size
  return_address                    // Usually at buffer + buffer_size + 8
```

**排查策略**：
1. `get-symbols` includeExternal=true → 找 strcpy、strcat、gets、scanf、sprintf 等导入
2. `find-cross-references` 到不安全函数 → 定位调用点
3. `get-decompilation` with includeContext=true → 对比 buffer 大小与输入大小
4. 计算：input_max_size > buffer_size? → 若成立则存在栈溢出/缓冲区溢出
5. 在漏洞点 `set-bookmark` type="Warning" category="Buffer Overflow"

**明显特征**：
- 本地 `char` 数组很小（64/128/256 等）
- 对该数组调用无界字符串函数
- 用户输入直接传给危险函数
- copy/format 前没有显式 size 校验

### 格式化字符串漏洞模式（Format String）

**概念特征**：
- 用户可控 format string 参数
- 格式化符可读内存（`%x`、`%s`、`%p`）与写内存（`%n`）
- 常见栈上利用（format string 读取栈参数）
- 利用后可获得任意读/写原语

**易错模式**：

```c
// VULNERABLE: User input as format string
printf(user_input);
fprintf(fp, user_input);
sprintf(buffer, user_input);
snprintf(buffer, size, user_input);
syslog(priority, user_input);

// SAFE: Format string is literal
printf("%s", user_input);
fprintf(fp, "Input: %s\n", user_input);
sprintf(buffer, "Data: %s", user_input);
```

**在反编译代码里要看的点**：
```
Direct user input to format function:
  read(0, buffer, 256);
  printf(buffer);                    // VULNERABLE

Variable format string:
  char* fmt = get_format_string();   // Source from user
  printf(fmt, args);                 // VULNERABLE if fmt user-controlled

Missing format string:
  fprintf(stderr, error_msg);        // VULNERABLE if error_msg from user
```

**利用原语（primitives）**：

```
%x or %p     → 泄露栈上的值（地址、canary、指针等）
%s           → 任意读（如果栈上有可控指针）
%n           → 任意写（把已输出字节数写到指针指向的位置）
%N$x         → 直接访问第 N 个参数
%N$n         → 向第 N 个参数指向的地址写入

Example attack:
  printf("AAAA%10$x");   → Leak 10th stack parameter
  printf("AAAA%7$n");    → Write to pointer at 7th stack position
```

**排查策略**：
1. `search-decompilation` pattern="printf|fprintf|sprintf|snprintf|syslog"
2. 对每个命中 `get-decompilation` 且 includeContext=true
3. 检查 format string 参数：是常量字符串还是变量？
4. 若是变量，追溯来源：是否来自用户输入？
5. 在漏洞点 `set-bookmark` type="Warning" category="Format String"

**明显特征**：
- printf/fprintf 只有一个参数（没有字面量 format）
- format 存在可写 buffer 里
- 用户输入被拷贝进 format 变量
- 错误信息打印时直接使用用户可控字符串

### 缓冲区大小与操作大小不匹配模式

**概念特征**：
- buffer 按某个大小分配
- 后续操作假设了不同（更大）的大小
- off-by-one 错误
- size 计算不一致

**常见不匹配模式**：

```c
// Wrong size constant
char buffer[64];
read(fd, buffer, 128);              // Reads 128 into 64-byte buffer

// Off-by-one
char buffer[64];
for (i = 0; i <= 64; i++)           // Loop goes to 64 (65 iterations)
    buffer[i] = input[i];           // Writes one byte past end

// Null terminator forgotten
char buffer[64];
strncpy(buffer, input, 64);         // May not null-terminate
printf("%s", buffer);               // Reads past end if not terminated

// Size calculation error
char buffer[64];
memcpy(buffer, src, strlen(src));   // strlen doesn't include null byte
                                    // But may overflow if strlen(src) >= 64
```

**在反编译代码里要看的点**：
```
Size declaration:
  local_48 = buffer (char array, size 64)

Operation size:
  read(0, local_48, 0x80);          // 0x80 = 128 > 64

Offset calculation:
  local_48[iVar1] = input[iVar1];   // Check iVar1 bounds

Loop bounds:
  for (i = 0; i < size; i++)        // Is size validated?
      buffer[i] = input[i];         // Does size match buffer capacity?
```

**排查策略**：
1. `get-decompilation` → 从局部变量声明看 buffer 大小
2. 找对 buffer 的所有操作（read、memcpy、strcpy、循环写入）
3. 对比 buffer 大小与操作 size
4. `rename-variables` → buffer、buffer_size、read_size（便于阅读）
5. `set-decompilation-comment` → "Buffer overflow: reads 128 into 64-byte buffer"
6. `set-bookmark` type="Warning" category="Size Mismatch"

**明显特征**：
- read/copy 里出现的魔数与 buffer 大小不一致
- sizeof() 使用错误（sizeof(pointer) vs sizeof(array)）
- 循环边界 off-by-one（`<=` 而不是 `<`）
- 缺少 `\0` 终止校验

### 整数溢出导致内存破坏

**概念特征**：
- 整数运算在类型边界处回绕（wrap）
- size 计算溢出导致分配过小
- 分配过小导致后续写入溢出
- bounds check 下溢绕过校验

**易错模式**：

```c
// Allocation size overflow
uint32_t count = user_input;        // User controls this
uint32_t size = count * sizeof(element);  // May overflow
buffer = malloc(size);              // Allocates small buffer due to overflow
for (i = 0; i < count; i++)         // Loop uses original count
    buffer[i] = data[i];            // Heap overflow

// Bounds check underflow
size_t len = user_input;
if (len - 1 < MAX_SIZE) {           // Underflows if len == 0 (unsigned)
    memcpy(buffer, src, len);       // Large len bypasses check
}

// Sign confusion
int size = user_size;               // User controls, may be negative
if (size < MAX_SIZE) {              // Passes check if negative
    memcpy(buffer, src, size);      // Casted to size_t (huge number)
}
```

**在反编译代码里要看的点**：
```
Size calculation:
  size = user_count * 16;           // Multiplication may overflow

Wraparound check missing:
  if (user_count < 1000) {          // Doesn't check for overflow
      size = user_count * 16;
      buf = malloc(size);
  }

Unsigned underflow:
  if (len - 1 < 1024) {             // What if len == 0?

Sign conversion:
  int signed_size = user_input;     // Signed integer
  malloc(signed_size);              // Casted to size_t (unsigned)
                                    // Negative becomes huge positive
```

**排查策略**：
1. `search-decompilation` pattern="malloc|calloc|realloc"
2. 回溯 size 参数到来���
3. 检查 size 计算里是否有乘法/加法
4. `change-variable-datatypes` 修正类型（uint32_t、size_t、ssize_t）
5. 看是否有溢出校验（或缺失）
6. `set-decompilation-comment` → "Integer overflow: count * size may wrap"
7. `set-bookmark` type="Warning" category="Integer Overflow"

**明显特征**：
- 分配 size 的乘法没有溢出检查
- bounds check 用了无符号减法
- signed/unsigned 混用
- 没有校验超大的用户输入 size

### 释放后使用（Use-After-Free, UAF）模式

**概念特征**：
- 内存被 free 了，但指针仍可访问（悬空指针）
- 悬空指针被解引用（UAF）
- allocator 可能复用已释放块给新对象
- 老指针访问新对象导致类型混淆

**易错模式**：

```c
// Classic use-after-free
object* ptr = malloc(sizeof(object));
use_object(ptr);
free(ptr);
// ... later in code ...
use_object(ptr);                     // Use after free!

// Double-free (special case)
free(ptr);
free(ptr);                           // Corrupts heap metadata

// Use-after-free via aliasing
object* ptr1 = malloc(sizeof(object));
object* ptr2 = ptr1;                 // Aliased pointer
free(ptr1);
use_object(ptr2);                    // Use after free via alias
```

**在反编译代码里要看的点**：
```
Allocation and free:
  heap_ptr = malloc(0x40);
  // ... use heap_ptr ...
  free(heap_ptr);

Later usage (use-after-free):
  // ... some code ...
  *heap_ptr = value;                 // Write to freed memory
  function(heap_ptr);                // Pass freed pointer

Conditional free (double-free risk):
  if (condition1) free(ptr);
  if (condition2) free(ptr);         // May free twice if both true

No pointer nulling:
  free(ptr);
  // ptr not set to NULL, can be reused
```

**排查策略**：
1. `search-decompilation` pattern="free"
2. 对每个 free()，追踪其后是否还使用该指针
3. `find-cross-references` 到指针变量 → 看所有使用点
4. 检查 free 后是否置空（ptr = NULL）
5. 检查 use 前是否判空（if (ptr != NULL)）
6. `rename-variables` → freed_ptr、dangling_ptr（便于理解）
7. 在 use 处 `set-decompilation-comment` → "Use-after-free"
8. `set-bookmark` type="Warning" category="Use-After-Free"

**明显特征**：
- free() 后没有把指针设为 NULL
- 任意路径上出现 free 后解引用
- 同一指针多次 free
- 指针在不同语义下被复用（A 类型释放，B 类型使用）

### 堆溢出（Heap Overflow）模式

**概念特征**：
- 按某个大小 malloc
- 写入超过分配大小
- 溢出到相邻 chunk
- 可破坏堆元数据或相邻对象数据

**易错模式**：

```c
// Allocation too small
buffer = malloc(64);
read(fd, buffer, 128);              // Heap overflow

// Calculation error
buffer = malloc(count * sizeof(element));
for (i = 0; i <= count; i++)        // Off-by-one (should be <, not <=)
    buffer[i] = data[i];            // Overflows by one element

// Unchecked string operation on heap
buffer = malloc(64);
strcpy(buffer, user_input);         // Overflow if user_input > 63 bytes
```

**在反编译代码里要看的点**：
```
Heap allocation:
  heap_buf = malloc(0x40);          // Allocates 64 bytes

Write operation:
  read(0, heap_buf, 0x100);         // Reads 256 bytes → overflow

Adjacent allocations:
  buf1 = malloc(0x40);
  buf2 = malloc(0x40);              // buf2 likely adjacent to buf1
  strcpy(buf1, user_input);         // May overflow into buf2

Metadata corruption risk:
  chunk = malloc(size);
  overflow_write(chunk, large_size);  // May corrupt next chunk's metadata
```

**排查策略**：
1. `search-decompilation` pattern="malloc"
2. 追踪分配出来的 buffer 在后续如何使用
3. 找写入操作（strcpy、memcpy、read、循环）
4. 对比分配 size 与写入 size
5. 看是否存在相邻分配（潜在利用目标）
6. `set-decompilation-comment` → "Heap overflow: writes 256 into 64-byte allocation"
7. `set-bookmark` type="Warning" category="Heap Overflow"

**明显特征**：
- 小 malloc 后跟大 read/write
- 堆 buffer 上做字符串操作但无 bounds
- 循环写入堆数组缺少边界检查
- 连续多次 malloc（堆布局更可预测）

---

## 利用原语模式（Exploitation Primitives）

### 任意地址写（Arbitrary Memory Write）原语

**概念特征**：
- 能把可控数据写到选定地址
- 可由多类漏洞实现
- 是控制流劫持/数据破坏的基础能力

**原语构造模式**：

**格式化字符串任意写**：
```
// Concept: %n writes byte count to pointer argument
printf("AAAA%7$n");
// If stack[7] is controlled pointer, writes to *stack[7]

Technique:
1. Place target address on stack
2. Position format string to access it (%N$n)
3. Adjust byte count with padding to write desired value
4. Use width specifiers: %200c%7$n → writes 200+4=204
```

**栈溢出任意写**：
```
// Concept: Overflow to overwrite pointer, then use pointer

Step 1: Overflow to corrupt pointer
[buffer overflow] → [overwrite ptr variable]

Step 2: Trigger write through pointer
*ptr = value;  // Writes to attacker-controlled address
```

**堆溢出任意写**：
```
// Concept: Overflow heap chunk to corrupt adjacent chunk's pointers

Chunk layout:
[chunk1 metadata][chunk1 data][chunk2 metadata][chunk2 data]

Overflow chunk1 data → overwrite chunk2 metadata → corrupt pointers
When chunk2 used, writes to attacker-controlled addresses
```

**排查策略**：
1. 先定位漏洞（格式化字符串/溢出/UAF 等）
2. 分析能覆盖到什么
3. 追踪指针在被破坏后是否会被解引用
4. `set-bookmark` type="Analysis" category="Arbitrary Write" → 记录原语

**任意写成立条件**：
- 指针值可控（溢出/格式化字符串等）
- 程序会解引用该可控指针（赋值/函数调用参数等）
- 可破坏堆元数据（unlink / freelist 利用等）

### 任意地址读（Arbitrary Memory Read）原语

**概念特征**：
- 能从选定地址读取内存
- 用于泄露地址、canary、代码/数据
- 是绕过 ASLR 等保护的关键

**原语构造模式**：

**格式化字符串任意读**：
```
// Concept: %s reads string from pointer argument
printf("AAAA%10$s");
// If stack[10] is controlled pointer, prints string at *stack[10]

Technique:
1. Place target address on stack
2. Position format string to access it (%N$s)
3. Read output to obtain memory contents
```

**未初始化数据泄露**：
```
// Concept: Uninitialized variables contain previous stack/heap data

Pattern in decompiled code:
  char buffer[64];
  // No initialization
  send(socket, buffer, 64, 0);      // Leaks stack contents

Investigation:
  Look for send/write without initialization
  Check if data used before written
```

**缓冲区越界读（over-read）**：
```
// Concept: Read past end of buffer into adjacent memory

Pattern:
  char buffer[64];
  strncpy(buffer, input, 64);       // No null termination
  printf("%s", buffer);             // Reads past end until null byte

Result: Leaks adjacent stack data
```

**排查策略**：
1. 找格式化字符串漏洞（用户可控 format）
2. 找未初始化变量被 send/write 输出
3. 找字符串操作缺少 `\0` 导致越界读
4. `set-bookmark` type="Analysis" category="Info Leak" → 记录泄露原语
5. 计算可泄露内容（地址、canary、指针等）

**任意读成立条件**：
- format string 里 `%s` 且指针可控
- 未初始化 buffer 被直接输出
- 缺少 `\0` 导致读取到相邻内存
- 堆 UAF 配合读操作可泄露元数据/指针

### 控制流劫持（Control Flow Hijack）原语

**概念特征**：
- 将程序执行流重定向到攻击者可控位置
- 通过覆盖函数指针或返回地址实现
- 目标：执行 shellcode、ROP 链或复用现有函数

**劫持目标模式**：

**覆盖返回地址（栈溢出）**：
```
Stack layout:
[buffer][saved rbp][return address]

Overflow buffer → overwrite return address → redirect on function return

What to look for:
  Local buffer vulnerable to overflow
  Return address at predictable offset (buffer_size + 8 on x64)
  Calculate offset: buffer start to return address location
```

**覆盖函数指针**：
```c
// Global or heap-allocated function pointer
void (*callback)(void) = default_handler;

// Overflow to overwrite callback
buffer_overflow → overwrite callback pointer

// Trigger hijack
callback();  // Calls attacker-controlled address
```

**覆盖 GOT/PLT**：
```c
// Global Offset Table contains addresses of library functions
// Overwrite GOT entry to redirect library call

Example:
  Overwrite GOT[puts] with system address
  Next call to puts() actually calls system()

Requirement: Arbitrary write primitive to GOT address
```

**覆盖虚表（vtable）**：
```c
// C++ objects have vtable pointers
// Overwrite vtable pointer to fake vtable

Object layout:
[vtable ptr][member1][member2]...

Overflow → overwrite vtable ptr → point to attacker-controlled memory
Virtual function call → uses fake vtable → hijacks control flow
```

**排查策略**：
1. 定位溢出点
2. 判断相邻内存里有什么（返回地址/函数指针/vtable）
3. 计算从 buffer 到目标的 offset
4. `get-data` at GOT/PLT addresses → 获取函数指针位置
5. `set-bookmark` type="Analysis" category="Control Flow Hijack"
6. 记录目标地址与 offset

**明显特征**：
- 全局变量或结构体里存在函数指针
- 存在通过函数指针的间接调用
- C++ 虚函数调用（vtable 相关）
- 可定位的 GOT/PLT 条目可作为目标

### 信息泄露（绕过 ASLR）原语

**概念特征**：
- 从内存中泄露地址以绕过地址随机化
- 用泄露出的指针推回 base 地址
- 后续利用要基于动态计算出的地址

**泄露来源模式**：

**泄露栈地址**：
```
// Stack addresses often present on stack itself
Format string: printf("%p %p %p %p")  // Leak stack pointers
Uninitialized: Stack variable contains previous stack frame address

Use: Calculate stack layout, predict buffer addresses
```

**泄露代码地址（绕 PIE）**：
```
// Return addresses on stack point to code section
Format string leak of return address → code address
Calculate code base: leaked_addr & ~0xFFF (page alignment)

Use: Calculate gadget addresses, function addresses
```

**泄露 libc 地址（绕 ASLR）**：
```
// GOT contains resolved libc function addresses
Arbitrary read of GOT entry → libc function address
Calculate libc base: leaked_addr - function_offset

Use: Calculate system(), one_gadget, useful function addresses
```

**泄露堆地址**：
```
// Heap pointers often in freed chunks or stack
Use-after-free leak: Read freed chunk (contains fwd/bck pointers)
Format string: Leak heap pointer from stack

Use: Predict heap layout, target heap objects
```

**排查策略**：
1. 找到泄露原语（格式化字符串/未初始化/越界读）
2. 判断泄露类型（stack/code/heap/libc）
3. 计算到目标地址的偏移
4. `set-bookmark` type="Note" category="Address Leak" → 记录泄露点
5. `set-comment` → "Leaks libc address, calculate system() as libc_base + 0x4f4e0"

**明显特征**：
- printf 使用用户可控 format
- send/write 输出未初始化 buffer
- 字符串未终止导致越界读
- 程序可见 freed chunk 元数据（UAF 泄露）

---

## 常见利用流程（Common Exploitation Workflows）

### 栈溢出拿 Shell

**攻击流程**：
```
1. Find buffer overflow on stack
2. Calculate offset to return address
3. Identify target for hijack:
   a. Shellcode address (if NX disabled)
   b. system() address (if no ASLR)
   c. ROP chain address (if protections enabled)
4. Construct payload: [padding][return address][arguments/ROP]
5. Trigger overflow, return redirects to attacker code
6. Execute shellcode/system("/bin/sh") to get shell
```

**排查步骤**：
1. `get-decompilation` 定位漏洞函数 → 确认溢出
2. `rename-variables` → buffer、user_input、size
3. 计算 offset：buffer 到返回地址（通常 buffer_size + 8）
4. `search-strings-regex` pattern="/bin/sh" → 找 shell 字符串
5. `get-symbols` includeExternal=true → 找 system() 导入
6. `set-bookmark` type="Analysis" category="Exploit Plan"
7. 用 comment 记录 payload 结构

### 格式化字符串到任意写

**攻击流程**：
```
1. Find printf(user_input) vulnerability
2. Test format string: Send "%x %x %x" → leak stack values
3. Find offset to controlled data on stack
4. Construct format string to write to arbitrary address:
   - Place target address on stack
   - Use %N$n to write to address at stack[N]
5. Target: Overwrite GOT entry, return address, or function pointer
6. Redirect execution to attacker code
```

**排查步骤**：
1. `search-decompilation` pattern="printf|sprintf" → 找 format 调用
2. `get-decompilation` with includeContext → 验证 format 来自用户
3. `get-data` at GOT addresses → 找覆盖目标
4. 计算栈上可控 buffer 的参数偏移
5. `set-bookmark` type="Warning" category="Format String"
6. 记录利用点："%7$n writes to address at stack[7]"

### 堆利用到代码执行

**攻击流程**：
```
1. Find heap vulnerability (use-after-free, heap overflow, double-free)
2. Understand heap layout (chunk sizes, allocation order)
3. Exploit heap corruption:
   a. Use-after-free: Free object, allocate new, use old pointer (type confusion)
   b. Heap overflow: Overflow chunk to corrupt adjacent chunk metadata
   c. Double-free: Corrupt freelist to allocate arbitrary address
4. Gain arbitrary write or control flow hijack primitive
5. Overwrite function pointer, GOT entry, or return address
6. Execute attacker code
```

**排查步骤**：
1. `search-decompilation` pattern="malloc|free"
2. 追踪 alloc/free 模式
3. 确认漏洞类型（UAF/overflow/double-free）
4. `rename-variables` → chunk1、chunk2、freed_ptr、size
5. 分析相邻分配（overflow 目标）
6. `set-bookmark` type="Warning" category="Heap Vulnerability"
7. 记录拿到的利用原语

### Ret2libc（返回到 libc）

**攻击流程**：
```
1. Find stack overflow vulnerability
2. Cannot use shellcode (NX enabled)
3. Redirect to existing libc function: system()
4. Set up arguments: First arg points to "/bin/sh"
5. Payload structure:
   - Overflow to return address
   - Overwrite return address → system() address
   - Set first argument → pointer to "/bin/sh" string
6. Function returns, calls system("/bin/sh"), spawns shell
```

**排查步骤**：
1. `get-decompilation` → 找到溢出点
2. `search-strings-regex` pattern="/bin/sh" → 获取字符串地址
3. `get-symbols` includeExternal=true → 找 system 导入
4. 确认调用约定（x86 栈传参；x64 RDI 传第一个参数）
5. 必要时找 ROP gadget：`pop rdi; ret`
6. `set-bookmark` type="Note" category="Ret2libc Plan"
7. 记录 payload：`[padding][system_addr][ret_addr]["/bin/sh"_ptr]`

### ROP 链构造（ROP Chain Construction）

**攻击流程**：
```
1. Find code execution vulnerability (overflow, etc.)
2. Protections prevent direct shellcode/ret2libc
3. Build ROP chain: Sequence of gadget addresses
4. Each gadget: Small code fragment ending in 'ret'
5. Chain gadgets to build desired operation (e.g., execve syscall)
6. Place chain on stack, trigger vulnerability
7. Execution flows through gadgets, performs desired operation
```

**排查步骤**：
1. 明确所需 gadget（`pop rdi; ret`、`pop rsi; ret`、`syscall; ret` 等）
2. 用外部工具（ROPgadget/ropper）在 binary/libc 中找 gadget
3. 在每个 gadget 地址 `set-bookmark` type="Note" category="ROP Gadget"
4. 在 gadget 地址 `set-comment` → "pop rdi; ret"
5. 记录 ROP 链结构：
   - [gadget1_addr] → pop rdi; ret
   - ["/bin/sh"_ptr] → rdi 参数
   - [gadget2_addr] → pop rsi; ret
   - [NULL] → rsi 参数
   - [syscall_addr] → execve syscall
6. `set-bookmark` type="Analysis" category="ROP Chain Plan"

---

## 保护机制绕过模式（Protection Mechanism Bypass）

### 栈 Canary 绕过

**Canary 机制**：
```
Stack layout with canary:
[buffer][stack canary][saved rbp][return address]

On function return:
  if (canary != expected_canary)
      __stack_chk_fail();  // Abort on corruption
```

**绕过方法**：

**1. 泄露 canary（格式化字符串/未初始化泄露）**：
```
printf(user_input);  // Format string leak
Send "%7$p" → leak canary from stack position 7
Include leaked canary in overflow payload to preserve it
```

**2. 爆破 canary（fork 服务端常见）**：
```
If server forks instead of exiting:
  Canary same across fork
  Brute-force one byte at a time
  256 attempts per byte, 1024 total for 32-bit canary
```

**3. 不破坏 canary 的覆盖**：
```
Partial overwrite: Overflow only up to return address
Don't touch canary if it's not in the way
Or overwrite saved rbp and return address precisely
```

**排查**：
1. `search-decompilation` pattern="__stack_chk_fail" → 判断是否有 canary
2. `get-decompilation` → 查看 canary check 逻辑
3. 定位 canary 在栈上的位置
4. `set-bookmark` type="Note" category="Stack Canary" → 记录位置
5. 规划绕过：泄露/爆破/规避

### NX/DEP 绕过（不可执行）

**保护机制**：
```
Stack/heap marked non-executable
Shellcode injection doesn't work (causes segfault)
```

**绕过方法**：

**1. Return-to-libc（ret2libc）**：
```
Don't inject code, reuse existing code
Redirect to system(), execve(), etc.
Set up arguments properly
```

**2. ROP（Return-Oriented Programming）**：
```
Chain existing code fragments (gadgets)
Build complex operations from simple gadgets
No new code introduced
```

**3. mprotect/VirtualProtect ROP**：
```
Use ROP to call mprotect(shellcode_addr, RWX)
Change shellcode memory to executable
Jump to now-executable shellcode
```

**排查**：
1. `get-memory-blocks` → 查看 stack/heap 权限（是否有 x）
2. 若 NX 开启，优先规划 ROP 或 ret2libc
3. `get-symbols` includeExternal=true → 找可复用函数
4. `set-bookmark` type="Analysis" category="NX Bypass"

### ASLR 绕过（地址随机化）

**保护机制**：
```
Addresses randomized each execution
Code base, libc base, stack base, heap base all randomized
Exploit addresses must be dynamically calculated
```

**绕过方法**：

**1. 信息泄露**：
```
Leak address from memory (format string, uninitialized data)
Calculate base address from leaked pointer
Use base + offset to find desired functions
```

**2. 部分覆盖（Partial Overwrite）**：
```
Only lowest 12 bits (page offset) are not randomized
Overwrite only last byte of address
Reduces entropy, enables brute-force or partial redirect
```

**3. 堆喷（CTF 中较少适用）**：
```
Fill heap with controlled data
Increase probability of hitting controlled memory
```

**排查**：
1. 定位泄露原语（format string/over-read/未初始化）
2. 计算泄露类型（code/stack/heap/libc）
3. 计算偏移：leaked_addr → target_addr
4. `set-comment` → "Leak libc: system = libc_base + 0x4f4e0"
5. `set-bookmark` type="Analysis" category="ASLR Bypass"

### PIE 绕过（地址无关可执行）

**保护机制**：
```
Code section randomized (in addition to ASLR)
Function addresses, gadget addresses randomized
Cannot hardcode code addresses
```

**绕过方法**：

**1. 泄露代码地址**：
```
Leak return address from stack → points to code
Calculate code base: leaked_addr & ~0xFFF
Calculate function/gadget addresses: code_base + offset
```

**2. 部分覆盖**：
```
Overwrite only last byte of return address
Redirect within same function or nearby functions
Useful for redirecting to existing win() function
```

**排查**：
1. 判断是否启用 PIE（看 binary 属性）
2. 找代码地址泄露（栈上的返回地址）
3. 计算从 code base 到目标的 offset
4. `set-bookmark` type="Analysis" category="PIE Bypass"

---

## 如何使用本参考（Using This Reference）

### 模式识别工作流

1. **确定漏洞类型** → 将反编译代码与漏洞模式匹配
2. **确定利用原语** → 漏洞能提供什么能力？
3. **检查保护** → 需要哪些绕过？
4. **规划利用链** → 组合原语达成目标
5. **在 Ghidra 中记录** → 书签、注释、变量重命名

### 排查优先级（国内 CTF 常用节奏）

**先从这些入手：**
1. 不安全 API（strcpy、printf 等）快速定位
2. buffer 大小 vs 操作大小对比（最直接）
3. 输入流追踪（用户数据从哪来，去哪）

**再分析：**
4. 内存布局（buffer 旁边是什么？）
5. 可利用目标（返回地址、函数指针、GOT）
6. 保护机制（canary、NX、ASLR、PIE）

**最后规划：**
7. 构造原语
8. 绕过策略
9. payload 结构
10. 执行计划与验证步骤

### 渐进式理解（Progressive Understanding）

**第一遍**："main() 里对 buffer[64] 做了不安全 strcpy"
**第二遍**："溢出 64 字节后能到返回地址，offset 大约 +72"
**第三遍**："可 ret 到 system@plt，还需要 '/bin/sh' 地址"
**第四遍**："完整 ret2libc：overflow → system('/bin/sh') → shell"

每一轮都在把利用计划变得更具体。

### 基于证据的利用（Evidence-Based Exploitation）

每个结论都要有证据支撑：
- “存在溢出” → 证明 buffer_size < input_size
- “返回地址 offset=72” → 给出栈布局计算
- “能调用 system()” → 给出 system@plt 地址或导入证据
- “可以绕过 ASLR” → 给出泄露原语与计算过程

把所有证据用 ida-pro-mcp 的书签和注释记录下来，便于复现与写 exp。