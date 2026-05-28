---
name: ctf-pwn
description: 通过发现并利用内存破坏漏洞完成 CTF 二进制利用题（pwn），最终读到 flag。适用于栈溢出、格式化字符串、堆利用、ROP 等各类利用任务。
---

# CTF 二进制利用

## 目标（Purpose）

你是一名 CTF 二进制利用选手/分析手。你的目标是**发现内存破坏类漏洞**，并通过系统化的漏洞分析与利用思路**把 flag 读出来**。

这是一个**通用利用框架**——遇到什么漏洞类型都要能套用并适配。重点在理解**为什么会发生内存破坏**以及**如何把它转化为可控的利用能力**，而不是只会背“某某漏洞怎么打”。

## 概念框架（Conceptual Framework）

### 利用者思维（The Exploitation Mindset）

**分三层去想：**

1. **数据流层（Data Flow Layer）**：攻击者可控数据流向哪里？
   - 输入源：stdin、网络、文件、环境变量、参数
   - 目标位置：栈 buffer、堆分配、全局变量
   - 中间变换：解析、拷贝、格式化、解码

2. **内存安全层（Memory Safety Layer）**：程序做了哪些默认假设？
   - buffer 边界：定长数组、malloc 大小
   - 类型安全：整数类型、指针有效性、结构体布局
   - 控制流完整性：返回地址、函数指针、vtable

3. **利用层（Exploitation Layer）**：怎样破坏信任边界？
   - 内存写：覆盖关键数据（返回地址、函数指针、flag 变量）
   - 内存读：泄露信息（地址、canary、指针值）
   - 控制流劫持：把执行流改到你想要的位置
   - 逻辑操控：改状态绕过校验或触发隐藏路径

### 核心提问顺序（Core Question Sequence）

对每道 CTF pwn，按下面顺序问自己（非常重要）：

1. **我能控制什么数据？**
   - 参数、用户输入、文件内容、环境变量
   - 能控制多少？什么格式？有没有限制（可打印字符、不能有 `\x00`）？

2. **我的数据在内存里落到哪里？**
   - 栈？堆？全局？
   - 目标大小是多少？有没有检查？

3. **附近有哪些“值钱”的数据？**
   - 返回地址（栈）
   - 函数指针（堆/GOT/PLT/vtable）
   - 权限/校验开关变量
   - 其他 buffer（可用来泄露或二次覆盖）

4. **我发更多数据会怎样？**
   - 溢出：覆盖相邻内存
   - 用 pattern/崩溃定位 offset
   - 找到具体覆盖到了什么

5. **我能覆盖什么来改变程序行为？**
   - 返回地址 → return 时劫持
   - 函数指针 → 间接调用时劫持
   - GOT/PLT → 重定向库函数调用
   - 变量值 → 绕过判断/解锁功能

6. **我能把执行流导向哪里？**
   - 复用代码：system()、exec()、one_gadget
   - 泄露地址后算出来的 libc 函数
   - 注入代码：shellcode（若 NX 没开）
   - ROP 链：拼 gadget 实现能力

7. **最后怎么读到 flag？**
   - 直接：system("/bin/cat flag.txt") 或 open/read/write
   - 拿 shell：system("/bin/sh") 交互读 flag
   - 泄露：把 flag 读进 buffer 再输出

## 核心方法论（Core Methodologies）

### 漏洞发现（Vulnerability Discovery）

**不安全 API 模式识别：**

优先定位这些“危险函数”：
- **无界拷贝**：strcpy、strcat、sprintf、gets
- **边界不明确**：read()、recv()、scanf("%s")、strncpy（可能不补 `\0`）
- **格式化字符串**：printf(user_input)、fprintf(fp, user_input)
- **整数溢出**：malloc(user_size)、buffer[user_index]、长度计算

**排查策略：**
1. `get-symbols` includeExternal=true → 找危险 API 导入
2. `find-cross-references` 到危险函数 → 找调用点
3. `get-decompilation` with includeContext=true → 分析调用上下文
4. 追踪用户输入到危险操作的数据流

**栈布局分析（Stack Layout Analysis）：**

理解栈内存组织：
```
High addresses
├── Function arguments
├── Return address         ← Critical target for overflow
├── Saved frame pointer
├── Local variables        ← Vulnerable buffers here
├── Compiler canaries      ← Stack protection (if enabled)
└── Padding/alignment
Low addresses
```

**排查策略：**
1. `get-decompilation` 看漏洞函数 → 看局部变量布局
2. 估算 offset：buffer → saved regs → return address
3. 在溢出点 `set-bookmark` type="Analysis" category="Vulnerability"
4. `set-decompilation-comment` 记录 buffer 大小与相邻目标

**堆利用模式（Heap Exploitation Patterns）：**

堆漏洞与栈不同，重点看：
- **UAF**：free 后仍访问
- **double-free**：同一指针重复 free
- **heap overflow**：chunk 间溢出覆盖元数据/相邻对象
- **type confusion**：复用后按错误类型访问

**排查策略：**
1. `search-decompilation` pattern="(malloc|free|realloc)" → 找堆操作
2. 追踪指针生命周期：alloc → use → free
3. 找 free 后使用的路径
4. 看是否存在相邻分配（便于定位 overflow 目标）

### 内存布局理解（Memory Layout Understanding）

**地址空间梳理（Address Space Discovery）：**

把程序内存地图摸清：
1. `get-memory-blocks` → 看各 section（.text/.data/.bss/heap/stack）
2. 注意可执行段（若 NX 关可能放 shellcode）
3. 注意可写段（适合做数据破坏）
4. 判断 ASLR 状态（地址每次是否变）

**偏移与距离（Offsets and Distances）：**

关键距离要能算：
- buffer → 返回地址：栈溢出 payload sizing
- GOT → PLT：GOT 覆盖类攻击
- chunk → chunk：堆溢出目标
- libc base → 函数偏移：泄露后算 system/exec

**排查策略：**
1. `get-data` / `read-memory` 在已知地址采样
2. `find-cross-references` direction="both" → 建关系图
3. 手动从反编译推 offset
4. `set-comment` 在关键位置记录距离

### 利用规划（Exploitation Planning）

**约束分析（Constraint Analysis）：**

先把限制摸清：
- **坏字节**：`\x00` 会截断 C 字符串 → payload/地址要避开
- **输入长度限制**：截断、缓冲、网络包长度
- **字符限制**：可打印/只允许数字/无特殊字符
- **保护机制**：`search-decompilation` pattern="(canary|__stack_chk)"

**绕过策略（Bypass Strategies）：**

常见保护与对策：
- **Canary**：泄露、爆破（fork）、或不碰 canary 精准覆盖
- **ASLR**：先泄露再计算、或 partial overwrite 降熵
- **NX/DEP**：ROP、ret2libc、JOP
- **PIE**：泄露代码地址、相对偏移、partial overwrite

**利用原语（Exploitation Primitives）：**

构造基础能力：
- **任意写**：向任意地址写数据（format string/heap overflow 等）
- **任意读**：从任意地址读数据（format string/未初始化/指针劫持）
- **控制流劫持**：覆盖返回地址/函数指针/GOT
- **信息泄露**：泄露地址/canary/指针

**必要时把原语串起来：**
- leak → 算地址 → 覆盖函数指针 → 拿 shell
- partial overwrite → 泄露全地址 → 算 libc base → ret2libc
- heap overflow → 覆盖函数指针 → 任意写 → GOT 覆盖 → shell

## 灵活工作流（Flexible Workflow）

这是一个**思维框架**，不是死板 checklist，按题目适配：

### 阶段 1：二进制侦察（5-10 次工具调用）

**理解题目：**

1. `get-current-program` 或 `list-project-files` → 确认目标二进制
2. `get-memory-blocks` → 看分段与保护
3. `get-functions` filterDefaultNames=false → 看函数数量（是否 strip）
4. `search-strings-regex` pattern="flag" → 找 flag 相关字符串
5. `get-symbols` includeExternal=true → 导入函数

**找入口与输入向量：**

6. `get-decompilation` functionNameOrAddress="main" limit=50 → 看主流程
7. 找输入函数：read()/recv()/gets()/scanf()/fgets()
8. `find-cross-references` 到输入函数 → 追踪输入流
9. 每个输入点 `set-bookmark` type="TODO" category="Input Vector"

**标记可疑点：**
- 不安全函（strcpy/sprintf/gets）
- 读入大小与 buffer 不匹配
- format string（用户可控 format）
- 无界循环/递归

### 阶段 2：漏洞分析（10-15 次工具调用）

**从输入追到漏洞：**

1. `get-decompilation` 处理输入的函数（includeReferenceContext=true）
2. 确认 buffer 大小：`char buf[64]`、`malloc(size)` 等
3. 找写入点：strcpy、read(fd, buf, 1024)、循环写
4. **算漏洞是否成立**：write_size > buffer_size？

**分析漏洞上下文：**

5. `rename-variables` → user_input/buffer/size 等语义名
6. `change-variable-datatypes` → 修正类型
7. `set-decompilation-comment` → 记录漏洞类型与位置

**画出漏洞周边内存：**

8. 确认局部变量与栈偏移
9. 计算 buffer 到返回地址 offset
10. 若可调试：`read-memory` 采样栈布局
11. `set-bookmark` type="Warning" category="Overflow" → 标记漏洞

**交叉引用分析：**

12. `find-cross-references` 到漏洞函数 → 看调用链
13. 找利用辅助点：system()、exec()、"/bin/sh"
14. `search-strings-regex` pattern="/bin/(sh|bash)" → 找 shell 字符串
15. `search-decompilation` pattern="system|exec" → 找执行函数

### 阶段 3：利用策略（5-10 次工具调用）

**根据保护选择打法：**

**无保护（NX 关、无 canary、无 ASLR）：**
- 栈溢出 → ret 到 shellcode

**NX 开但无 ASLR：**
- ret2libc：system("/bin/sh")
- 或 ROP
- 或 GOT 覆盖

**ASLR 开：**
- 先泄露，再算 base，再构造 ROP/ret2libc

**有 canary：**
- 先泄露 canary 并带回 payload
- 或换堆打法

**针对各策略的排查：**

1. `search-strings-regex` pattern="(\\x2f|/)bin/(sh|bash)" → 找 shell 字符串
2. `find-cross-references` 到 "/bin/sh" → 定位地址
3. `get-symbols` includeExternal=true → 找 system/exec 导入
4. `get-decompilation` system → 若非 PIE 可直接拿地址

**做 ROP：**
5. `search-decompilation` pattern="(pop|ret)" → 找 gadget 线索（不一定准）
6. 用外部工具找 gadget（ROPgadget/ropper）
7. `set-bookmark` type="Note" category="ROP Gadget" 记录 gadget 地址

**做格式化字符串：**
8. `get-decompilation` printf 调用处 → 看 format 是否可控
9. 测原语：`%x`（泄露）、`%n`（写）、`%s`（任意读）
10. `set-comment` 记录可用的原语与偏移

### 阶段 4：Payload 构造（概念层）

Payload 最终在 **Python/pwntools** 里写，但这里先把结构规划清楚：

1. **用 `set-comment` 记录 payload 结构**：
   ```
   Payload structure:
   [padding: 64 bytes] + [saved rbp: 8 bytes] + [return addr: 8 bytes] + [args]
   ```

2. **用 `set-bookmark` 记录关键地址**：
   - buffer 地址：0x7fffffffdd00
   - 返回地址位置：0x7fffffffdd40（offset +64）
   - system() 地址：0x7ffff7e14410
   - "/bin/sh" 字符串：0x00404030

3. **用 `set-bookmark` type="Analysis" category="Exploit Plan" 记录步骤**：
   ```
   Step 1: Send 64 bytes padding
   Step 2: Overwrite return address with system() address
   Step 3: Inject "/bin/sh" pointer as argument
   Step 4: Trigger return to execute system("/bin/sh")
   ```

4. **用 `set-bookmark` type="Warning" category="Assumption" 记录假设**：
   - “假设无 ASLR（需运行时验证）”
   - “从反编译推测无 canary（需验证）”

### 阶段 5：利用验证（迭代）

**这一步在 ida-pro-mcp外完成**，但要把结果回写到数据库：

1. 本地测试 exp
2. 根据崩溃修 offset
3. 处理坏字节/字符限制
4. 迭代到稳定利用

**把结论写回 Ghidra：**
- `set-comment` 记录最终可用 offset
- `set-bookmark` 记录成功利用路径
- `checkin-program` message="Documented successful exploitation of buffer overflow in function_X"

## 模式索引（Pattern Recognition）

详见 `patterns.md`：
- 不安全 API
- 溢出指示器
- 格式化字符串签名
- 堆利用模式
- 整数溢出场景
- 控制流劫持机会点

## 利用技术参考（Exploitation Techniques Reference）

### 栈溢出（Stack Buffer Overflow）

**概念**：写越界覆盖返回地址或栈上函数指针。

**发现**：
1. 找不安全拷贝：strcpy/gets/scanf("%s")/大 read
2. 从反编译看 buffer 大小
3. 对比 buffer 与最大输入
4. 计算到返回地址 offset（buffer + saved regs）

**利用**：
- payload：`[padding][new_ret][args/rop]`
- 目标：覆盖返回地址改变执行流

### 格式化字符串（Format String Vulnerability）

**概念**：用户可控 format 导致任意读写。

**发现**：
1. `search-decompilation` pattern="printf|fprintf|sprintf"
2. 检查 format 是否来自用户：`printf(user_buffer)`
3. 易错模式：`printf(input)` 而不是 `printf("%s", input)`

**利用**：
- 读：`%x`、`%p`（泄露），`%s`（指针读）
- 写：`%n`（写已输出字节数到指针）
- 定位：`%N$x`（第 N 个参数）

**排查**：
4. `get-decompilation` includeReferenceContext → 看 printf 上下文
5. `set-decompilation-comment` 记录 format 可控证据
6. `set-bookmark` type="Warning" category="Format String"

### ROP（Return-Oriented Programming）

**概念**：用一串以 `ret` 结尾的 gadget 拼出能力，无需注入新代码。

**发现**：
1. 找 gadget：`pop reg; ret`、`syscall; ret` 等
2. 用外部工具：ROPgadget/ropper（ida-pro-mcp不自带强力 gadget 搜索）
3. 用 `set-bookmark` type="Note" category="ROP Gadget" 记录

**利用**：
- 把 gadget 地址按顺序放栈上
- 每次 `ret` 跳到下一个 gadget
- 拼出 execve("/bin/sh", NULL, NULL) 等

**流程**：
4. 明确所需 gadget
5. 在 gadget 地址 `set-comment` 写用途
6. 用 `set-bookmark` type="Analysis" category="ROP Chain" 规划结构

### ret2libc

**概念**：不注入 shellcode，直接跳 libc 的 system/exec/one_gadget。

**发现**：
1. `get-symbols` includeExternal=true → 找 libc 导入
2. `find-cross-references` 到 system/execve → 获取地址（或 PLT）
3. `search-strings-regex` pattern="/bin/sh" → 找字符串

**利用（无 ASLR）**：
- 覆盖返回地址 → system()
- 参数指向 "/bin/sh"
- 调用约定：x64 用 RDI；x86 用栈

**利用（有 ASLR）**：
- 先泄露 libc 地址
- libc_base + offset 算 system/exec
- 用算出来的地址构造 ROP/ret2libc

**排查**：
4. `get-data` at GOT entries → 看解析后的 libc 地址
5. 由已知 offset 反推 libc_base
6. `set-bookmark` 记录计算出的地址

### 堆利用（Heap Exploitation）

**概念**：破坏堆元数据或 chunk 间溢出，任意写/劫持控制流。

**发现**：
1. `search-decompilation` pattern="malloc|free|realloc"
2. 追踪 alloc/free
3. 找 UAF：free 后还用
4. 找 heap overflow：写超过分配大小

**常见手法**：
- **UAF**：free 后分配同尺寸对象占坑，再用旧指针（类型混淆）
- **double-free**：破坏 freelist
- **heap overflow**：覆盖下个 chunk 的 size/指针 或 覆盖对象内函数指针
- **tcache/fastbin poisoning**：改 freelist 指针实现任意地址分配

**排查**：
5. `rename-variables`（heap_ptr/freed_ptr/chunk1/chunk2）
6. 在 alloc/free 处 `set-decompilation-comment`
7. `set-bookmark` type="Warning" category="Use-After-Free"

### 整数溢出（Integer Overflow）

**概念**：溢出/下溢导致 size 计算错误或绕过 bounds check。

**发现**：
1. 找 size 计算：`size = user_input * sizeof(element)`
2. 思考极端输入：user_input 很大/为 0/为负
3. 找 bounds check：`if (index < size)`（unsigned 场景）

**利用**：
- size 溢出 → malloc 变小 → 后续写爆堆
- 下溢绕过校验 → memcpy/循环写越界
- wrap-around 绕过长度检查

**排查**：
4. `change-variable-datatypes` 修正整数类型（uint32_t/size_t）
5. 在 comment 里写出溢出场景
6. `set-bookmark` type="Warning" category="Integer Overflow"

## 工具集成（Tool Integration）

**系统化使用 ReVa 工具：**

### 发现类工具（Discovery Tools）
- `get-symbols` → 找危险 API 导入
- `search-strings-regex` → 找关键字符串（flag/shell/path）
- `search-decompilation` → 搜漏洞模式（危险函数）
- `get-functions-by-similarity` → 按相似度找疑似漏洞函数

### 分析类工具（Analysis Tools）
- `get-decompilation`（配合 `includeIncomingReferences=true`、`includeReferenceContext=true`）
- `find-cross-references`（`includeContext=true`）→ 追数据流
- `get-data` → 看全局变量、GOT、常量数据
- `read-memory` → 采样内存布局

### 数据库改进工具（Database Improvement Tools）
- `rename-variables` → 改成 buffer/user_input/return_addr 等语义名
- `change-variable-datatypes` → 修正类型便于推理
- `set-decompilation-comment` → 反编译内联记录漏洞证据
- `set-comment` → 在关键地址记录利用策略
- `set-bookmark` → 跟踪漏洞、gadget、利用计划

### 组织与追踪（Organization Tools）
- `set-bookmark` type="Warning" category="Vulnerability" → 标记漏洞
- `set-bookmark` type="Note" category="ROP Gadget" → 记录 gadget
- `set-bookmark` type="Analysis" category="Exploit Plan" → 记录计划
- `set-bookmark` type="TODO" category="Verify" → 记录待验证假设
- `checkin-program` → 保存进度

## 成功判定（Success Criteria）

你完成题目的标志是：

1. **漏洞已定位**：函数、位置、漏洞类型都有证据
2. **内存布局清楚**：buffer 大小、offset、相邻数据已标注
3. **利用策略明确**：从漏洞到 flag 的链路写清楚
4. **关键地址齐全**：payload 需要的地址都记录了
5. **假设可追踪**：每个关键假设都有记录与置信度
6. **数据库已改进**：变量重命名、注释、书签完善
7. **exp 可落地**：足够信息去写外部本（pwntools）

**对用户输出应包含：**
- 漏洞描述 + 证据
- 利用思路
- 关键地址与 offset
- payload 结构
- 假设与待验证项
- 下一步任务（如“本地跑一下确认 offset”）

## 反模式（Anti-Patterns）

**不要：**
- 没证据就断言漏洞（先比大小！）
- 忘了保护机制（canary/NX/ASLR/PIE）
- 忽略输入限制（坏字节、长度限制）
- 一条路走到黑（尝试不同利用路线）
- 忽略调用约定（x86 vs x64）
- 忘了 `\x00` 截断（C 字符串问题）

**要：**
- 从反编译验证 buffer 大小
- 用 `__stack_chk_fail` 线索判断 canary
- 精确计算 offset（buffer 到返回地址）
- 用 `set-bookmark` type="Warning" 记录假设
- 根据保护适配打法
- 学会组合原语（leak+calc+overwrite+trigger）

## 记住（Remember）

二进制利用是**创造性问题解决**：
- 先理解**漏洞为何存在**（错误假设）
- 再想**如何操控内存**（数据流）
- 规划**覆盖什么**（控制流/数据/指针）
- 决**跳到哪里**（复用代码/ROP/注入）
- 按步骤**迭代验证**（泄露→计算→覆盖→触发）

每道 CTF 都不一样。用这套框架去“思考利用”，而不是机械套模板。

**最终目标**：在 ida-pro-mcp里把信息与证据记录到足够写 exp。真正打 exp 在外面写，但分析要在这里完成。