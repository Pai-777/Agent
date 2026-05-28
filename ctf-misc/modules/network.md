# 流量分析模块

## 适用文件类型
- PCAP / PCAPNG

## 检查清单

```yaml
检查项:
  - [ ] HTTP 文件传输还原
  - [ ] FTP/SMB 凭据提取
  - [ ] DNS 隧道 / ICMP 隧道
  - [ ] TCP 流重组
  - [ ] USB 键盘/鼠标流量解析
  - [ ] TLS 解密（如有私钥）
  - [ ] 无线抓包（802.11）
  - [ ] WebSocket / HTTP/2 流量
  - [ ] 异常协议识别
  - [ ] 工控协议隐蔽通道（Modbus/S7/DNP3）
  - [ ] Modbus Function 08 诊断报文分析
  - [ ] Transaction ID / Unit ID 隐写检测
  - [ ] 寄存器值高低字节分离分析

常用工具:
  - Wireshark (GUI 分析)
  - tshark (命令行)
  - tcpdump
  - scapy (Python)
  - NetworkMiner (文件提取)
  - foremost
  - pycryptodome (加密解密)
```

## 分析流程

### Step 1: 基础信息
```bash
# 查看流量包统计
capinfos traffic.pcap

# 协议分布
tshark -r traffic.pcap -q -z io,phs

# 会话统计
tshark -r traffic.pcap -q -z conv,tcp
```

### Step 2: HTTP 分析
```bash
# 提取 HTTP 对象
tshark -r traffic.pcap --export-objects http,./http_objects

# 查看 HTTP 请求
tshark -r traffic.pcap -Y "http.request" -T fields -e http.request.uri

# 查看 HTTP 响应
tshark -r traffic.pcap -Y "http.response" -T fields -e http.file_data
```

### Step 3: FTP/SMB 凭据
```bash
# FTP 用户名密码
tshark -r traffic.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ftp.request.arg

# SMB 文件传输
tshark -r traffic.pcap --export-objects smb,./smb_objects
```

### Step 4: DNS 隧道检测
```bash
# 查看 DNS 查询
tshark -r traffic.pcap -Y "dns.qry.name" -T fields -e dns.qry.name

# 提取 DNS 数据（可能是 Base64 编码）
tshark -r traffic.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | cut -d'.' -f1 | base64 -d
```

### Step 5: USB 键盘流量
```bash
# 提取 USB 数据
tshark -r usb.pcap -T fields -e usb.capdata > usb_data.txt

# 使用脚本解析
python3 scripts/usb_keyboard.py usb_data.txt
```

### Step 6: TCP 流追踪
```bash
# 追踪特定 TCP 流
tshark -r traffic.pcap -q -z follow,tcp,ascii,0

# 或使用 Wireshark GUI
# 右键数据包 → Follow → TCP Stream
```

## 常见出题套路

1. **HTTP 文件传输** → `--export-objects` 提取
2. **USB 键盘** → `scripts/usb_keyboard.py` 解析
3. **DNS 隧道** → 提取域名前缀解码
4. **FTP 明文传输** → 直接提取用户名密码
5. **TCP 流重组** → Follow TCP Stream
6. **ICMP 隧道** → 提取 ICMP data 字段
7. **工控协议隐蔽通道** → Modbus/S7/DNP3 等协议字段隐写

## 工控协议分析（ICS/SCADA）

### Modbus/TCP 协议分析

Modbus 是工控领域最常见的协议，CTF 中常用于隐蔽通道题目。

#### Modbus 协议结构

```yaml
MBAP Header (7 bytes):
  - Transaction ID (2 bytes)    # 事务标识符，可用于隐写
  - Protocol ID (2 bytes)       # 固定为 0x0000
  - Length (2 bytes)            # 后续数据长度
  - Unit ID (1 byte)            # 单元标识符，可用于隐写

PDU (Protocol Data Unit):
  - Function Code (1 byte)      # 功能码，可用于隐写
  - Data (N bytes)              # 数据区，主要隐写位置

常见功能码:
  - 0x01: Read Coils
  - 0x03: Read Holding Registers
  - 0x04: Read Input Registers
  - 0x08: Diagnostics           # ⚠️ 常用于隐蔽通道！
  - 0x10: Write Multiple Registers
```

#### 关键分析点

```yaml
隐写位置优先级:
  1. Function 08 (Diagnostics) 数据区
     - 子功能 0x0000: Return Query Data (回显数据)
     - 攻击者可以在"诊断数据"中隐藏任意内容
     - 协议完全合规，防火墙难以检测
  
  2. Transaction ID 低字节
     - 正常流量中 Transaction ID 递增
     - 异常流量可能在低字节中编码数据
     - 常见编码: ASCII, Base64 字符
  
  3. 寄存器值（Register Values）
     - Read Holding/Input Registers 的响应数据
     - 16位寄存器值可拆分为高低字节
     - 高字节/低字节可能分别编码不同信息
  
  4. Unit ID 字段
     - 正常情况下固定为 0x01 或其他常量
     - 变化的 Unit ID 可能隐藏数据
  
  5. 寄存器地址（Register Address）
     - 读取的起始地址可能编码信息
     - 读取的寄存器数量可能编码信息
```

#### 分析流程

```bash
# Step 1: 识别异常流量
# 查找非标准主机的通信
tshark -r traffic.pcap -Y "modbus" -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport | sort | uniq -c

# Step 2: 提取 Function 08 (Diagnostics) 报文
tshark -r traffic.pcap -Y "modbus.func_code == 8" -T fields -e frame.number -e modbus.trans_id -e modbus.data

# Step 3: 提取 Transaction ID
tshark -r traffic.pcap -Y "modbus" -T fields -e modbus.trans_id

# Step 4: 提取寄存器值
tshark -r traffic.pcap -Y "modbus.func_code == 3 || modbus.func_code == 4" -T fields -e modbus.regnum16 -e modbus.regval_uint16
```

#### Python 分析脚本模板

完整的 Modbus 隐蔽通道分析模板请参考：
**`skills/ctf-misc/templates/modbus_covert_channel.py`**

该模板包含：
- 异常客户端识别
- Function Code 分布分析
- 密钥自动搜索
- Function 08 数据提取
- Transaction ID 和寄存器值分析
- 多种解密算法尝试（DES、AES、XOR）

快速使用：
```bash
# 复制模板到工作目录
cp skills/ctf-misc/templates/modbus_covert_channel.py ./analyze.py

# 修改配置区的 PCAP_FILE 路径
# 运行分析
python analyze.py
```

简化版脚本示例：

```python
#!/usr/bin/env python3
"""Modbus 隐蔽通道分析脚本"""

from scapy.all import rdpcap, TCP, IP

pcap_file = "traffic.pcap"
packets = rdpcap(pcap_file)

# 1. 识别异常 IP
ip_stats = {}
for pkt in packets:
    if TCP in pkt and IP in pkt and pkt[TCP].dport == 502:
        src = pkt[IP].src
        ip_stats[src] = ip_stats.get(src, 0) + 1

print("[*] Modbus 客户端统计:")
for ip, count in sorted(ip_stats.items(), key=lambda x: x[1]):
    print(f"    {ip}: {count} 个请求")

# 2. 提取 Function 08 数据
func08_data = []
for pkt in packets:
    if TCP in pkt and len(pkt[TCP].payload) > 0:
        payload = bytes(pkt[TCP].payload)
        if len(payload) >= 8 and payload[7] == 0x08:  # Function Code 08
            trans_id = int.from_bytes(payload[0:2], 'big')
            diag_data = payload[10:] if len(payload) > 10 else b''
            func08_data.append((trans_id, diag_data))
            print(f"[+] Function 08: TID=0x{trans_id:04x}, Data={diag_data.hex()}")

# 3. 提取 Transaction ID 低字节
trans_ids = []
for pkt in packets:
    if TCP in pkt and len(pkt[TCP].payload) > 0:
        payload = bytes(pkt[TCP].payload)
        if len(payload) >= 2:
            trans_id = int.from_bytes(payload[0:2], 'big')
            trans_ids.append(trans_id)

# 尝试解码 Transaction ID 低字节
low_bytes = [tid & 0xFF for tid in trans_ids]
ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in low_bytes)
print(f"\n[*] Transaction ID 低字节 ASCII: {ascii_str}")

# 4. 提取寄存器值
register_values = []
for pkt in packets:
    if TCP in pkt and len(pkt[TCP].payload) > 0:
        payload = bytes(pkt[TCP].payload)
        if len(payload) > 9:
            func_code = payload[7]
            if func_code in [0x03, 0x04]:  # Read Holding/Input Registers
                data = payload[8:]
                if len(data) > 1:
                    byte_count = data[0]
                    register_data = data[1:]
                    # 按 16 位分组
                    for i in range(0, len(register_data), 2):
                        if i + 1 < len(register_data):
                            reg_val = int.from_bytes(register_data[i:i+2], 'big')
                            register_values.append(reg_val)

# 提取寄存器高低字节
reg_high = [(v >> 8) & 0xFF for v in register_values]
reg_low = [v & 0xFF for v in register_values]

print(f"\n[*] 寄存器高字节 ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in reg_high[:100])}")
print(f"[*] 寄存器低字节 ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in reg_low[:100])}")

# 5. 搜索密钥和密文
# 常见模式: 密钥在正常响应中，密文在 Function 08 中
for pkt in packets:
    if TCP in pkt and len(pkt[TCP].payload) > 0:
        payload = bytes(pkt[TCP].payload)
        # 搜索可疑字符串（可能是密钥）
        if b'S7COMM' in payload or b'KEY' in payload or b'PASS' in payload:
            print(f"\n[!!!] 发现可疑字符串: {payload}")
```

#### 典型案例：Modbus Diagnostics 隐蔽通道

```yaml
攻击场景:
  - 攻击者控制一台主机，伪装成合法 PLC 客户端
  - 使用 Function 08 (Diagnostics) 进行数据外传
  - 所有报文都符合 Modbus 协议规范
  - 基于规则的防火墙无法检测

识别特征:
  1. 非标准主机访问 PLC（IP 地址异常）
  2. Function 08 报文数量异常增多
  3. Diagnostics 数据长度不固定（正常应该是固定模式）
  4. Transaction ID 出现非递增模式
  5. 数据中包含高熵内容（加密/编码数据）

解题步骤:
  1. 统计所有 Modbus 客户端 IP，找出异常 IP
  2. 提取该 IP 的所有 Function 08 报文
  3. 在正常流量中搜索密钥（常见字符串: S7COMM, KEY, PASS）
  4. 提取 Function 08 中的数据块（通常是固定长度，如 8 字节）
  5. 使用找到的密钥解密（常见算法: DES, AES, XOR）
  6. 注意去重：请求和响应可能包含相同数据

常见加密:
  - DES-ECB: 8 字节密钥，8 字节分组
  - AES-ECB: 16/24/32 字节密钥，16 字节分组
  - XOR: 任意长度密钥
  - Base64: 编码而非加密
```

#### 其他工控协议

```yaml
S7Comm (Siemens S7):
  - 端口: 102
  - 隐写点: Job 数据区、Parameter 字段
  - 分析: tshark -r traffic.pcap -Y "s7comm"

DNP3:
  - 端口: 20000
  - 隐写点: Application Layer 数据
  - 分析: tshark -r traffic.pcap -Y "dnp3"

IEC 60870-5-104:
  - 端口: 2404
  - 隐写点: ASDU 数据区
  - 分析: tshark -r traffic.pcap -Y "iec60870_104"

OPC UA:
  - 端口: 4840
  - 隐写点: ExtensionObject 数据
  - 分析: tshark -r traffic.pcap -Y "opcua"
```

#### 防御检测思路

```yaml
异常检测指标:
  1. 非标准客户端 IP 访问
  2. Function Code 分布异常（大量 Function 08）
  3. Transaction ID 非递增模式
  4. 数据熵异常（加密数据熵高）
  5. 访问模式异常（非周期性轮询）
  6. 寄存器地址访问模式异常
  7. 数据长度分布异常

检测脚本:
  - 统计 Function Code 分布
  - 分析 Transaction ID 序列
  - 计算数据熵值
  - 识别访问时间模式
```

## 脚本参考

详见 `scripts/usb_keyboard.py`

## 无工具替代方案

当没有 Wireshark/tshark 时：

### 纯 Python 替代 (使用 scapy)

```python
#!/usr/bin/env python3
"""使用 scapy 分析 pcap（pip install scapy）"""

from scapy.all import *

# 读取 pcap
packets = rdpcap('traffic.pcap')

# 1. 基础统计
print(f"Total packets: {len(packets)}")

# 2. 提取 HTTP 数据
for pkt in packets:
    if pkt.haslayer('Raw'):
        payload = pkt['Raw'].load
        if b'HTTP' in payload or b'GET' in payload or b'POST' in payload:
            print(payload.decode('utf-8', errors='ignore'))

# 3. 提取所有字符串
for pkt in packets:
    if pkt.haslayer('Raw'):
        data = pkt['Raw'].load
        # 搜索 flag
        if b'flag' in data.lower():
            print(f"[+] Found in packet: {data}")

# 4. TCP 流重组
sessions = packets.sessions()
for session, pkts in sessions.items():
    data = b''.join(bytes(p['Raw'].load) for p in pkts if p.haslayer('Raw'))
    if b'flag' in data.lower():
        print(f"[+] Session {session}: {data}")
```

### 无依赖 Python (手动解析)

```python
#!/usr/bin/env python3
"""无依赖 pcap 解析（仅适用于简单情况）"""

def parse_pcap_simple(filename):
    """简单提取 pcap 中的字符串"""
    with open(filename, 'rb') as f:
        data = f.read()
    
    # 提取可打印字符串
    result = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= 10:
                s = ''.join(current)
                if 'flag' in s.lower() or 'http' in s.lower():
                    result.append(s)
            current = []
    return result

# 使用
strings = parse_pcap_simple('traffic.pcap')
for s in strings:
    print(s)
```

### 在线工具替代

```yaml
PCAP 分析:
  - https://apackets.com/ - 在线 PCAP 分析
  - https://www.cloudshark.org/ - 云端 Wireshark
  - https://packettotal.com/ - 流量分析

文件提取:
  - 将 pcap 上传到在线分析工具
  - 使用 NetworkMiner (Windows GUI)
```

### 系统自带命令

```bash
# tcpdump (通常预装)
tcpdump -r traffic.pcap -A | grep -i flag
tcpdump -r traffic.pcap -X | head -100

# 字符串搜索
strings traffic.pcap | grep -iE "flag|password|user"

# hexdump 查看
hexdump -C traffic.pcap | head -50
```

## Wireshark 过滤器速查

```
# HTTP
http.request.method == "POST"
http contains "flag"

# DNS
dns.qry.name contains "ctf"

# FTP
ftp.request.command == "PASS"

# USB
usb.capdata

# TCP 端口
tcp.port == 8080

# 包含特定字符串
frame contains "flag"
```
