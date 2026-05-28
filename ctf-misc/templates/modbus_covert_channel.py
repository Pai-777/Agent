#!/usr/bin/env python3
"""
Modbus 隐蔽通道分析模板
适用于工控流量中的数据隐写和隐蔽通道检测

使用场景:
1. CTF 工控安全题目
2. Modbus/TCP 流量分析
3. 隐蔽通道检测

分析思路:
1. 识别异常客户端（非标准 IP）
2. 提取 Function 08 (Diagnostics) 报文
3. 搜索密钥（在正常响应中）
4. 提取密文（在 Function 08 数据区）
5. 解密并提取 FLAG
"""

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("[!] 需要安装 scapy: pip install scapy")
    exit(1)

try:
    from Crypto.Cipher import DES, AES
except ImportError:
    print("[!] 需要安装 pycryptodome: pip install pycryptodome")
    exit(1)

import base64

# ============================================================================
# 配置区
# ============================================================================

PCAP_FILE = "challenge/challenge.pcapng"  # PCAP 文件路径
MODBUS_PORT = 502                          # Modbus 端口
SUSPICIOUS_TIDS = set()                    # 可疑的 Transaction IDs（如果已知）
KEY_MARKER = None                          # 密钥标记（如果已知）

# ============================================================================
# 工具函数
# ============================================================================

def pkcs5_unpad(data):
    """去除 PKCS#5 padding"""
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 8 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data

def try_decrypt(ciphertext, key, algorithm='DES', mode='ECB'):
    """尝试解密"""
    try:
        if algorithm == 'DES':
            if mode == 'ECB':
                cipher = DES.new(key, DES.MODE_ECB)
            elif mode == 'CBC':
                iv = ciphertext[:8]
                cipher = DES.new(key, DES.MODE_CBC, iv)
                ciphertext = ciphertext[8:]
        elif algorithm == 'AES':
            if mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
            elif mode == 'CBC':
                iv = ciphertext[:16]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                ciphertext = ciphertext[16:]
        else:
            return None
        
        plaintext = cipher.decrypt(ciphertext)
        plaintext = pkcs5_unpad(plaintext)
        
        # 尝试解码为文本
        try:
            text = plaintext.decode('ascii')
            if 'flag' in text.lower():
                return text
        except:
            pass
        
        return plaintext
    except Exception as e:
        return None

def xor_decrypt(data, key):
    """XOR 解密"""
    if isinstance(key, str):
        key = key.encode()
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)

# ============================================================================
# 主分析流程
# ============================================================================

def main():
    print(f"[*] 读取 PCAP 文件: {PCAP_FILE}")
    packets = rdpcap(PCAP_FILE)
    print(f"[+] 总数据包数: {len(packets)}")
    
    # ========================================================================
    # Step 1: 识别 Modbus 客户端
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"[*] Step 1: 识别 Modbus 客户端")
    print(f"{'='*60}")
    
    client_stats = {}
    for pkt in packets:
        if TCP in pkt and IP in pkt and pkt[TCP].dport == MODBUS_PORT:
            src = pkt[IP].src
            client_stats[src] = client_stats.get(src, 0) + 1
    
    print(f"\n[*] Modbus 客户端统计:")
    for ip, count in sorted(client_stats.items(), key=lambda x: x[1]):
        print(f"    {ip}: {count} 个请求")
    
    # 识别异常客户端（请求数量少的可能是隐蔽通道）
    if len(client_stats) > 1:
        suspicious_ips = [ip for ip, count in client_stats.items() 
                         if count < max(client_stats.values()) / 10]
        if suspicious_ips:
            print(f"\n[!] 可疑客户端 IP: {suspicious_ips}")
    
    # ========================================================================
    # Step 2: 分析 Function Code 分布
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"[*] Step 2: 分析 Function Code 分布")
    print(f"{'='*60}")
    
    func_code_stats = {}
    for pkt in packets:
        if TCP in pkt and len(pkt[TCP].payload) > 0:
            payload = bytes(pkt[TCP].payload)
            if len(payload) >= 8:
                proto_id = int.from_bytes(payload[2:4], 'big')
                if proto_id == 0:  # Modbus
                    func_code = payload[7]
                    func_code_stats[func_code] = func_code_stats.get(func_code, 0) + 1
    
    print(f"\n[*] Function Code 统计:")
    for fc, count in sorted(func_code_stats.items()):
        fc_name = {
            0x01: "Read Coils",
            0x03: "Read Holding Registers",
            0x04: "Read Input Registers",
            0x08: "Diagnostics",
            0x10: "Write Multiple Registers"
        }.get(fc, "Unknown")
        print(f"    0x{fc:02x} ({fc_name}): {count} 个")
    
    # ========================================================================
    # Step 3: 搜索密钥
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"[*] Step 3: 搜索密钥")
    print(f"{'='*60}")
    
    possible_keys = []
    for pkt in packets:
        if TCP in pkt and len(pkt[TCP].payload) > 0:
            payload = bytes(pkt[TCP].payload)
            
            # 搜索常见密钥模式
            for pattern in [b'KEY', b'PASS', b'S7COMM', b'SECRET', b'DES', b'AES']:
                if pattern in payload:
                    # 提取密钥（假设是 8 或 16 字节）
                    idx = payload.find(pattern)
                    for key_len in [8, 16, 24, 32]:
                        if idx + key_len <= len(payload):
                            key = payload[idx:idx+key_len]
                            if key not in possible_keys:
                                possible_keys.append(key)
                                print(f"[+] 发现可能的密钥: {key} (hex: {key.hex()})")
    
    if not possible_keys:
        print(f"[!] 未找到明显的密钥，尝试从数据中提取...")
    
    # ========================================================================
    # Step 4: 提取 Function 08 数据
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"[*] Step 4: 提取 Function 08 (Diagnostics) 数据")
    print(f"{'='*60}")
    
    func08_blocks = {}  # 使用字典去重
    for pkt in packets:
        if TCP in pkt and len(pkt[TCP].payload) > 0:
            payload = bytes(pkt[TCP].payload)
            if len(payload) >= 8:
                proto_id = int.from_bytes(payload[2:4], 'big')
                if proto_id == 0:  # Modbus
                    trans_id = int.from_bytes(payload[0:2], 'big')
                    func_code = payload[7]
                    
                    if func_code == 0x08:
                        diag_data = payload[10:] if len(payload) > 10 else b''
                        
                        # 只保存固定长度的数据块（通常是 8 或 16 字节）
                        if len(diag_data) in [8, 16, 24, 32]:
                            if trans_id not in func08_blocks:
                                func08_blocks[trans_id] = diag_data
                                print(f"[+] TID 0x{trans_id:04x}: {diag_data.hex()} ({len(diag_data)} bytes)")
    
    print(f"\n[+] 找到 {len(func08_blocks)} 个唯一的 Function 08 数据块")
    
    # ========================================================================
    # Step 5: 提取其他可能的隐写位置
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"[*] Step 5: 分析其他隐写位置")
    print(f"{'='*60}")
    
    # Transaction ID 低字节
    trans_ids = []
    for pkt in packets:
        if TCP in pkt and len(pkt[TCP].payload) > 0:
            payload = bytes(pkt[TCP].payload)
            if len(payload) >= 2:
                proto_id = int.from_bytes(payload[2:4], 'big')
                if proto_id == 0:
                    trans_id = int.from_bytes(payload[0:2], 'big')
                    trans_ids.append(trans_id)
    
    if trans_ids:
        low_bytes = [tid & 0xFF for tid in trans_ids[:100]]
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in low_bytes)
        print(f"\n[*] Transaction ID 低字节 (前100个): {ascii_str}")
    
    # 寄存器值
    register_values = []
    for pkt in packets:
        if TCP in pkt and len(pkt[TCP].payload) > 0:
            payload = bytes(pkt[TCP].payload)
            if len(payload) > 9:
                proto_id = int.from_bytes(payload[2:4], 'big')
                if proto_id == 0:
                    func_code = payload[7]
                    if func_code in [0x03, 0x04]:
                        data = payload[8:]
                        if len(data) > 1:
                            register_data = data[1:]
                            for i in range(0, len(register_data), 2):
                                if i + 1 < len(register_data):
                                    reg_val = int.from_bytes(register_data[i:i+2], 'big')
                                    register_values.append(reg_val)
    
    if register_values:
        reg_high = [(v >> 8) & 0xFF for v in register_values[:100]]
        reg_low = [v & 0xFF for v in register_values[:100]]
        print(f"\n[*] 寄存器高字节 (前100个): {''.join(chr(b) if 32 <= b < 127 else '.' for b in reg_high)}")
        print(f"[*] 寄存器低字节 (前100个): {''.join(chr(b) if 32 <= b < 127 else '.' for b in reg_low)}")
    
    # ========================================================================
    # Step 6: 尝试解密
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"[*] Step 6: 尝试解密")
    print(f"{'='*60}")
    
    if func08_blocks and possible_keys:
        # 拼接密文
        sorted_tids = sorted(func08_blocks.keys())
        ciphertext = b''.join(func08_blocks[tid] for tid in sorted_tids)
        
        print(f"\n[*] 密文 ({len(ciphertext)} bytes): {ciphertext.hex()}")
        
        # 尝试所有密钥和算法组合
        for key in possible_keys:
            print(f"\n[*] 尝试密钥: {key} (hex: {key.hex()})")
            
            # DES-ECB
            if len(key) == 8:
                result = try_decrypt(ciphertext, key, 'DES', 'ECB')
                if result:
                    print(f"[+] DES-ECB 解密成功!")
                    if isinstance(result, str):
                        print(f"[!!!] FLAG: {result}")
                    else:
                        print(f"    结果 (hex): {result.hex()}")
                        print(f"    结果 (ascii): {result.decode('ascii', errors='ignore')}")
            
            # AES-ECB
            if len(key) in [16, 24, 32]:
                result = try_decrypt(ciphertext, key, 'AES', 'ECB')
                if result:
                    print(f"[+] AES-ECB 解密成功!")
                    if isinstance(result, str):
                        print(f"[!!!] FLAG: {result}")
                    else:
                        print(f"    结果 (hex): {result.hex()}")
                        print(f"    结果 (ascii): {result.decode('ascii', errors='ignore')}")
            
            # XOR
            result = xor_decrypt(ciphertext, key)
            try:
                text = result.decode('ascii', errors='ignore')
                if 'flag' in text.lower():
                    print(f"[+] XOR 解密成功!")
                    print(f"[!!!] FLAG: {text}")
            except:
                pass
    
    print(f"\n{'='*60}")
    print(f"[*] 分析完成")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
