# 编码与加密分析模块

## 适用场景
- 纯文本编码字符串
- 多层嵌套编码
- 古典密码

## 检查清单

```yaml
编码识别优先级:
  1. Base64 / Base32 / Base58 / Base85
  2. Hex / Binary / Octal
  3. URL Encoding / HTML Entities
  4. ROT13 / ROT47 / Caesar 全枚举
  5. Morse / Bacon / 培根密码
  6. 栅栏密码 / 维吉尼亚（需要 key 或频率分析）
  7. 多层嵌套编码（递归解码）

识别技巧:
  - Base64: [A-Za-z0-9+/=] 且长度 %4==0
  - Base32: [A-Z2-7=] 大写为主
  - Hex: [0-9A-Fa-f] 且长度为偶数
  - Binary: 只有 0 和 1
  - Morse: 只有 . - 和空格
  - 如果解码结果仍像编码，继续递归
```

## 分析流程

### Step 1: 自动识别
```bash
# 使用 CyberChef 自动识别（推荐）
# https://gchq.github.io/CyberChef/

# 或使用脚本递归解码
python3 scripts/decode_multilayer.py encoded.txt
```

### Step 2: Base 系列
```python
import base64

# Base64
base64.b64decode(data)

# Base32
base64.b32decode(data)

# Base58 (需要 base58 库)
import base58
base58.b58decode(data)

# Base85
base64.b85decode(data)
```

### Step 3: 进制转换
```python
# Hex to bytes
bytes.fromhex(hex_string)

# Binary to bytes
int(binary_string, 2).to_bytes(length, 'big')

# Octal to bytes
int(octal_string, 8).to_bytes(length, 'big')
```

### Step 4: ROT / Caesar
```python
import codecs

# ROT13
codecs.decode(text, 'rot_13')

# Caesar 全枚举
for shift in range(26):
    result = ''.join(chr((ord(c) - 65 + shift) % 26 + 65) if c.isupper() 
                     else chr((ord(c) - 97 + shift) % 26 + 97) if c.islower() 
                     else c for c in text)
    print(f"Shift {shift}: {result}")
```

### Step 5: 古典密码
```bash
# 使用在线工具
# https://www.dcode.fr/

# 摩尔斯电码
# . = dit, - = dah
# 空格分隔字母，/ 分隔单词

# 培根密码
# A/B 两种字符，每 5 个一组
```

## 常见出题套路

1. **多层 Base64** → 递归解码直到出现可读文本
2. **Base64 + Hex** → 先 Base64 再 Hex
3. **ROT13 变体** → 尝试所有 shift
4. **URL 编码** → `urllib.parse.unquote()`
5. **HTML 实体** → `html.unescape()`
6. **混合编码** → CyberChef Magic 自动识别

## 在线工具推荐

- **CyberChef** - https://gchq.github.io/CyberChef/
  - Magic 功能可自动识别编码
  - 支持链式操作
  
- **dcode.fr** - https://www.dcode.fr/
  - 古典密码专家
  - 支持频率分析

## 无工具替代方案

编码解码完全可以用 Python 标准库完成：

### Python 标准库

```python
#!/usr/bin/env python3
"""纯 Python 标准库编码解码"""

import base64
import codecs
import urllib.parse
import html
import binascii

# 1. Base64 系列
def decode_base64(data):
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        return None

def decode_base32(data):
    try:
        return base64.b32decode(data).decode('utf-8', errors='ignore')
    except:
        return None

# 2. Hex
def decode_hex(data):
    try:
        return bytes.fromhex(data.replace(' ', '')).decode('utf-8', errors='ignore')
    except:
        return None

# 3. Binary
def decode_binary(data):
    try:
        binary = data.replace(' ', '')
        chars = [chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)]
        return ''.join(chars)
    except:
        return None

# 4. ROT13
def decode_rot13(data):
    return codecs.decode(data, 'rot_13')

# 5. Caesar 全枚举
def caesar_all(data):
    results = []
    for shift in range(26):
        result = ''
        for c in data:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result += chr((ord(c) - base + shift) % 26 + base)
            else:
                result += c
        results.append((shift, result))
    return results

# 6. URL 解码
def decode_url(data):
    return urllib.parse.unquote(data)

# 7. HTML 实体
def decode_html(data):
    return html.unescape(data)

# 8. 递归自动解码
def auto_decode(data, depth=0, max_depth=10):
    if depth > max_depth:
        return data
    
    # 尝试各种解码
    decoders = [
        ('base64', decode_base64),
        ('base32', decode_base32),
        ('hex', decode_hex),
        ('url', decode_url),
        ('html', decode_html),
        ('rot13', decode_rot13),
    ]
    
    for name, func in decoders:
        result = func(data)
        if result and result != data:
            print(f"[{depth}] {name}: {result[:50]}...")
            # 如果看起来还像编码，继续递归
            if any(c.isalpha() for c in result):
                return auto_decode(result, depth + 1)
            return result
    
    return data

# 使用
if __name__ == '__main__':
    import sys
    data = sys.argv[1] if len(sys.argv) > 1 else input("Enter encoded data: ")
    result = auto_decode(data)
    print(f"\n[Result] {result}")
```

### 在线工具替代

```yaml
万能工具:
  - https://gchq.github.io/CyberChef/ - 最强推荐，支持 Magic 自动识别
  - https://www.dcode.fr/ - 古典密码专家

Base 系列:
  - https://www.base64decode.org/ - Base64
  - https://emn178.github.io/online-tools/base32_decode.html - Base32

其他编码:
  - https://www.rapidtables.com/convert/number/hex-to-ascii.html - Hex
  - https://morsedecoder.com/ - 摩尔斯
  - https://www.rot13.com/ - ROT13
```

### 命令行快速解码

```bash
# Base64
echo "SGVsbG8=" | base64 -d

# Hex
echo "48656c6c6f" | xxd -r -p

# ROT13
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# URL 解码
python3 -c "import urllib.parse; print(urllib.parse.unquote('Hello%20World'))"

# 二进制转文本
python3 -c "print(''.join(chr(int(b,2)) for b in '01001000 01101001'.split()))"
```

## 脚本参考

详见 `scripts/decode_multilayer.py`

## 快速命令

```bash
# Base64 解码
echo "SGVsbG8=" | base64 -d

# Hex 解码
echo "48656c6c6f" | xxd -r -p

# URL 解码
python3 -c "import urllib.parse; print(urllib.parse.unquote('%48%65%6c%6c%6f'))"

# ROT13
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
