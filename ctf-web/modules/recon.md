# 信息搜集模块

## 适用场景
- 渗透测试前期侦察
- CTF Web 题目初始信息收集
- 目标技术栈识别

## 检查清单

```yaml
基础信息:
  - [ ] HTTP 响应头分析（Server/X-Powered-By）
  - [ ] 技术栈识别（whatweb/wappalyzer）
  - [ ] 端口扫描（nmap）
  - [ ] 子域名枚举
  - [ ] 目录扫描

敏感文件:
  - [ ] robots.txt
  - [ ] .git 泄露
  - [ ] .svn 泄露
  - [ ] DS_Store 泄露
  - [ ] 备份文件（.bak/.swp/.zip）
  - [ ] 配置文件（web.xml/config.php）

信息泄露:
  - [ ] 源码注释
  - [ ] JS 文件分析
  - [ ] API 接口发现
  - [ ] 错误信息泄露
  - [ ] 版本号泄露

常用工具:
  - nmap, masscan (端口扫描)
  - dirsearch, gobuster, ffuf (目录扫描)
  - whatweb, wappalyzer (技术栈识别)
  - subfinder, amass (子域名枚举)
  - GitHacker, dvcs-ripper (源码泄露)
```

## 分析流程

### Step 1: 基础信息收集

```bash
# HTTP 响应头
curl -I http://target.com

# 详细响应（包含响应体）
curl -v http://target.com

# 技术栈识别
whatweb http://target.com
whatweb -v http://target.com  # 详细模式

# 在线识别
# https://www.wappalyzer.com/
# https://builtwith.com/
```

### Step 2: 端口扫描

```bash
# 快速扫描常用端口
nmap -F target.com

# 全端口扫描
nmap -p- target.com

# 服务识别
nmap -sV -sC target.com

# 漏洞扫描
nmap --script=vuln target.com

# UDP 扫描
nmap -sU --top-ports 100 target.com

# 绕过防火墙
nmap -Pn -f target.com
nmap -D RND:10 target.com  # 诱饵扫描
```

### Step 3: 目录扫描

```bash
# dirsearch（推荐）
dirsearch -u http://target.com -e php,html,txt,bak,zip
dirsearch -u http://target.com -w /path/to/wordlist.txt

# gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target.com -w wordlist.txt -x php,txt,html

# ffuf（高性能）
ffuf -u http://target.com/FUZZ -w wordlist.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt -e .php,.txt,.html
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302

# feroxbuster（递归扫描）
feroxbuster -u http://target.com -w wordlist.txt
```

### Step 4: 敏感文件探测

```bash
# robots.txt
curl http://target.com/robots.txt

# .git 泄露检测
curl http://target.com/.git/HEAD
curl http://target.com/.git/config
# 如果存在，使用 GitHacker 提取
python3 GitHacker.py http://target.com/.git/

# .svn 泄露
curl http://target.com/.svn/entries
curl http://target.com/.svn/wc.db

# DS_Store 泄露
curl http://target.com/.DS_Store
# 使用 ds_store_exp 解析
python3 ds_store_exp.py http://target.com/.DS_Store

# 备份文件
curl http://target.com/www.zip
curl http://target.com/www.tar.gz
curl http://target.com/backup.sql
curl http://target.com/web.zip
curl http://target.com/1.zip

# vim 临时文件
curl http://target.com/.index.php.swp
curl http://target.com/index.php~
curl http://target.com/index.php.bak

# 配置文件
curl http://target.com/web.xml
curl http://target.com/WEB-INF/web.xml
curl http://target.com/config.php.bak
```

### Step 5: 子域名枚举

```bash
# subfinder
subfinder -d target.com

# amass
amass enum -d target.com

# 在线工具
# https://crt.sh/?q=%.target.com
# https://dnsdumpster.com/

# 暴力枚举
gobuster dns -d target.com -w subdomains.txt
wfuzz -c -w subdomains.txt -u http://target.com -H "Host: FUZZ.target.com"
```

### Step 6: JS 文件分析

```bash
# 提取页面中的 JS 链接
curl http://target.com | grep -oE '(src|href)="[^"]*\.js"'

# 使用 gau 收集所有 URL
gau target.com | grep "\.js$"

# 使用 LinkFinder 提取 JS 中的端点
python3 linkfinder.py -i http://target.com/app.js -o cli

# 使用 SecretFinder 查找敏感信息
python3 SecretFinder.py -i http://target.com/app.js -o cli

# JS 美化
js-beautify app.js
```

### Step 7: 历史信息收集

```bash
# Wayback Machine
waybackurls target.com | tee urls.txt

# gau（多源聚合）
gau target.com | tee all_urls.txt

# 过滤参数化 URL
cat urls.txt | grep "=" | sort -u

# 过滤特定文件类型
cat urls.txt | grep -E "\.php|\.asp|\.jsp"
```

## 常见出题套路与解法

### 套路 1: .git 源码泄露

**特征**: 访问 `/.git/HEAD` 返回 `ref: refs/heads/master`

**解法**:
```bash
# 使用 GitHacker
python3 GitHacker.py http://target.com/.git/

# 使用 git-dumper
git-dumper http://target.com/.git/ output_dir

# 查看历史提交
cd output_dir
git log --oneline
git diff HEAD~1
git show <commit_hash>
```

### 套路 2: .svn 源码泄露

**特征**: 访问 `/.svn/entries` 或 `/.svn/wc.db` 存在

**解法**:
```bash
# 使用 dvcs-ripper
perl rip-svn.pl -u http://target.com/.svn/

# 或手动下载
sqlite3 .svn/wc.db "select local_relpath from nodes"
```

### 套路 3: DS_Store 泄露

**特征**: 访问 `/.DS_Store` 返回二进制内容

**解法**:
```bash
# 下载并解析
curl http://target.com/.DS_Store -o .DS_Store
python3 ds_store_exp.py http://target.com/.DS_Store
```

### 套路 4: 备份文件泄露

**特征**: 常见备份文件名存在

**解法**:
```bash
# 常见备份文件
www.zip
www.tar.gz
backup.zip
backup.sql
web.rar
1.zip
filename.php.bak
filename.php~
.filename.php.swp
```

### 套路 5: WEB-INF 泄露

**特征**: Java Web 应用，可能泄露 web.xml

**解法**:
```bash
# 尝试访问
curl http://target.com/WEB-INF/web.xml
curl http://target.com/WEB-INF/classes/xxx.class

# Nginx 配置不当可能导致
# location /WEB-INF/ 未配置 deny
```

### 套路 6: 目录遍历

**特征**: 目录列表功能开启

**解法**:
```bash
# Nginx 目录遍历
http://target.com/files/

# Apache 目录遍历
http://target.com/upload/
```

### 套路 7: phpinfo 泄露

**特征**: `phpinfo.php` 或 `info.php` 存在

**解法**:
```bash
curl http://target.com/phpinfo.php
curl http://target.com/info.php
curl http://target.com/php.php
curl http://target.com/i.php

# 从 phpinfo 获取重要信息
# - PHP 版本
# - 禁用函数 (disable_functions)
# - 配置路径
# - 临时目录
```

### 套路 8: 错误信息泄露

**特征**: 错误页面显示详细信息

**解法**:
```bash
# 触发错误
curl "http://target.com/index.php?id='"
curl "http://target.com/index.php?id[]=1"

# 分析错误信息
# - 绝对路径
# - 数据库信息
# - 框架版本
```

## 信息搜集自动化脚本

```python
#!/usr/bin/env python3
"""
Web 信息搜集自动化脚本
"""

import requests
import re
from urllib.parse import urljoin

def recon(target_url):
    """基础信息搜集"""
    
    results = {
        'headers': {},
        'sensitive_files': [],
        'technologies': [],
        'endpoints': []
    }
    
    # 1. 响应头分析
    try:
        resp = requests.get(target_url, timeout=10)
        results['headers'] = dict(resp.headers)
        
        # 提取技术栈信息
        if 'Server' in resp.headers:
            results['technologies'].append(resp.headers['Server'])
        if 'X-Powered-By' in resp.headers:
            results['technologies'].append(resp.headers['X-Powered-By'])
            
    except Exception as e:
        print(f"[-] Error: {e}")
    
    # 2. 敏感文件检测
    sensitive_paths = [
        'robots.txt',
        '.git/HEAD',
        '.svn/entries',
        '.DS_Store',
        'web.xml',
        'WEB-INF/web.xml',
        'phpinfo.php',
        'info.php',
        'www.zip',
        'backup.zip',
        'config.php.bak'
    ]
    
    for path in sensitive_paths:
        url = urljoin(target_url, path)
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                results['sensitive_files'].append({
                    'path': path,
                    'size': len(resp.content),
                    'content_type': resp.headers.get('Content-Type', '')
                })
                print(f"[+] Found: {path}")
        except:
            pass
    
    # 3. 提取 JS 文件
    try:
        resp = requests.get(target_url)
        js_files = re.findall(r'src=["\']([^"\']*\.js)["\']', resp.text)
        for js in js_files:
            full_url = urljoin(target_url, js)
            results['endpoints'].append(full_url)
            print(f"[*] JS: {full_url}")
    except:
        pass
    
    return results

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 recon.py http://target.com")
        sys.exit(1)
    
    target = sys.argv[1]
    results = recon(target)
    
    print("\n[=== Results ===]")
    print(f"Technologies: {results['technologies']}")
    print(f"Sensitive Files: {len(results['sensitive_files'])}")
    for f in results['sensitive_files']:
        print(f"  - {f['path']}")
```

## 工具速查

```bash
# 基础信息
curl -I http://target.com        # 响应头
whatweb http://target.com        # 技术栈识别

# 端口扫描
nmap -sV -sC target.com          # 服务识别
masscan target.com -p1-65535     # 快速全端口

# 目录扫描
dirsearch -u http://target.com   # 目录扫描
ffuf -u http://target.com/FUZZ   # Fuzz 扫描

# 源码泄露
python3 GitHacker.py http://target.com/.git/  # Git 泄露
perl rip-svn.pl -u http://target.com/.svn/    # SVN 泄露

# 子域名
subfinder -d target.com          # 子域名枚举

# URL 收集
gau target.com                   # 历史 URL
```
