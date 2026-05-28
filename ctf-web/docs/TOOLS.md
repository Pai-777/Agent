# CTF Web Skill - 工具安装指南

## 必备工具

### 1. Burp Suite

```bash
# 下载
# https://portswigger.net/burp/communitydownload

# Linux 安装
chmod +x burpsuite_community_linux_xxx.sh
./burpsuite_community_linux_xxx.sh

# 配置浏览器代理
# 127.0.0.1:8080
```

### 2. sqlmap

```bash
# 使用 pip 安装
pip install sqlmap

# 或从 GitHub
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py -h

# 基本使用
sqlmap -u "http://target.com/?id=1" --dbs
```

### 3. 目录扫描工具

```bash
# dirsearch
pip install dirsearch
dirsearch -u http://target.com

# gobuster
go install github.com/OJ/gobuster/v3@latest
gobuster dir -u http://target.com -w wordlist.txt

# ffuf
go install github.com/ffuf/ffuf@latest
ffuf -u http://target.com/FUZZ -w wordlist.txt
```

### 4. XSStrike

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py -u "http://target.com/?param=test"
```

### 5. tplmap (SSTI)

```bash
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip install -r requirements.txt
python tplmap.py -u "http://target.com/?name=test"
```

### 6. ysoserial (Java 反序列化)

```bash
# 下载
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# 使用
java -jar ysoserial-all.jar CommonsCollections1 "id" > payload.bin
```

### 7. phpggc (PHP 反序列化)

```bash
git clone https://github.com/ambionics/phpggc.git
cd phpggc
./phpggc -l  # 列出可用链
./phpggc Laravel/RCE1 system id
```

### 8. jwt_tool

```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip install -r requirements.txt
python jwt_tool.py <JWT>
```

### 9. Gopherus (SSRF)

```bash
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus
chmod +x gopherus.py
python gopherus.py --exploit redis
```

### 10. Nuclei

```bash
# 安装
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# 更新模板
nuclei -ut

# 使用
nuclei -u http://target.com
nuclei -u http://target.com -t cves/
```

## Python 库

```bash
# 基础库
pip install requests beautifulsoup4 lxml

# Web 安全库
pip install pycryptodome  # 加密
pip install pyjwt         # JWT
pip install web3          # 区块链

# 其他
pip install colorama      # 彩色输出
pip install tqdm          # 进度条
```

## 在线工具

### 编码解码
- [CyberChef](https://gchq.github.io/CyberChef/) - 万能编码工具
- [jwt.io](https://jwt.io/) - JWT 解码
- [Base64](https://www.base64decode.org/)

### 漏洞检测
- [Aperi'Solve](https://www.aperisolve.com/) - 隐写分析
- [RequestBin](https://requestbin.net/) - HTTP 请求记录
- [Webhook.site](https://webhook.site/) - 回调接收

### 信息搜集
- [Shodan](https://www.shodan.io/) - 网络设备搜索
- [Censys](https://search.censys.io/) - 互联网扫描
- [crt.sh](https://crt.sh/) - SSL 证书查询

### CVE 查询
- [Exploit-DB](https://www.exploit-db.com/)
- [NVD](https://nvd.nist.gov/)
- [CVE Details](https://www.cvedetails.com/)

## Docker 环境

```bash
# 漏洞靶场
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa

# Vulhub (各种 CVE 环境)
git clone https://github.com/vulhub/vulhub.git
cd vulhub/struts2/s2-045
docker-compose up -d

# 常用工具容器
docker pull kalilinux/kali-rolling
docker run -it kalilinux/kali-rolling /bin/bash
```

## 无工具替代方案

当无法安装工具时：

### SQL 注入
```python
# 使用 Python + requests
import requests
url = "http://target.com/?id=1'"
print(requests.get(url).text)
```

### 目录扫描
```python
import requests
wordlist = ['admin', 'backup', 'config', 'upload']
for word in wordlist:
    url = f"http://target.com/{word}"
    resp = requests.get(url)
    if resp.status_code == 200:
        print(f"Found: {url}")
```

### 编码解码
```python
import base64
# Base64
encoded = base64.b64encode(b"test").decode()
decoded = base64.b64decode("dGVzdA==").decode()

# URL 编码
from urllib.parse import quote, unquote
encoded = quote("test'or 1=1--")
decoded = unquote("%27")
```

## 字典资源

```bash
# SecLists
git clone https://github.com/danielmiessler/SecLists.git

# 常用字典路径
/usr/share/wordlists/dirbuster/
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/

# 在线字典
# https://github.com/danielmiessler/SecLists
# https://github.com/fuzzdb-project/fuzzdb
```

