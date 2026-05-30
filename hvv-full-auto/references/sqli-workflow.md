# SQL 注入工作流

## 触发条件

满足任一条件就切进来：
- 参数加 `'` 出错；
- 布尔判断出现页面差异；
- 时间延迟成立；
- 用户指出某路径/参数高度可疑；
- 指纹产品 + 路径 + 参数命中现成 POC。

## Step 1：手工最小验证

优先少量请求确认类型，不要一上来全自动。

### 常用试探
- `'`
- `and 1=1`
- `and 1=2`
- `order by 100`
- `sleep(5)` / `benchmark()`（只在必要时）

### 观察点
- SQL 报错信息；
- 500 / 200 差异；
- 页面内容差异；
- 响应时间变化；
- 是否存在过滤/WAF。

## Step 2：一旦成立，优先 sqlmap

### GET 型
使用 `sqlmap_scan`，URL 带完整参数，必要时用 `additional_args` 指定参数名和策略。

推荐参数模板：
```text
--batch -p <param> --level 3 --risk 2 --threads 4 --banner --current-db
```

深挖模板：
```text
--batch -p <param> --dbs
--batch -p <param> -D <db> --tables
--batch -p <param> -D <db> -T <table> --columns
--batch -p <param> -D <db> -T <table> --dump
```

### POST 型
把 `data` 明确传给 `sqlmap_scan`，并指定：
```text
--batch -p <param> --method POST --risk 2 --level 3
```

## Step 3：利用产出优先级

优先拿：
1. 后台账号密码；
2. 数据库名、表名、CMS 关键配置；
3. 文件写能力；
4. Web 根路径；
5. 管理员 Session / token（如适用）。

## Step 4：与后台工作流衔接

一旦从 SQLi 拿到：
- 用户名/密码；
- 后台路径；
- CMS 指纹；
- 文件写路径；

应立即：
1. Chrome MCP 登录后台；
2. 寻找文件管理器、模板编辑器、附件管理、插件上传；
3. 优先走最短 getshell 链。

## 手工与自动的切换规则

- 报错型、数据量小、只想拿一个值：手工也可直接取；
- 需要系统化跑库、跑表、枚举字段：优先 `sqlmap`；
- 用户已经明确点出注入参数时，不要忽略，直接验证。
