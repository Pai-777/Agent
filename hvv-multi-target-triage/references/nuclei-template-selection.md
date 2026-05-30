# nuclei 模板选择规则

## 总原则

1. 先看 nuclei 识别结果
2. 再看产品 / 组件 / 版本
3. 再看路径特征与暴露面
4. 最后只跑单模板或极小模板集

## 识别层与漏洞层要分开

### 识别层（允许大池优先跑）

这层是为了知道“这是什么东西”，不是为了直接打洞：
- `http/technologies`
- `http/exposed-panels`
- 精选 `http/exposures`

### 漏洞层（只对已识别目标定向跑）

这层才是 N-day 锁定与验证：
- 按 `candidate_products`
- 按 `recommended_nuclei_tags`
- 按命中的后台路径 / 暴露路径 / 登录面板
- 按已知 CVE / 本地 POC

## 批量场景推荐顺序

1. `normalize_targets.py`
2. `nuclei_fingerprint.py`
3. 从 `fingerprinted_targets.jsonl` 读取产品 / 面板 / 暴露结果
4. `bulk_nuclei_lock.py` 做定向批量 N-day 锁定
5. 命中目标回流 `hvv-full-auto`

## 常见选择方式

### CMS / OA / 门户
- 用产品名、后台路径、已知 CVE 检索
- 如：`dedecms`、`thinkphp`、`seeyon`、`weaver`、`landray`

### Java / 中间件
- 用组件名、header、错误页、默认路径
- 如：`shiro`、`weblogic`、`tomcat`、`spring`、`struts`

### 运维 / 云控 / 安全面板
- 用登录页标题、面板模板、favicon、路径
- 如：`jenkins`、`gitlab`、`harbor`、`grafana`、`nacos`、`zabbix`

### 配置暴露 / 文件暴露 / API 暴露
- 用 `exposure_hits` 再扩展同类模板
- 如：`swagger-api`、`git-config`、`phpinfo-files`、`.env` 类模板

## 推荐实操

### 1. 先用 rg 在模板库中精搜

```powershell
rg -n -i "dedecms|recommend.php|CVE-2017-17731" "C:\Users\pai\nuclei-templates"
rg -n -i "jenkins|gitlab|grafana|nacos|phpmyadmin|zabbix" "C:\Users\pai\nuclei-templates"
rg -n -i "swagger|git-config|phpinfo|env" "C:\Users\pai\nuclei-templates\http\exposures"
```

### 2. 再选择：
- 单模板
- 极小模板集
- 必要时才使用小 tags 集

## 禁止项

- 禁止对 5000 目标全量跑 `C:\Users\pai\nuclei-templates`
- 禁止不读识别结果就机械跑 tags
- 禁止把 fallback 探针当主识别层
