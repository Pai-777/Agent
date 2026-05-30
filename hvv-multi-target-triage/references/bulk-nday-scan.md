# 批量 N-day 锁定策略

## 目标

在大批量目标中，先用 **低噪声、限速、定向** 的方式做一轮 N-day 锁定：

- 不追求一次打穿
- 不追求全库覆盖
- 只追求尽快找出“值得交给 `hvv-full-auto` 深打”的目标

## 输入前置

推荐输入不是裸 `targets.txt`，而是：
- `normalized_targets.jsonl`
- `fingerprinted_targets.jsonl`

尤其优先吃 `scripts/nuclei_fingerprint.py` 的输出，因为其中已经包含：
- `technologies`
- `candidate_products`
- `exposed_panels`
- `exposure_hits`
- `recommended_nuclei_tags`

## 核心原则

1. **不全量跑模板库**
2. **先看 nuclei 识别结果，再选漏洞模板**
3. **先高信号产品，再高信号 tags**
4. **先单模板 / 小模板集，再泛化 tags**
5. **默认限速、分批、低并发**
6. **命中后立刻交给总控 Skill 深打**

## 推荐模板来源

### 1. 产品 / 组件定向模板

优先按：
- `candidate_products`
- `technologies`
- `exposed_panels`
- `matched_templates`
- `matched_paths`

例如：
- `dedecms`
- `thinkphp`
- `weblogic`
- `tomcat`
- `shiro`
- `jenkins`
- `gitlab`
- `harbor`
- `grafana`
- `nacos`
- `phpmyadmin`
- `zabbix`

### 2. 高信号 tags

当产品指纹不够明确时，可跑极小 tags 集：
- `rce`
- `sqli`
- `lfi`
- `traversal`
- `default-login`
- `auth-bypass`
- `file-upload`
- `exposure`
- `panel`

## 默认限制

建议默认：
- `severity=medium,high,critical`
- `rate-limit=80~150`
- `concurrency=20~40`
- `chunk-size=100~300`
- 排除：
  - `dos`
  - `fuzz`
  - `bruteforce`
  - `tech`
  - `ssl`
  - `headless`

## 推荐脚本

- `scripts/bulk_nuclei_lock.py`

示例：

```powershell
python .\scripts\bulk_nuclei_lock.py .\normalized_targets.jsonl `
  --metadata .\triage_out\fingerprinted_targets.jsonl `
  --output-dir .\triage_out `
  --rate-limit 120 `
  --concurrency 30 `
  --chunk-size 200
```

## 命中后的处理

命中后不要在批量阶段继续深挖，直接回流 `hvv-full-auto`：

- SQLi 迹象 → 走 SQLi 工作流
- 上传 / 文件写入 → 走上传 / RCE 工作流
- 默认口令 / 后台暴露 → 先登录态验证
- 配置暴露 / Swagger / `.git` / `phpinfo` → 继续扩路径、接口、凭据和利用链
