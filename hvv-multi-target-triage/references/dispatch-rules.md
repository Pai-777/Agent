# 分发与样本簇策略

## 样本优先

每个簇先选 1~3 个样本，优先条件：
- nuclei 识别结果最完整
- 标题最完整
- 响应最稳定
- 路径暴露最多
- 登录口 / 后台口最明显

## 分发层级

### P1：立即深打

满足任一即可：
- 高价值系统 + 命中产品 / 面板识别
- 命中 `nday_locked_targets.jsonl`
- 后台、上传、SQLi、配置暴露等证据明显
- 同簇样本已经命中且该目标属于同类资产

### P2：排队验证

- 价值高但漏洞证据不足
- 识别出高价值产品，但还没命中漏洞模板
- 同簇样本已命中，但本目标仍需二次确认

### P3：记录即可

- 静态站
- 无有效识别结果
- 低价值重复站
- 成本高但现阶段价值一般

## 回流给 `hvv-full-auto` 的字段

至少保留：
- target
- host
- scheme
- port
- title
- server
- favicon_hash
- technologies
- candidate_products
- exposed_panels
- exposure_hits
- sector_tags
- system_tags
- leak_paths
- matched_templates
- final_score
- reasons
