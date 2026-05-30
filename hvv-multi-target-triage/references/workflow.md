# 多目标分诊总体流程

## 推荐固定链

1. 导入资产
2. 归一化与去重
3. nuclei 识别层
4. 识别结果整理与产品映射
5. 聚类与样本优先
6. 定向批量 N-day 锁定
7. 评分与 Top N 分发
8. 回流 `hvv-full-auto` 深打
9. 仅在必要时补 fallback 识别

## 1. 导入

- 读取 TXT / CSV / Excel / JSONL
- 去掉空行、注释、无效主机

## 2. 归一化

- 统一 URL / 域名 / IP / 端口
- 去重
- 生成 `canonical_key`

## 3. nuclei 识别层

默认优先：
- `http/technologies`
- `http/exposed-panels`
- 精选 `http/exposures`

产出：
- `matched_templates`
- `technologies`
- `candidate_products`
- `exposed_panels`
- `exposure_hits`
- `recommended_nuclei_tags`

## 4. 识别结果整理与产品映射

根据 nuclei 识别结果补：
- 行业标签
- 系统标签
- 高价值标签
- 推荐 N-day tags

## 5. 聚类

优先按：
- title
- server
- favicon_hash
- technologies
- candidate_products

## 6. 样本优先

- 每簇先取 1~3 个样本
- 样本命中后再扩同簇
- 禁止整簇盲打

## 7. 定向批量 N-day 锁定

- 根据 `recommended_nuclei_tags` / `candidate_products` / `exposed_panels` 选择单模板或小模板集
- 只跑 `medium,high,critical`
- 默认限速、限并发、分批次

输出：
- `nuclei_raw.jsonl`
- `nuclei_hits.jsonl`
- `nday_locked_targets.jsonl`

## 8. Top N 分发

- P1 → 立刻回流 `hvv-full-auto`
- P2 → 排队验证
- P3 → 归档

## 9. fallback 补充识别

仅在以下情况启用：
- nuclei 没识别出产品
- 需要 `robots.txt` / 登录口 / favicon / generator
- 需要补路径证据给 SQLi / 上传 / 后台验证工作流
