---
name: hvv-multi-target-triage
description: |
  HVV 多目标分诊与编排 Skill，用于处理几十到几千个 URL、域名、IP、CIDR 或资产清单。
  负责目标归一化、去重、nuclei 技术识别 / 面板识别 / 暴露识别、行业/系统分类、可利用性评分、样本聚类、定向批量 N-day 锁定与 Top N 深打分发。
  优先复用本地 nuclei / nuclei-templates 做识别与锁定；仅在识别不足或需要 robots/login/favicon 等补充证据时，才回退到轻量自写探针。
---

# HVV 多目标分诊与编排

## 目标

这个 Skill 的目标是：
- 在大批量目标场景下，先做 **分诊、聚类、识别、评分、排优先级**；
- 先用 **nuclei 现成识别层** 找出产品、组件、面板、暴露面，而不是一上来自己造扫描器；
- 把“最有价值、最可能命中 N-day、最值得交给 `hvv-full-auto` 深打”的目标挑出来；
- 避免把单目标深打逻辑粗暴平铺到几百或几千个目标上；
- 输出可直接回流到 `hvv-full-auto` 的 Top N 深打队列和 `nday_locked_targets.jsonl`。

## 输入类型

支持：
- URL 列表
- 域名列表
- IP 列表
- CIDR
- TXT / CSV / Excel 导出的资产清单
- 扫描结果表（包含标题、状态码、Server、body 片段等字段）

## 输出类型

至少输出：
1. 归一化目标清单
2. nuclei 识别结果
3. 聚类结果
4. 评分结果
5. Top N 深打队列
6. 批量 N-day 命中结果
7. Markdown 简报

推荐输出文件：
- `normalized_targets.jsonl`
- `nuclei_fingerprint_raw.jsonl`
- `fingerprinted_targets.jsonl`
- `clustered_targets.jsonl`
- `scored_targets.jsonl`
- `top_targets.jsonl`
- `nuclei_raw.jsonl`
- `nuclei_hits.jsonl`
- `nday_locked_targets.jsonl`
- `triage_summary.md`

## 总体原则

1. **先归一化，再识别，再锁定，再深打**
2. **优先复用 nuclei / nuclei-templates**，本地脚本只负责编排、整形、聚类、评分，不重复发明识别层
3. **先跑识别层，再映射 N-day**：先知道它是什么，再决定跑哪些模板
4. **先样本，再扩同簇**：每簇先验证 1~3 个样本，命中后再扩同类资产
5. **先单模板 / 小模板集，再大范围 tags**：禁止全库盲扫
6. **先高价值系统，再普通门户**：SSO / OA / VPN / 运维平台 / 教务 / HIS 等优先
7. **只有 nuclei 识别不足时才走 fallback**：如需要 `robots.txt`、登录口、favicon、generator 等补充字段，再使用轻量探针

## 工具基线

### 1. nuclei / nuclei-templates（主识别层 + 主锁定层）

默认本地路径：
- `C:\Users\pai\Desktop\tool\nuclei_3.8.0_windows_amd64\nuclei.exe`
- `C:\Users\pai\nuclei-templates`

优先使用的识别目录：
- `C:\Users\pai\nuclei-templates\http\technologies`
- `C:\Users\pai\nuclei-templates\http\exposed-panels`
- `C:\Users\pai\nuclei-templates\http\exposures` 中的**精选暴露模板**

说明：
- `http/technologies` 负责技术栈 / CMS / 中间件 / 面板产品识别
- `http/exposed-panels` 负责后台、登录面板、管理控制台暴露识别
- `http/exposures` 只挑高信号模板，不允许整目录全量跑
- `nuclei -as` 可作为补充，但更适合样本目标或小池目标，不作为 5000 目标默认首刀

### 2. 本地脚本（编排 / 整形 / 聚类 / 评分）

- `scripts/normalize_targets.py`
- `scripts/nuclei_fingerprint.py`
- `scripts/fingerprint_targets.py`（fallback，仅补充字段）
- `scripts/cluster_targets.py`
- `scripts/score_targets.py`
- `scripts/bulk_nuclei_lock.py`
- `scripts/select_topn.py`

### 3. Kali MCP

用于：
- 少量样本目标的端口探测
- 目录爆破 / 路由验证
- SQLi 命中后的 sqlmap 深挖
- nuclei 命中后的补充验证

### 4. Chrome MCP

用于：
- Top N 目标的人机交互验证
- 后台登录态验证
- 文件上传点、复杂表单、动态路由、编辑器、富文本场景验证
- 避免 PowerShell 吃 payload 的场景

## 工作流

### Phase A：目标导入与归一化

先做：
1. 删除空行、注释、明显无效项
2. 标准化协议、主机、端口、路径
3. 合并重复目标
4. 生成 `canonical_key`

优先脚本：
- `python .\scripts\normalize_targets.py .\targets.txt -o .\normalized_targets.jsonl`

### Phase B：nuclei 技术识别 / 面板识别 / 暴露识别

这是多目标场景的**主识别层**，默认优先于自写探针。

先跑：
1. `http/technologies`
2. `http/exposed-panels`
3. 少量高信号 `http/exposures` 模板
4. 必要时对样本目标补跑 `nuclei -as`

识别目标不是深打，而是尽量回答：
- 它像什么产品 / 组件 / 系统
- 是否存在后台 / 登录面板 / 运维控制台
- 是否已有明显暴露面
- 应优先映射哪些 N-day tags / 模板

标准入口：
- `python .\scripts\nuclei_fingerprint.py .\normalized_targets.jsonl --output-dir .\triage_out`

本阶段至少产出：
- `nuclei_fingerprint_raw.jsonl`
- `fingerprinted_targets.jsonl`

### Phase C：识别结果整理与产品映射

把 nuclei 识别结果整理成可供后续评分与漏扫使用的字段：
- `matched_templates`
- `technologies`
- `candidate_products`
- `exposed_panels`
- `exposure_hits`
- `recommended_nuclei_tags`
- `matched_paths`
- `recognized_by`

再根据标题、域名、产品名、cookie、路径关键词补：
- `sector_tags`
- `system_tags`
- `high_value_tags`

### Phase D：聚类与样本优先

聚类键优先参考：
- `favicon_hash`（若 fallback 已补到）
- `title`
- `server`
- `technologies`
- `candidate_products`
- 路径形态

每簇策略：
- 先选 1~3 个样本
- 样本命中后再扩同簇
- 重复站点不要重复深打

优先脚本：
- `python .\scripts\cluster_targets.py .\triage_out\fingerprinted_targets.jsonl -o .\clustered_targets.jsonl`

### Phase E：定向批量 N-day 锁定

目标：
- 在几百到几千目标中，先用**低噪声、限速、定向**的 nuclei 漏扫快速锁定 N-day
- 只负责“找出值得交给 `hvv-full-auto` 深打”的目标，不在本阶段直接打穿

执行顺序：
1. 优先吃 `fingerprinted_targets.jsonl`
2. 从 `technologies` / `candidate_products` / `exposed_panels` / `exposure_hits` / `recommended_nuclei_tags` 推导模板范围
3. 先单模板、再极小模板集、最后才是高信号 tags 集合
4. 只跑 `medium,high,critical`
5. 默认限速、限并发、分批跑
6. 输出 `nuclei_hits.jsonl` 与 `nday_locked_targets.jsonl`

标准入口：
- `python .\scripts\bulk_nuclei_lock.py .\normalized_targets.jsonl --metadata .\triage_out\fingerprinted_targets.jsonl --output-dir .\triage_out`

### Phase F：评分、Top N 分发与回流

评分维度：
- 资产价值
- 可利用性
- 证据信号
- 操作成本

高分信号包括：
- 命中高价值产品 / 面板 / 暴露模板
- 命中本地 POC / nuclei 模板
- `robots.txt` / JS / 错误页 / 后台路径证据明显
- 同簇样本已命中

推荐流程：
1. `python .\scripts\score_targets.py .\triage_out\fingerprinted_targets.jsonl -o .\scored_targets.jsonl`
2. `python .\scripts\select_topn.py .\scored_targets.jsonl -n 50 --per-cluster 2 -o .\top_targets.jsonl`

分发结果：
- P1：立即交给 `hvv-full-auto`
- P2：排队待验证
- P3：存档，不立即深打

### Phase G：fallback 补充识别（仅当 nuclei 识别不足时）

只有以下情况才走 fallback：
- nuclei 没识别出产品，但站点明显活着
- 需要 `robots.txt`、`favicon_hash`、`login_paths_found`、`generator`、`body_excerpt` 等补充字段
- 需要判断是否存在 `/admin`、`/login`、`/dede/`、`/manage` 等入口

使用：
- `python .\scripts\fingerprint_targets.py .\normalized_targets.jsonl -o .\fallback_fingerprinted_targets.jsonl`

要求：
- fallback 结果应当作为**补充元数据**合并回 `fingerprinted_targets.jsonl`
- 不允许因为写了 fallback 脚本，就跳过 nuclei 识别层

## 推荐标准链路

### 最小推荐链

```powershell
python .\scripts\normalize_targets.py .\targets.txt -o .\normalized_targets.jsonl
python .\scripts\nuclei_fingerprint.py .\normalized_targets.jsonl --output-dir .\triage_out
python .\scripts\cluster_targets.py .\triage_out\fingerprinted_targets.jsonl -o .\clustered_targets.jsonl
python .\scripts\score_targets.py .\triage_out\fingerprinted_targets.jsonl -o .\scored_targets.jsonl
python .\scripts\bulk_nuclei_lock.py .\normalized_targets.jsonl --metadata .\triage_out\fingerprinted_targets.jsonl --output-dir .\triage_out
python .\scripts\select_topn.py .\scored_targets.jsonl -n 50 --per-cluster 2 -o .\top_targets.jsonl
```

### 加 fallback 的补充链

```powershell
python .\scripts\fingerprint_targets.py .\normalized_targets.jsonl -o .\fallback_fingerprinted_targets.jsonl
```

仅在以下场景追加：
- 识别结果稀疏
- 需要 `robots.txt` 泄露路径
- 需要登录口 / 管理口 / favicon 作为补充证据

## 与 `hvv-full-auto` 的关系

这个 Skill 负责：
- 挑目标
- 排顺序
- 做识别
- 做样本
- 控预算
- 锁 N-day

`hvv-full-auto` 负责：
- 接手高分目标或 `nday_locked_targets.jsonl`
- 进入单目标深打
- getshell、提权、后渗透、横向、持久化、痕迹处理、报告输出

## 强制规则

1. 对 5000 目标 **禁止直接套用单目标深打逻辑逐个硬打**
2. 对 5000 目标 **禁止一上来全量跑整个 `C:\Users\pai\nuclei-templates`**
3. 允许全量跑的只有：
   - `http/technologies`
   - `http/exposed-panels`
   - 精选小规模 `http/exposures` 模板集
4. 大池目标优先顺序固定为：
   - 归一化
   - nuclei 识别层
   - 结果映射
   - 聚类/样本
   - 定向批量 N-day 锁定
   - Top N 回流
5. fallback 轻量探针只能补充，不能替代 nuclei 识别层

## 参考资料

- `references/workflow.md`
- `references/fingerprint-nday-mapping.md`
- `references/bulk-nday-scan.md`
- `references/priority-scoring.md`
- `references/sector-keywords.md`
- `references/nuclei-template-selection.md`
- `references/dispatch-rules.md`
- `references/result-schema.md`

## 脚本

- `scripts/normalize_targets.py`
- `scripts/nuclei_fingerprint.py`
- `scripts/fingerprint_targets.py`
- `scripts/cluster_targets.py`
- `scripts/score_targets.py`
- `scripts/bulk_nuclei_lock.py`
- `scripts/select_topn.py`
