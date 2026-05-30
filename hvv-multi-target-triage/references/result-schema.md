# 结果字段建议

## normalized_targets.jsonl

- raw
- target
- type
- host
- scheme
- port
- path
- canonical_key

## nuclei_fingerprint_raw.jsonl

- host
- matched-at
- template-id
- template-path
- info.name
- info.severity
- info.tags

## fingerprinted_targets.jsonl

- target
- canonical_key
- host
- scheme
- port
- path
- matched_templates
- matched_paths
- recognized_by
- technologies
- candidate_products
- exposed_panels
- exposure_hits
- recommended_nuclei_tags
- sector_tags
- system_tags
- title
- server
- x_powered_by
- generator
- cookies
- favicon_hash
- leak_paths
- login_paths_found
- body_excerpt

说明：
- 上半部分优先由 `scripts/nuclei_fingerprint.py` 产出
- 下半部分中的 `title/server/robots/favicon/login_paths_found` 可以由 fallback 探针补充

## clustered_targets.jsonl

- canonical_key
- cluster_key
- title
- server
- favicon_hash
- technologies
- candidate_products

## scored_targets.jsonl

- target
- cluster_key
- value_score
- exploit_score
- evidence_score
- cost_score
- final_score
- sector_tags
- system_tags
- reasons

## top_targets.jsonl

- target
- final_score
- priority
- sample_of_cluster
- recommended_templates
- next_action

## nuclei_hits.jsonl

- target
- host
- template_id
- template_name
- severity
- matched
- matcher_name
- type
- next_action

## nday_locked_targets.jsonl

- target
- matched_template
- severity
- reason
- next_action
