#!/usr/bin/env python3
import argparse
import json

HIGH_VALUE_KEYWORDS = [
    "sso", "cas", "4a", "vpn", "堡垒机", "oa", "教务", "一卡通",
    "his", "lis", "pacs", "emr", "邮件", "jenkins", "gitlab", "k8s", "harbor",
]
HIGH_EXPLOIT_KEYWORDS = [
    "upload", "admin", "login", "phpmyadmin", "dedecms", "thinkphp",
    "weblogic", "tomcat", "shiro", "grafana", "nacos", "swagger", "git-config", "phpinfo",
]
EVIDENCE_KEYWORDS = [
    "robots", "sql", "error", "debug", "swagger", "api", "manage", "dede", "plus",
    "panel", "exposure", "default-login",
]
HIGH_COST_KEYWORDS = [
    "captcha", "waf", "forbidden", "cloudflare",
]


def text_of(row):
    parts = [
        row.get("target", ""),
        row.get("title", ""),
        row.get("server", ""),
        " ".join(row.get("sector_tags", []) or []),
        " ".join(row.get("system_tags", []) or []),
        " ".join(row.get("technologies", []) or []),
        " ".join(row.get("candidate_products", []) or []),
        " ".join(row.get("exposed_panels", []) or []),
        " ".join(row.get("exposure_hits", []) or []),
        " ".join(row.get("recommended_nuclei_tags", []) or []),
        " ".join(row.get("leak_paths", []) or []),
        " ".join(row.get("matched_templates", []) or []),
        row.get("body_excerpt", ""),
    ]
    return " ".join(parts).lower()


def count_hits(text, keywords):
    return sum(1 for k in keywords if k.lower() in text)


def build_reasons(row, text):
    reasons = []
    if row.get("technologies"):
        reasons.append("technologies_identified")
    if row.get("exposed_panels"):
        reasons.append("panel_exposed")
    if row.get("exposure_hits"):
        reasons.append("exposure_template_hit")
    if row.get("leak_paths"):
        reasons.append("path_leak")
    if any(x in text for x in ["dedecms", "thinkphp", "weblogic", "shiro", "jenkins", "grafana", "nacos"]):
        reasons.append("high_signal_product")
    if any(x in text for x in ["oa", "sso", "cas", "vpn", "his", "pacs", "教务", "一卡通"]):
        reasons.append("high_value_system")
    return sorted(set(reasons))


def main():
    ap = argparse.ArgumentParser(description="Heuristically score target records.")
    ap.add_argument("input", help="Input jsonl")
    ap.add_argument("-o", "--output", default="scored_targets.jsonl")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as fin, open(
        args.output, "w", encoding="utf-8"
    ) as fout:
        for line in fin:
            row = json.loads(line)
            text = text_of(row)
            value_score = count_hits(text, HIGH_VALUE_KEYWORDS) * 10
            exploit_score = count_hits(text, HIGH_EXPLOIT_KEYWORDS) * 10
            evidence_score = count_hits(text, EVIDENCE_KEYWORDS) * 5
            cost_score = count_hits(text, HIGH_COST_KEYWORDS) * 5
            if row.get("exposed_panels"):
                exploit_score += 10
                evidence_score += 10
            if row.get("exposure_hits"):
                exploit_score += 10
                evidence_score += 10
            final_score = value_score * 0.35 + exploit_score * 0.35 + evidence_score * 0.20 - cost_score * 0.10
            row.update(
                {
                    "value_score": value_score,
                    "exploit_score": exploit_score,
                    "evidence_score": evidence_score,
                    "cost_score": cost_score,
                    "final_score": round(final_score, 2),
                    "reasons": build_reasons(row, text),
                }
            )
            fout.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"[+] wrote scored output to {args.output}")


if __name__ == "__main__":
    main()
