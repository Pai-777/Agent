#!/usr/bin/env python3
import argparse
import json
from collections import defaultdict


def main():
    ap = argparse.ArgumentParser(description="Select top N targets with per-cluster cap.")
    ap.add_argument("input", help="Input scored jsonl")
    ap.add_argument("-n", "--top", type=int, default=50)
    ap.add_argument("--per-cluster", type=int, default=2)
    ap.add_argument("-o", "--output", default="top_targets.jsonl")
    args = ap.parse_args()

    rows = []
    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            rows.append(json.loads(line))
    rows.sort(key=lambda x: x.get("final_score", 0), reverse=True)

    chosen = []
    cluster_count = defaultdict(int)
    for row in rows:
        ck = row.get("cluster_key", "")
        if cluster_count[ck] >= args.per_cluster:
            continue
        chosen.append(row)
        cluster_count[ck] += 1
        if len(chosen) >= args.top:
            break

    with open(args.output, "w", encoding="utf-8") as f:
        for row in chosen:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[+] selected {len(chosen)} targets into {args.output}")


if __name__ == "__main__":
    main()
