#!/usr/bin/env python3
import argparse
import json


def cluster_key(row):
    title = (row.get("title") or "").strip().lower()
    server = (row.get("server") or "").strip().lower()
    favicon = (row.get("favicon_hash") or "").strip().lower()
    tech = ",".join(sorted(row.get("technologies") or []))
    return "|".join([title, server, favicon, tech])


def main():
    ap = argparse.ArgumentParser(description="Assign simple cluster keys to target records.")
    ap.add_argument("input", help="Input jsonl with fingerprint fields")
    ap.add_argument("-o", "--output", default="clustered_targets.jsonl")
    args = ap.parse_args()

    count = 0
    with open(args.input, "r", encoding="utf-8", errors="ignore") as fin, open(
        args.output, "w", encoding="utf-8"
    ) as fout:
        for line in fin:
            row = json.loads(line)
            row["cluster_key"] = cluster_key(row)
            fout.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    print(f"[+] wrote {count} rows to {args.output}")


if __name__ == "__main__":
    main()
