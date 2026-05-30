#!/usr/bin/env python3
import argparse
import json
from urllib.parse import urlparse


def normalize_target(raw: str):
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    if "://" not in s:
        guess = f"http://{s}"
    else:
        guess = s
    p = urlparse(guess)
    host = p.hostname or s
    scheme = p.scheme or "http"
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    canonical_key = f"{scheme}://{host}:{port}{path}"
    return {
        "raw": raw.rstrip("\n"),
        "target": guess,
        "type": "url" if "://" in guess else "host",
        "host": host,
        "scheme": scheme,
        "port": port,
        "path": path,
        "canonical_key": canonical_key,
    }


def main():
    ap = argparse.ArgumentParser(description="Normalize and deduplicate target lines.")
    ap.add_argument("input", help="Input txt file")
    ap.add_argument("-o", "--output", default="normalized_targets.jsonl")
    args = ap.parse_args()

    seen = set()
    rows = []
    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            row = normalize_target(line)
            if not row:
                continue
            if row["canonical_key"] in seen:
                continue
            seen.add(row["canonical_key"])
            rows.append(row)

    with open(args.output, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[+] wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
