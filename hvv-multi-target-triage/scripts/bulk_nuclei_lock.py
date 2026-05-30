#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_NUCLEI = r"C:\Users\pai\Desktop\tool\nuclei_3.8.0_windows_amd64\nuclei.exe"
DEFAULT_TEMPLATES = r"C:\Users\pai\nuclei-templates"

KEYWORD_TAGS = {
    "dedecms": ["dedecms", "cms"],
    "dede": ["dedecms", "cms"],
    "thinkphp": ["thinkphp", "php"],
    "weblogic": ["weblogic", "java"],
    "tomcat": ["tomcat", "java"],
    "shiro": ["shiro", "java"],
    "spring": ["spring", "java"],
    "struts": ["struts", "java"],
    "jenkins": ["jenkins", "panel"],
    "gitlab": ["gitlab", "panel"],
    "harbor": ["harbor", "panel"],
    "grafana": ["grafana", "panel"],
    "nacos": ["nacos", "panel"],
    "seeyon": ["seeyon", "oa"],
    "weaver": ["weaver", "oa"],
    "landray": ["landray", "oa"],
    "ruoyi": ["ruoyi", "java"],
    "phpmyadmin": ["phpmyadmin", "panel"],
    "zabbix": ["zabbix", "panel"],
    "swagger": ["swagger", "api", "exposure"],
    "git-config": ["git", "config", "exposure"],
    "phpinfo": ["phpinfo", "exposure"],
    "laravel": ["laravel", "php", "config", "exposure"],
    "codeigniter": ["codeigniter", "php", "config", "exposure"],
    "env": ["env", "config", "exposure"],
    "jeecg": ["jeecg", "swagger", "api", "exposure"],
}

FALLBACK_TAGS = [
    "rce",
    "sqli",
    "lfi",
    "traversal",
    "default-login",
    "auth-bypass",
    "file-upload",
    "exposure",
    "panel",
]

EXCLUDE_TAGS = [
    "dos",
    "fuzz",
    "bruteforce",
    "tech",
    "ssl",
    "headless",
]


def read_targets(path: str):
    rows = []
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    target = obj.get("target") or obj.get("url") or obj.get("host")
                    if target:
                        rows.append(target)
                except Exception:
                    rows.append(line)
            else:
                rows.append(line)
    return rows


def read_metadata(path: str):
    if not path:
        return []
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def text_of(row):
    parts = [
        row.get("target", ""),
        row.get("title", ""),
        row.get("server", ""),
        row.get("generator", ""),
        " ".join(row.get("candidate_products", []) or []),
        " ".join(row.get("sector_tags", []) or []),
        " ".join(row.get("system_tags", []) or []),
        " ".join(row.get("technologies", []) or []),
        " ".join(row.get("recommended_nuclei_tags", []) or []),
        " ".join(row.get("exposed_panels", []) or []),
        " ".join(row.get("exposure_hits", []) or []),
        " ".join(row.get("leak_paths", []) or []),
        " ".join(row.get("matched_templates", []) or []),
        row.get("body_excerpt", ""),
    ]
    return " ".join(parts).lower()


def derive_tags(metadata_rows, user_tags=None):
    tags = set()
    if user_tags:
        for item in user_tags.split(","):
            item = item.strip()
            if item:
                tags.add(item)
    for row in metadata_rows:
        tags.update(row.get("recommended_nuclei_tags", []) or [])
        for field in ["candidate_products", "technologies", "exposed_panels", "exposure_hits", "matched_templates"]:
            for item in row.get(field, []) or []:
                token = str(item).strip().lower()
                if token:
                    for keyword, mapped in KEYWORD_TAGS.items():
                        if keyword in token:
                            tags.update(mapped)
        t = text_of(row)
        for keyword, mapped in KEYWORD_TAGS.items():
            if keyword in t:
                tags.update(mapped)
    if not tags:
        tags.update(FALLBACK_TAGS)
    return sorted(tags)


def chunked(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def run_nuclei(nuclei_bin, templates_dir, targets, tags, severities, rate_limit, concurrency, output_file):
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as tf:
        for item in targets:
            tf.write(item + "\n")
        list_file = tf.name

    cmd = [
        nuclei_bin,
        "-l", list_file,
        "-t", templates_dir,
        "-tags", ",".join(tags),
        "-etags", ",".join(EXCLUDE_TAGS),
        "-severity", severities,
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-jsonl",
        "-silent",
        "-o", output_file,
    ]
    print("[*] running:", " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    try:
        os.unlink(list_file)
    except OSError:
        pass
    if cp.returncode not in (0, 1):
        print(cp.stdout)
        print(cp.stderr, file=sys.stderr)
        raise SystemExit(cp.returncode)
    if cp.stderr:
        print(cp.stderr, file=sys.stderr)


def parse_hits(raw_file, hits_file, locked_file):
    seen = set()
    count = 0
    with open(raw_file, "r", encoding="utf-8", errors="ignore") as fin, \
         open(hits_file, "w", encoding="utf-8") as fhits, \
         open(locked_file, "w", encoding="utf-8") as flock:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            info = obj.get("info", {}) or {}
            row = {
                "target": obj.get("matched-at") or obj.get("host") or "",
                "host": obj.get("host") or "",
                "template_id": obj.get("template-id") or "",
                "template_name": info.get("name") or "",
                "severity": info.get("severity") or "",
                "matched": obj.get("matched-at") or "",
                "matcher_name": obj.get("matcher-name") or "",
                "type": obj.get("type") or "",
                "next_action": "route_to_hvv_full_auto",
            }
            key = (row["target"], row["template_id"])
            if key in seen:
                continue
            seen.add(key)
            fhits.write(json.dumps(row, ensure_ascii=False) + "\n")
            locked_row = {
                "target": row["target"],
                "matched_template": row["template_id"],
                "severity": row["severity"],
                "reason": f"nuclei hit: {row['template_id']}",
                "next_action": "handoff_to_hvv_full_auto",
            }
            flock.write(json.dumps(locked_row, ensure_ascii=False) + "\n")
            count += 1
    return count


def write_summary(path, tags, total_targets, total_hits, chunk_size, rate_limit, concurrency):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Bulk N-day Lock Summary\n\n")
        f.write(f"- total_targets: {total_targets}\n")
        f.write(f"- total_hits: {total_hits}\n")
        f.write(f"- tags: {', '.join(tags)}\n")
        f.write(f"- chunk_size: {chunk_size}\n")
        f.write(f"- rate_limit: {rate_limit}\n")
        f.write(f"- concurrency: {concurrency}\n")


def main():
    ap = argparse.ArgumentParser(description="Run focused bulk nuclei scans to lock N-day targets.")
    ap.add_argument("targets", help="Input targets txt/jsonl")
    ap.add_argument("--metadata", help="Optional metadata/scored jsonl", default="")
    ap.add_argument("--nuclei-bin", default=DEFAULT_NUCLEI)
    ap.add_argument("--templates-dir", default=DEFAULT_TEMPLATES)
    ap.add_argument("--tags", default="", help="Explicit comma-separated tags")
    ap.add_argument("--severities", default="medium,high,critical")
    ap.add_argument("--rate-limit", type=int, default=120)
    ap.add_argument("--concurrency", type=int, default=30)
    ap.add_argument("--chunk-size", type=int, default=200)
    ap.add_argument("--output-dir", default="triage_out")
    args = ap.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    nuclei_bin = Path(args.nuclei_bin)
    templates_dir = Path(args.templates_dir)
    if not nuclei_bin.exists():
        raise SystemExit(f"nuclei binary not found: {nuclei_bin}")
    if not templates_dir.exists():
        raise SystemExit(f"templates dir not found: {templates_dir}")

    targets = read_targets(args.targets)
    metadata = read_metadata(args.metadata)
    tags = derive_tags(metadata, args.tags)

    raw_file = outdir / "nuclei_raw.jsonl"
    if raw_file.exists():
        raw_file.unlink()

    for idx, chunk in enumerate(chunked(targets, args.chunk_size), start=1):
        tmp_out = outdir / f"nuclei_raw.part{idx}.jsonl"
        run_nuclei(
            str(nuclei_bin),
            str(templates_dir),
            chunk,
            tags,
            args.severities,
            args.rate_limit,
            args.concurrency,
            str(tmp_out),
        )
        with raw_file.open("a", encoding="utf-8") as fout:
            if tmp_out.exists():
                with tmp_out.open("r", encoding="utf-8", errors="ignore") as fin:
                    for line in fin:
                        fout.write(line)

    hits_file = outdir / "nuclei_hits.jsonl"
    locked_file = outdir / "nday_locked_targets.jsonl"
    summary_file = outdir / "triage_summary.md"
    total_hits = parse_hits(str(raw_file), str(hits_file), str(locked_file))
    write_summary(str(summary_file), tags, len(targets), total_hits, args.chunk_size, args.rate_limit, args.concurrency)
    print(f"[+] targets={len(targets)} hits={total_hits} tags={','.join(tags)}")
    print(f"[+] wrote: {raw_file}")
    print(f"[+] wrote: {hits_file}")
    print(f"[+] wrote: {locked_file}")
    print(f"[+] wrote: {summary_file}")


if __name__ == "__main__":
    main()
