#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

DEFAULT_NUCLEI = r"C:\Users\pai\Desktop\tool\nuclei_3.8.0_windows_amd64\nuclei.exe"
DEFAULT_TECH_DIR = r"C:\Users\pai\nuclei-templates\http\technologies"
DEFAULT_PANEL_DIR = r"C:\Users\pai\nuclei-templates\http\exposed-panels"
DEFAULT_EXPOSURE_TEMPLATES = [
    r"C:\Users\pai\nuclei-templates\http\exposures\apis\swagger-api.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\apis\jeecg-boot-swagger.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\configs\git-config.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\configs\git-config-nginxoffbyslash.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\configs\phpinfo-files.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\configs\javascript-env-config.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\files\javascript-env.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\configs\laravel-env.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\configs\codeigniter-env.yaml",
    r"C:\Users\pai\nuclei-templates\http\exposures\configs\wordpress-wp-env-exposure.yaml",
]

GENERIC_TAGS = {
    "tech", "detect", "detection", "discovery", "panel", "exposure", "config", "info",
    "misc", "login", "api", "files", "file", "vuln", "misconfig", "intrusive"
}

PRODUCT_TAG_MAP = {
    "dedecms": ["dedecms", "cms"],
    "thinkphp": ["thinkphp", "php"],
    "wordpress": ["wordpress", "cms", "wp"],
    "discuz": ["discuz", "cms"],
    "jenkins": ["jenkins", "panel"],
    "gitlab": ["gitlab", "panel"],
    "grafana": ["grafana", "panel"],
    "harbor": ["harbor", "panel"],
    "nacos": ["nacos", "panel"],
    "zabbix": ["zabbix", "panel"],
    "phpmyadmin": ["phpmyadmin", "panel"],
    "weblogic": ["weblogic", "java"],
    "tomcat": ["tomcat", "java"],
    "shiro": ["shiro", "java"],
    "spring": ["spring", "java"],
    "struts": ["struts", "java"],
    "seeyon": ["seeyon", "oa"],
    "weaver": ["weaver", "oa"],
    "landray": ["landray", "oa"],
    "ruoyi": ["ruoyi", "java"],
    "swagger": ["swagger", "api", "exposure"],
    "git": ["git", "config", "exposure"],
    "phpinfo": ["phpinfo", "exposure"],
    "laravel": ["laravel", "php", "config", "exposure"],
    "codeigniter": ["codeigniter", "php", "config", "exposure"],
    "env": ["env", "config", "exposure"],
    "jeecg": ["jeecg", "swagger", "api", "exposure"],
}

PRODUCT_HINTS = {
    "dedecms": ["dedecms", "dede"],
    "thinkphp": ["thinkphp"],
    "wordpress": ["wordpress", "wp-"],
    "discuz": ["discuz"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "harbor": ["harbor"],
    "nacos": ["nacos"],
    "zabbix": ["zabbix"],
    "phpmyadmin": ["phpmyadmin"],
    "weblogic": ["weblogic"],
    "tomcat": ["tomcat", "catalina"],
    "shiro": ["shiro", "rememberme"],
    "spring": ["spring", "springboot"],
    "struts": ["struts"],
    "seeyon": ["seeyon", "致远"],
    "weaver": ["weaver", "ecology", "泛微"],
    "landray": ["landray", "蓝凌"],
    "ruoyi": ["ruoyi", "若依"],
    "swagger": ["swagger"],
    "git": ["git-config", ".git/config"],
    "phpinfo": ["phpinfo"],
    "laravel": ["laravel"],
    "codeigniter": ["codeigniter"],
    "env": ["env"],
    "jeecg": ["jeecg"],
}

EXCLUDE_TAGS = ["dos", "fuzz", "bruteforce", "ssl", "headless"]


def iter_input_rows(path: str):
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                obj = json.loads(line)
                target = obj.get("target") or obj.get("url") or obj.get("host")
                if target:
                    obj.setdefault("target", target)
                    rows.append(obj)
            else:
                rows.append({"target": line})
    return rows


def write_target_list(targets):
    tf = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt")
    try:
        for item in targets:
            tf.write(item + "\n")
    finally:
        tf.close()
    return tf.name


def chunked(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def run_nuclei(nuclei_bin, targets, output_file, template_paths=None, auto_scan=False,
               rate_limit=120, concurrency=30, extra_args=None):
    list_file = write_target_list(targets)
    cmd = [nuclei_bin, "-l", list_file, "-jsonl", "-silent", "-rl", str(rate_limit), "-c", str(concurrency)]
    if auto_scan:
        cmd.append("-as")
    else:
        for tp in template_paths or []:
            cmd.extend(["-t", tp])
    if EXCLUDE_TAGS:
        cmd.extend(["-etags", ",".join(EXCLUDE_TAGS)])
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(["-o", output_file])

    print("[*] running:", " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    try:
        os.unlink(list_file)
    except OSError:
        pass
    if cp.returncode not in (0, 1):
        if cp.stdout:
            print(cp.stdout)
        if cp.stderr:
            print(cp.stderr, file=sys.stderr)
        raise SystemExit(cp.returncode)
    if cp.stderr:
        print(cp.stderr, file=sys.stderr)


def append_jsonl(src: Path, dst: Path):
    if not src.exists():
        return
    with dst.open("a", encoding="utf-8") as fout, src.open("r", encoding="utf-8", errors="ignore") as fin:
        for line in fin:
            fout.write(line)


def extract_tags(field):
    if isinstance(field, list):
        items = field
    elif isinstance(field, str):
        items = [x.strip() for x in field.split(",")]
    else:
        items = []
    out = []
    for item in items:
        item = str(item).strip().lower()
        if item:
            out.append(item)
    return out


def classify_source(obj):
    path = str(obj.get("template-path") or "").replace("\\", "/").lower()
    tags = set(extract_tags((obj.get("info") or {}).get("tags")))
    if "http/technologies" in path:
        return "technologies"
    if "http/exposed-panels" in path or "panel" in tags:
        return "panels"
    if "http/exposures" in path or "exposure" in tags or "config" in tags:
        return "exposures"
    return "auto-tags"


def infer_products(obj):
    info = obj.get("info") or {}
    text = " ".join([
        str(obj.get("template-id") or ""),
        str(info.get("name") or ""),
        str(info.get("tags") or ""),
        str(obj.get("template-path") or ""),
        str(obj.get("matched-at") or ""),
    ]).lower()
    hits = set()
    for product, keywords in PRODUCT_HINTS.items():
        if any(k.lower() in text for k in keywords):
            hits.add(product)
    return hits


def filtered_tags(obj):
    tags = set(extract_tags((obj.get("info") or {}).get("tags")))
    return {t for t in tags if t not in GENERIC_TAGS}


def merge_row(current, obj):
    source = classify_source(obj)
    tags = filtered_tags(obj)
    products = infer_products(obj)
    tid = str(obj.get("template-id") or "").strip()
    matched = str(obj.get("matched-at") or obj.get("host") or "").strip()

    current["matched_templates"].add(tid)
    if matched:
        current["matched_paths"].add(matched)
    current["recognized_by"].add(source)
    current["raw_tags"].update(tags)

    if source == "technologies":
        current["technologies"].update(products or tags)
    elif source == "panels":
        current["exposed_panels"].update(products or tags)
    elif source == "exposures":
        current["exposure_hits"].add(tid)
        current["candidate_products"].update(products)
    else:
        current["candidate_products"].update(products)

    current["candidate_products"].update(products)
    for product in products:
        current["recommended_nuclei_tags"].update(PRODUCT_TAG_MAP.get(product, []))

    low_tid = tid.lower()
    if any(x in low_tid for x in ["swagger", "jeecg"]):
        current["recommended_nuclei_tags"].update(["swagger", "api", "exposure"])
    if "git-config" in low_tid:
        current["recommended_nuclei_tags"].update(["git", "config", "exposure"])
    if "phpinfo" in low_tid:
        current["recommended_nuclei_tags"].update(["phpinfo", "exposure"])
    if any(x in low_tid for x in ["env", "laravel", "codeigniter"]):
        current["recommended_nuclei_tags"].update(["config", "exposure"])


def finalize_row(base_row, current):
    out = dict(base_row)
    out.setdefault("target", base_row.get("target") or base_row.get("url") or base_row.get("host") or "")
    out["matched_templates"] = sorted(x for x in current["matched_templates"] if x)
    out["matched_paths"] = sorted(x for x in current["matched_paths"] if x)
    out["recognized_by"] = sorted(x for x in current["recognized_by"] if x)
    out["technologies"] = sorted(x for x in current["technologies"] if x)
    out["candidate_products"] = sorted(x for x in current["candidate_products"] if x)
    out["exposed_panels"] = sorted(x for x in current["exposed_panels"] if x)
    out["exposure_hits"] = sorted(x for x in current["exposure_hits"] if x)
    rec_tags = set(current["recommended_nuclei_tags"])
    for tech in out["technologies"] + out["candidate_products"] + out["exposed_panels"]:
        rec_tags.update(PRODUCT_TAG_MAP.get(tech, []))
    out["recommended_nuclei_tags"] = sorted(x for x in rec_tags if x)
    return out


def merge_fallback(primary_rows, fallback_path):
    if not fallback_path:
        return primary_rows
    fb = {}
    with open(fallback_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            key = row.get("target") or row.get("final_url") or row.get("host")
            if key:
                fb[key] = row
    for row in primary_rows:
        key = row.get("target") or row.get("final_url") or row.get("host")
        extra = fb.get(key)
        if not extra:
            continue
        for field in ["title", "server", "x_powered_by", "generator", "favicon_hash", "body_excerpt"]:
            if extra.get(field) and not row.get(field):
                row[field] = extra[field]
        for field in ["cookies", "leak_paths", "login_paths_found", "system_tags", "sector_tags"]:
            cur = set(row.get(field) or [])
            cur.update(extra.get(field) or [])
            if cur:
                row[field] = sorted(cur)
    return primary_rows


def main():
    ap = argparse.ArgumentParser(description="Run nuclei-first fingerprinting for bulk targets.")
    ap.add_argument("input", help="Input targets txt/jsonl")
    ap.add_argument("--nuclei-bin", default=DEFAULT_NUCLEI)
    ap.add_argument("--tech-dir", default=DEFAULT_TECH_DIR)
    ap.add_argument("--panel-dir", default=DEFAULT_PANEL_DIR)
    ap.add_argument("--with-exposures", action="store_true", default=True)
    ap.add_argument("--without-exposures", action="store_true")
    ap.add_argument("--auto-tags", action="store_true", help="Also run nuclei -as as a supplement")
    ap.add_argument("--fallback-jsonl", default="", help="Optional fallback fingerprint jsonl to merge")
    ap.add_argument("--rate-limit", type=int, default=120)
    ap.add_argument("--concurrency", type=int, default=30)
    ap.add_argument("--chunk-size", type=int, default=200)
    ap.add_argument("--output-dir", default="triage_out")
    args = ap.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    nuclei_bin = Path(args.nuclei_bin)
    if not nuclei_bin.exists():
        raise SystemExit(f"nuclei binary not found: {nuclei_bin}")
    for path in [Path(args.tech_dir), Path(args.panel_dir)]:
        if not path.exists():
            raise SystemExit(f"required path not found: {path}")

    rows = iter_input_rows(args.input)
    targets = [row.get("target") for row in rows if row.get("target")]
    index = {row.get("target"): row for row in rows if row.get("target")}

    raw_file = outdir / "nuclei_fingerprint_raw.jsonl"
    if raw_file.exists():
        raw_file.unlink()

    use_exposures = args.with_exposures and not args.without_exposures

    for idx, chunk in enumerate(chunked(targets, args.chunk_size), start=1):
        tech_part = outdir / f"fingerprint.tech.part{idx}.jsonl"
        panel_part = outdir / f"fingerprint.panel.part{idx}.jsonl"
        run_nuclei(str(nuclei_bin), chunk, str(tech_part), template_paths=[args.tech_dir],
                   rate_limit=args.rate_limit, concurrency=args.concurrency)
        run_nuclei(str(nuclei_bin), chunk, str(panel_part), template_paths=[args.panel_dir],
                   rate_limit=args.rate_limit, concurrency=args.concurrency)
        append_jsonl(tech_part, raw_file)
        append_jsonl(panel_part, raw_file)

        if use_exposures:
            exposure_templates = [p for p in DEFAULT_EXPOSURE_TEMPLATES if Path(p).exists()]
            if exposure_templates:
                exp_part = outdir / f"fingerprint.exposure.part{idx}.jsonl"
                run_nuclei(str(nuclei_bin), chunk, str(exp_part), template_paths=exposure_templates,
                           rate_limit=args.rate_limit, concurrency=args.concurrency)
                append_jsonl(exp_part, raw_file)

        if args.auto_tags:
            auto_part = outdir / f"fingerprint.auto.part{idx}.jsonl"
            run_nuclei(str(nuclei_bin), chunk, str(auto_part), auto_scan=True,
                       rate_limit=args.rate_limit, concurrency=args.concurrency,
                       extra_args=["-severity", "medium,high,critical"])
            append_jsonl(auto_part, raw_file)

    grouped = defaultdict(lambda: {
        "matched_templates": set(),
        "matched_paths": set(),
        "recognized_by": set(),
        "technologies": set(),
        "candidate_products": set(),
        "exposed_panels": set(),
        "exposure_hits": set(),
        "recommended_nuclei_tags": set(),
        "raw_tags": set(),
    })

    if raw_file.exists():
        with raw_file.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                host = obj.get("host") or obj.get("matched-at") or ""
                if not host:
                    continue
                if host not in index:
                    index.setdefault(host, {"target": host})
                merge_row(grouped[host], obj)

    final_rows = []
    for target, base_row in index.items():
        row = finalize_row(base_row, grouped[target])
        final_rows.append(row)

    final_rows = merge_fallback(final_rows, args.fallback_jsonl)

    fp_file = outdir / "fingerprinted_targets.jsonl"
    with fp_file.open("w", encoding="utf-8") as f:
        for row in final_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    recognized = sum(1 for row in final_rows if row.get("matched_templates"))
    summary_file = outdir / "fingerprint_summary.md"
    with summary_file.open("w", encoding="utf-8") as f:
        f.write("# Nuclei Fingerprint Summary\n\n")
        f.write(f"- total_targets: {len(final_rows)}\n")
        f.write(f"- recognized_targets: {recognized}\n")
        f.write(f"- used_exposures: {use_exposures}\n")
        f.write(f"- auto_tags: {args.auto_tags}\n")

    print(f"[+] wrote: {raw_file}")
    print(f"[+] wrote: {fp_file}")
    print(f"[+] wrote: {summary_file}")
    print(f"[+] targets={len(final_rows)} recognized={recognized}")


if __name__ == "__main__":
    main()
