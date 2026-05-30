#!/usr/bin/env python3
import argparse
import concurrent.futures
import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from html import unescape


UA = "Mozilla/5.0 (compatible; HVV-Triage/1.0)"
SSL_CTX = ssl._create_unverified_context()
LOGIN_PATHS = [
    "/login",
    "/admin",
    "/user/login",
    "/dede/",
    "/manage",
    "/oa",
    "/phpmyadmin/",
    "/nacos/",
    "/jenkins/",
]


TECH_RULES = [
    ("dedecms", ["dedecms", "织梦", "/plus/", "/dede/", "dede"]),
    ("thinkphp", ["thinkphp"]),
    ("wordpress", ["wordpress", "wp-content", "wp-includes"]),
    ("discuz", ["discuz"]),
    ("grafana", ["grafana", "grafana_session"]),
    ("jenkins", ["jenkins"]),
    ("gitlab", ["gitlab"]),
    ("harbor", ["harbor"]),
    ("nacos", ["nacos"]),
    ("phpmyadmin", ["phpmyadmin"]),
    ("zabbix", ["zabbix", "zbx_sessionid"]),
    ("weblogic", ["weblogic"]),
    ("tomcat", ["tomcat", "catalina"]),
    ("shiro", ["rememberme", "shiro"]),
    ("spring", ["spring", "whitelabel error page"]),
    ("struts", ["struts"]),
    ("seeyon", ["seeyon", "致远"]),
    ("weaver", ["weaver", "泛微", "ecology"]),
    ("landray", ["landray", "蓝凌"]),
    ("ruoyi", ["ruoyi", "若依"]),
]

PRODUCT_TO_TAGS = {
    "dedecms": ["dedecms", "cms"],
    "thinkphp": ["thinkphp", "php"],
    "wordpress": ["wordpress", "cms"],
    "discuz": ["discuz", "cms"],
    "grafana": ["grafana", "panel"],
    "jenkins": ["jenkins", "panel"],
    "gitlab": ["gitlab", "panel"],
    "harbor": ["harbor", "panel"],
    "nacos": ["nacos", "panel"],
    "phpmyadmin": ["phpmyadmin", "panel"],
    "zabbix": ["zabbix", "panel"],
    "weblogic": ["weblogic", "java"],
    "tomcat": ["tomcat", "java"],
    "shiro": ["shiro", "java"],
    "spring": ["spring", "java"],
    "struts": ["struts", "java"],
    "seeyon": ["seeyon", "oa"],
    "weaver": ["weaver", "oa"],
    "landray": ["landray", "oa"],
    "ruoyi": ["ruoyi", "java"],
}


def ensure_url(raw: str) -> str:
    s = raw.strip()
    if "://" in s:
        return s
    return "http://" + s


def fetch(url: str, timeout: float = 8.0, max_bytes: int = 65536):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "identity"})
    with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
        data = resp.read(max_bytes)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return {
            "status": getattr(resp, "status", None),
            "url": resp.geturl(),
            "headers": headers,
            "data": data,
        }


def safe_fetch(url: str, timeout: float = 8.0, max_bytes: int = 65536):
    try:
        return fetch(url, timeout=timeout, max_bytes=max_bytes), None
    except urllib.error.HTTPError as e:
        try:
            data = e.read(max_bytes)
        except Exception:
            data = b""
        headers = {k.lower(): v for k, v in getattr(e, "headers", {}).items()} if getattr(e, "headers", None) else {}
        return {
            "status": e.code,
            "url": url,
            "headers": headers,
            "data": data,
        }, None
    except Exception as e:
        return None, str(e)


def decode_bytes(data: bytes, headers: dict) -> str:
    ctype = headers.get("content-type", "")
    m = re.search(r"charset=([a-zA-Z0-9_\-]+)", ctype)
    if m:
        enc = m.group(1)
        try:
            return data.decode(enc, errors="ignore")
        except Exception:
            pass
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return unescape(re.sub(r"\s+", " ", m.group(1)).strip()) if m else ""


def extract_generator(html: str) -> str:
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', html, re.I | re.S)
    return unescape(m.group(1).strip()) if m else ""


def extract_leak_paths(robots_text: str):
    out = []
    for line in robots_text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if ":" in s:
            _, rhs = s.split(":", 1)
            rhs = rhs.strip()
            if rhs.startswith("/"):
                out.append(rhs)
    return out[:30]


def extract_cookies(headers: dict):
    out = []
    for k, v in headers.items():
        if k == "set-cookie":
            parts = v.split(";")[0].split("=", 1)
            if parts and parts[0]:
                out.append(parts[0].strip())
    return out


def detect_technologies(text: str):
    hits = []
    lower = text.lower()
    for tech, rules in TECH_RULES:
        if any(rule.lower() in lower for rule in rules):
            hits.append(tech)
    return sorted(set(hits))


def system_tags_from_text(text: str):
    t = text.lower()
    tags = []
    if any(x in t for x in ["sso", "cas", "oauth", "4a"]):
        tags.append("identity")
    if any(x in t for x in ["oa", "审批", "办公", "seeyon", "weaver", "landray"]):
        tags.append("oa")
    if any(x in t for x in ["his", "lis", "pacs", "emr", "医院", "门诊", "住院"]):
        tags.append("hospital")
    if any(x in t for x in ["教务", "一卡通", "研究生", "迎新", "学工"]):
        tags.append("edu")
    if any(x in t for x in ["jenkins", "gitlab", "harbor", "nacos", "grafana", "zabbix", "k8s", "rancher"]):
        tags.append("ops-panel")
    return sorted(set(tags))


def recommended_tags(technologies):
    tags = []
    for tech in technologies:
        tags.extend(PRODUCT_TO_TAGS.get(tech, []))
    return sorted(set(tags))


def probe_target(raw: str, timeout: float = 8.0):
    base = ensure_url(raw)
    home, home_err = safe_fetch(base, timeout=timeout)
    if not home:
        return {
            "target": raw.strip(),
            "final_url": "",
            "status": None,
            "error": home_err or "request failed",
        }

    headers = home["headers"]
    html = decode_bytes(home["data"], headers)
    title = extract_title(html)
    generator = extract_generator(html)
    cookies = extract_cookies(headers)
    server = headers.get("server", "")
    x_powered_by = headers.get("x-powered-by", "")

    parsed = urllib.parse.urlsplit(home["url"])
    origin = f"{parsed.scheme}://{parsed.netloc}"

    robots, _ = safe_fetch(origin + "/robots.txt", timeout=timeout, max_bytes=32768)
    robots_text = decode_bytes(robots["data"], robots["headers"]) if robots else ""
    leak_paths = extract_leak_paths(robots_text)

    fav, _ = safe_fetch(origin + "/favicon.ico", timeout=timeout, max_bytes=262144)
    favicon_hash = hashlib.md5(fav["data"]).hexdigest() if fav and fav.get("data") else ""

    login_hits = []
    for path in LOGIN_PATHS:
        resp, _ = safe_fetch(origin + path, timeout=timeout, max_bytes=8192)
        if resp and resp.get("status") and resp["status"] < 500:
            if resp["status"] in (200, 301, 302, 401, 403):
                login_hits.append(path)

    body_excerpt = re.sub(r"\s+", " ", html[:1500]).strip()
    detection_text = " ".join([
        home["url"],
        title,
        generator,
        server,
        x_powered_by,
        " ".join(cookies),
        " ".join(leak_paths),
        " ".join(login_hits),
        body_excerpt,
    ])
    technologies = detect_technologies(detection_text)
    candidate_products = technologies[:]
    sys_tags = system_tags_from_text(detection_text)
    rec_tags = recommended_tags(technologies)

    return {
        "target": raw.strip(),
        "final_url": home["url"],
        "status": home["status"],
        "title": title,
        "server": server,
        "x_powered_by": x_powered_by,
        "generator": generator,
        "cookies": cookies,
        "favicon_hash": favicon_hash,
        "leak_paths": leak_paths,
        "login_paths_found": login_hits,
        "technologies": technologies,
        "candidate_products": candidate_products,
        "system_tags": sys_tags,
        "recommended_nuclei_tags": rec_tags,
        "body_excerpt": body_excerpt,
    }


def read_targets(path: str):
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
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


def main():
    ap = argparse.ArgumentParser(description="Lightweight fingerprinting for bulk targets.")
    ap.add_argument("input", help="Input targets txt/jsonl")
    ap.add_argument("-o", "--output", default="fingerprinted_targets.jsonl")
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    targets = read_targets(args.input)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex, open(
        args.output, "w", encoding="utf-8"
    ) as fout:
        futures = [ex.submit(probe_target, t, args.timeout) for t in targets]
        for fut in concurrent.futures.as_completed(futures):
            row = fut.result()
            fout.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[+] wrote {len(targets)} fingerprint rows to {args.output}")


if __name__ == "__main__":
    main()
