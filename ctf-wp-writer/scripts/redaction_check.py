#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Redaction check for WP.

- Ensures no IP/domain/port patterns appear.
- Ensures no flag{...} appears.

This is best-effort (regex-based)."""

from __future__ import annotations

import re
import sys
from pathlib import Path


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"\b:\d{2,5}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
FLAG_RE = re.compile(r"flag\{[\s\S]*?\}", re.IGNORECASE)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: redaction_check.py <path-to-wp.md>")

    p = Path(sys.argv[1])
    text = p.read_text(encoding="utf-8", errors="replace")

    hits = []
    if IP_RE.search(text):
        hits.append("IP")
    if PORT_RE.search(text):
        hits.append("PORT")
    if DOMAIN_RE.search(text):
        hits.append("DOMAIN")
    if FLAG_RE.search(text):
        hits.append("FLAG")

    if hits:
        print(f"[FAIL] Found: {', '.join(hits)}")
        raise SystemExit(2)

    print("[OK] No obvious sensitive patterns found.")


if __name__ == "__main__":
    main()
