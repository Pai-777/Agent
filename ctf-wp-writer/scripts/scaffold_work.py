#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Scaffold `work/` output for a CTF writeup.

Creates:
- work/<title>_wp.md
- work/exp.py

No network actions.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--title", required=True, help="Challenge title, used in <title>_wp.md")
    ap.add_argument("--root", default=".", help="Challenge directory root")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True)

    wp_template = (Path(__file__).resolve().parents[1] / "references" / "wp_template.md").read_text(encoding="utf-8")
    exp_template = (Path(__file__).resolve().parents[1] / "references" / "exp_template.py").read_text(encoding="utf-8")

    wp_path = work / f"{args.title}_wp.md"
    exp_path = work / "exp.py"

    if not wp_path.exists():
        wp_path.write_text(wp_template.replace("{TITLE}", args.title), encoding="utf-8")
    if not exp_path.exists():
        exp_path.write_text(exp_template, encoding="utf-8")

    print(str(wp_path))
    print(str(exp_path))


if __name__ == "__main__":
    main()
