#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CTF one-click exploit template.

- No CLI arguments.
- Target address intentionally blank.
- Fill credentials/paths if needed.
"""

import re
import time
from typing import Optional

import requests

BASE_URL = ""  # intentionally blank
USERNAME = ""  # optionally blank (script may auto-register)
PASSWORD = ""  # optionally blank

TIMEOUT = 10


def must_base_url() -> str:
    if not BASE_URL:
        raise SystemExit("BASE_URL is empty by design. Fill it locally before running.")
    return BASE_URL.rstrip("/")


def extract_flag(text: str) -> Optional[str]:
    m = re.search(r"flag\{[\s\S]*?\}", text, re.IGNORECASE)
    return m.group(0) if m else None


def main() -> None:
    base = must_base_url()

    s = requests.Session()

    # TODO: register/login if needed
    # TODO: craft payload
    # TODO: trigger
    # TODO: parse flag

    raise SystemExit("TODO: implement exploit")


if __name__ == "__main__":
    main()
