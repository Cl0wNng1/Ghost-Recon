"""
GHOST RECON v2.0 — core/tools.py
External binary resolution helpers.

ProjectDiscovery's `httpx` and the Python `httpx` CLI (installed by
`pip install httpx[cli]`, and by some distros) share a binary name. When the
Python one shadows the Go one on PATH, every `httpx -l … -json` call silently
returns nothing and verification reports "0 alive". `resolve_pd_httpx()`
finds the real one (or Kali's `httpx-toolkit`) and rejects the impostor.
"""
from __future__ import annotations

import os
import shutil
from functools import lru_cache
from typing import Optional

__all__ = ["resolve_pd_httpx", "is_python_script"]


def is_python_script(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(128)
        return head.startswith(b"#!") and b"python" in head.split(b"\n", 1)[0]
    except OSError:
        return False


@lru_cache(maxsize=1)
def resolve_pd_httpx() -> Optional[str]:
    """Absolute path to ProjectDiscovery httpx, or None."""
    candidates = []
    for name in ("httpx-toolkit", "httpx"):
        p = shutil.which(name)
        if p:
            candidates.append(p)
    gopath = os.environ.get("GOPATH") or os.path.expanduser("~/go")
    candidates.append(os.path.join(gopath, "bin", "httpx"))
    for p in candidates:
        if p and os.path.isfile(p) and os.access(p, os.X_OK) and not is_python_script(p):
            return p
    return None
