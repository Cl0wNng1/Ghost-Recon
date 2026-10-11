"""
GHOST RECON v2.0 — core/pipeline.py
Pipeline definition, step selection and the persistent event loop.

Why a persistent loop
---------------------
Earlier builds wrapped every step in its own ``asyncio.run()``. The shared
httpx engine, the aiohttp client and module-level semaphores were created in
the first step's loop and reused in the next one, so against any keep-alive
server every in-process request after the first step failed with
"Event loop is closed" — and the failures were swallowed as ``code=0``.
``PipelineLoop`` keeps ONE loop alive for the whole scan and runs every step
(and the final client cleanup) on it.
"""
from __future__ import annotations

import asyncio
import inspect
from typing import Any, Dict, Iterable, List, Optional, Set

__all__ = [
    "STEP_DEFINITIONS", "STEP_NUMS", "step_by_num", "PipelineLoop",
    "completed_from_snapshot",
]

# Order here IS execution order. ``num`` is a stable ID used by --steps,
# --skip-steps and checkpoints; it is NOT the position in the pipeline.
STEP_DEFINITIONS: List[Dict[str, Any]] = [
    {"num": 0,  "name": "Dependency & Environment Validation", "module": "modules.step00_deps",         "active": False},
    {"num": 1,  "name": "Attack Surface Discovery",            "module": "modules.step01_discovery",    "active": False},
    {"num": 2,  "name": "Data Processing & Resolution",        "module": "modules.step02_processing",  "active": False},
    {"num": 3,  "name": "Asset Verification & Visual Recon",   "module": "modules.step03_verification", "active": True},
    # Authenticate early so every downstream step reuses the session.
    {"num": 15, "name": "Authentication & Session Setup",      "module": "modules.step_auth",          "active": True},
    {"num": 4,  "name": "URL & Endpoint Discovery",            "module": "modules.step04_urls",        "active": True},
    {"num": 5,  "name": "JavaScript Analysis",                 "module": "modules.step05_javascript",  "active": True},
    {"num": 6,  "name": "Secret Discovery",                    "module": "modules.step06_secrets",     "active": True},
    {"num": 7,  "name": "Parameter Discovery",                 "module": "modules.step07_params",      "active": True},
    {"num": 8,  "name": "Vulnerability Scanning",              "module": "modules.step13_vulnscan",    "active": True},
    {"num": 9,  "name": "Network Discovery",                   "module": "modules.step09_network",     "active": True},
    {"num": 10, "name": "Sensitive Data Discovery",            "module": "modules.step10_sensitive",   "active": True},
    {"num": 11, "name": "Backup & Artifact Discovery",         "module": "modules.step11_backups",     "active": True},
    {"num": 12, "name": "Content Discovery",                   "module": "modules.step12_content",     "active": True},
    {"num": 13, "name": "Advanced Fuzzing",                    "module": "modules.step13_fuzzing",     "active": True},
    {"num": 14, "name": "Deep API & Content Discovery",        "module": "modules.step14_deep_api",    "active": True},
    # Needs every endpoint discovered so far, so it runs last.
    {"num": 16, "name": "Access Control & IDOR Testing",       "module": "modules.step_authz",         "active": True},
]

STEP_NUMS: Set[int] = {int(s["num"]) for s in STEP_DEFINITIONS}


def step_by_num(num: int) -> Optional[Dict[str, Any]]:
    for s in STEP_DEFINITIONS:
        if s["num"] == num:
            return s
    return None


def completed_from_snapshot(snapshot: Dict[str, Any], legacy_step: int = 0) -> Set[int]:
    """Return the set of step IDs already completed for a resumed scan.

    v2 checkpoints store ``completed_steps`` explicitly. Older (v15-era)
    checkpoints only stored ``last step number + 1``; because the auth step
    (15) ran fifth, that number cannot be trusted as a position, so we map
    it back through the execution order instead of comparing raw numbers.
    """
    done = snapshot.get("completed_steps")
    if isinstance(done, list):
        return {int(x) for x in done if str(x).lstrip("-").isdigit()}
    if not legacy_step:
        return set()
    last_num = legacy_step - 1
    out: Set[int] = set()
    for s in STEP_DEFINITIONS:
        out.add(int(s["num"]))
        if s["num"] == last_num:
            return out
    return set()


class PipelineLoop:
    """One event loop for the whole scan.

    ``run(fn_or_coro)`` accepts a coroutine, an async function result, or a
    plain value from a sync function. Between ``run`` calls the loop is idle,
    so legacy sync helpers that call ``asyncio.run`` still work.
    """

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def run(self, maybe_coro: Any) -> Any:
        if inspect.isawaitable(maybe_coro):
            return self.loop.run_until_complete(maybe_coro)
        return maybe_coro

    def close(self) -> None:
        if self.loop.is_closed():
            return
        try:
            pending = [t for t in asyncio.all_tasks(self.loop) if not t.done()]
            for t in pending:
                t.cancel()
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        finally:
            self.loop.close()
            try:
                asyncio.set_event_loop(None)
            except Exception:
                pass

    def __enter__(self) -> "PipelineLoop":
        return self

    def __exit__(self, *exc: Iterable[Any]) -> None:
        self.close()
