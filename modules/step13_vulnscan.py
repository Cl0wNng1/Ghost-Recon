"""
GHOST RECON v2.0 — modules/step13_vulnscan.py
Vulnerability Scanning Orchestration — Enterprise Pipeline

Integrates:
  - Nessus (REST API via core/nessus_client.py)
  - Wapiti (web app scanner — JSON output)
  - Nuclei (template-based scanner — JSONL output)
  - Ghauri (advanced SQLi — batch mode)
  - Dalfox (XSS — file input, blind polling, JSON output)
  - Nikto (legacy web scanner — JSON output)

Architecture contracts (Ghost v14):
  - All network I/O via httpx.AsyncClient
  - All subprocess via asyncio.create_subprocess_exec
  - Zero zombie processes — explicit kill() + wait() in all error paths
  - asyncio.Semaphore(3) gates all heavy CLI tools
  - AutoCorrector wraps every CLI execution with timeout recovery +
    degraded-config retry + JSON salvage logic
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

from core.context import Ctx

log = logging.getLogger("ghost.step13")

STEP_NUM = 13
STEP_NAME = "Vulnerability Scanning (Enterprise)"

# ─── Concurrency ──────────────────────────────────────────────────────────────
# Cap concurrent heavy CLI tools to prevent OOM / port exhaustion
_HEAVY_SEM: asyncio.Semaphore = asyncio.Semaphore(3)

# ─── Tool timeouts (seconds) — degraded config uses 60% of these ─────────────
_TIMEOUT: Dict[str, int] = {
    "wapiti":  600,
    "nuclei":  480,
    "ghauri":  300,
    "dalfox":  360,
    "nikto":   600,
    "nessus":  1800,  # Nessus scans can take 30+ minutes
}


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None


# ═══════════════════════════════════════════════════════════════════════════════
# AUTOCORRECTOR — crash-proof subprocess wrapper
# ═══════════════════════════════════════════════════════════════════════════════

class AutoCorrector:
    """
    Wraps asyncio subprocess execution with:
      1. asyncio.wait_for timeout enforcement
      2. On timeout: clean kill() + wait() of orphaned process, retry with
         degraded configuration (reduced timeout, fewer modules/depth)
      3. Corrupted/partial JSON salvage before raising JSONDecodeError
      4. All exceptions are caught and logged — never propagates to orchestrator
    """

    @staticmethod
    async def run(
        cmd: List[str],
        tool_name: str,
        timeout: int,
        *,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        degraded_cmd: Optional[List[str]] = None,
        degraded_timeout: Optional[int] = None,
    ) -> Tuple[str, str, int]:
        """
        Execute a subprocess with full lifecycle management.

        Returns:
            (stdout_text, stderr_text, returncode)
            On irrecoverable failure: ("", error_message, -1)
        """
        merged_env = {**os.environ, **(env or {})}

        for attempt, (exec_cmd, exec_timeout) in enumerate([
            (cmd, timeout),
            (degraded_cmd or cmd, degraded_timeout or max(30, timeout // 2)),
        ]):
            proc: Optional[asyncio.subprocess.Process] = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *exec_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=merged_env,
                    cwd=cwd,
                )

                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(exec_timeout),
                )

                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                rc = proc.returncode if proc.returncode is not None else -1

                if rc != 0 and attempt == 0 and degraded_cmd:
                    log.warning(
                        "[autocorrector] %s exited %d on attempt 1 — retrying degraded",
                        tool_name, rc,
                    )
                    continue

                return stdout, stderr, rc

            except asyncio.TimeoutError:
                log.warning(
                    "[autocorrector] %s timed out after %ds (attempt %d)",
                    tool_name, exec_timeout, attempt + 1,
                )
                if proc is not None:
                    try:
                        proc.kill()
                        await asyncio.wait_for(proc.wait(), timeout=10.0)
                    except Exception as kill_exc:
                        log.debug("[autocorrector] kill cleanup error: %s", kill_exc)

                if attempt == 0 and (degraded_cmd or degraded_timeout):
                    log.info("[autocorrector] %s retrying with degraded config", tool_name)
                    continue

                return "", f"TimeoutError after {exec_timeout}s", -1

            except Exception as exc:
                log.error("[autocorrector] %s unexpected error: %s", tool_name, exc)
                if proc is not None:
                    try:
                        proc.kill()
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                    except Exception:
                        pass
                return "", str(exc), -1

        return "", "exhausted retry budget", -1

    @staticmethod
    def parse_json_output(raw: str, tool_name: str) -> List[Dict[str, Any]]:
        """
        Resilient JSON parser for security tool output.

        Handles:
          - JSONL (one JSON object per line — Nuclei, Dalfox)
          - Single JSON array/object
          - Truncated output (appends ]} and retries)
          - Trailing commas before ] or }
        """
        if not raw or not raw.strip():
            return []

        results: List[Dict[str, Any]] = []

        # ── Strategy 1: JSONL (line-by-line) ─────────────────────────────────
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        jsonl_hits = 0
        for line in lines:
            if not line.startswith("{") and not line.startswith("["):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    results.append(obj)
                    jsonl_hits += 1
                elif isinstance(obj, list):
                    results.extend(i for i in obj if isinstance(i, dict))
                    jsonl_hits += 1
            except json.JSONDecodeError:
                continue

        if jsonl_hits > 0:
            return results

        # ── Strategy 2: Full document parse ──────────────────────────────────
        try:
            doc = json.loads(raw)
            if isinstance(doc, list):
                return [i for i in doc if isinstance(i, dict)]
            if isinstance(doc, dict):
                # Wapiti wraps findings under a key
                for key in ("vulnerabilities", "anomalies", "findings", "results"):
                    sub = doc.get(key)
                    if isinstance(sub, list):
                        return [i for i in sub if isinstance(i, dict)]
                return [doc]
        except json.JSONDecodeError:
            pass

        # ── Strategy 3: Structural salvage ───────────────────────────────────
        salvage_attempts = [
            raw + "]}",
            raw + "}]",
            raw.rstrip(",\n\r ") + "]}",
            # Remove trailing commas before closing brackets
            re.sub(r",\s*([\]\}])", r"\1", raw),
        ]
        for attempt in salvage_attempts:
            try:
                doc = json.loads(attempt)
                if isinstance(doc, list):
                    fixed = [i for i in doc if isinstance(i, dict)]
                    if fixed:
                        log.info("[autocorrector] %s: salvaged %d records", tool_name, len(fixed))
                        return fixed
                if isinstance(doc, dict):
                    return [doc]
            except json.JSONDecodeError:
                continue

        log.warning("[autocorrector] %s: JSON unrecoverable — yielding empty findings", tool_name)
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL WRAPPERS
# ═══════════════════════════════════════════════════════════════════════════════

async def _run_wapiti(target: str, workspace: str, aggressive: bool = False) -> List[Dict[str, Any]]:
    """
    Wapiti web application scanner.

    Targets: sql, xss, file, xxe, blindsql, ssrf, redirect, htaccess, backup
    Produces: strict JSON output to temp file
    Degraded:  fewer modules, depth 1, lower timeout
    """
    if not _has("wapiti"):
        log.warning("[wapiti] not found in PATH — skipping")
        return []

    out_dir = Path(workspace) / "wapiti_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = str(out_dir / "wapiti_results.json")

    modules = "sql,xss,file,xxe,blindsql,ssrf,redirect,htaccess,backup,shellshock"
    degraded_modules = "sql,xss,file"

    base_cmd = [
        "wapiti",
        "-u", target,
        "-m", modules,
        "-d", "3",
        "-t", "20",
        "--flush-session",
        "-f", "json",
        "-o", out_file,
        "--max-scan-time", "480",
        "--max-parameters-count", "500",
        "--max-files-per-dir", "100",
        "--verify-ssl", "0",
    ]

    degraded_cmd = [
        "wapiti",
        "-u", target,
        "-m", degraded_modules,
        "-d", "1",
        "-t", "10",
        "--flush-session",
        "-f", "json",
        "-o", out_file,
        "--max-scan-time", "180",
        "--verify-ssl", "0",
    ]

    async with _HEAVY_SEM:
        stdout, stderr, rc = await AutoCorrector.run(
            base_cmd,
            tool_name="wapiti",
            timeout=_TIMEOUT["wapiti"],
            degraded_cmd=degraded_cmd,
            degraded_timeout=200,
        )

    # Wapiti writes results to file even on non-zero exit
    raw = ""
    try:
        if Path(out_file).exists():
            raw = Path(out_file).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.debug("[wapiti] output file read error: %s", exc)

    if not raw and stdout:
        raw = stdout

    return AutoCorrector.parse_json_output(raw, "wapiti")


async def _run_nuclei(targets: List[str], workspace: str) -> List[Dict[str, Any]]:
    """
    Nuclei template-based scanner.

    Templates: CVEs, exposed-panels, misconfigs, takeovers, tokens, default-logins
    Output:    JSONL to temp file
    WAF bypass: random-agent, header injection
    Degraded:  reduced rate, fewer template categories
    """
    if not _has("nuclei"):
        log.warning("[nuclei] not found in PATH — skipping")
        return []

    out_file = str(Path(workspace) / "nuclei_out.jsonl")

    # Write target list to temp file
    target_file = str(Path(workspace) / "nuclei_targets.txt")
    Path(target_file).write_text("\n".join(targets), encoding="utf-8")

    base_cmd = [
        "nuclei",
        "-l", target_file,
        "-t", "cves,exposed-panels,misconfigs,takeovers,technologies,default-logins,exposures",
        "-rl", "150",
        "-c", "50",
        "-timeout", "5",
        "-retries", "2",
        "-fr",                       # follow redirects
        "-random-agent",             # WAF evasion
        "-H", "X-Forwarded-For: 127.0.0.1",
        "-H", "X-Real-IP: 127.0.0.1",
        "-json-export", out_file,
        "-silent",
        "-no-color",
        "-stats",
    ]

    degraded_cmd = [
        "nuclei",
        "-l", target_file,
        "-t", "cves,exposed-panels",
        "-rl", "50",
        "-c", "20",
        "-timeout", "8",
        "-fr",
        "-random-agent",
        "-json-export", out_file,
        "-silent",
        "-no-color",
    ]

    async with _HEAVY_SEM:
        stdout, stderr, rc = await AutoCorrector.run(
            base_cmd,
            tool_name="nuclei",
            timeout=_TIMEOUT["nuclei"],
            degraded_cmd=degraded_cmd,
            degraded_timeout=240,
        )

    raw = ""
    try:
        if Path(out_file).exists():
            raw = Path(out_file).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.debug("[nuclei] output read error: %s", exc)

    if not raw and stdout:
        raw = stdout

    return AutoCorrector.parse_json_output(raw, "nuclei")


async def _run_ghauri(target: str, workspace: str) -> List[Dict[str, Any]]:
    """
    Ghauri advanced SQLi scanner.

    Batch mode: no interactive prompts
    Level 2:   tests more injection points (cookies, headers)
    Confirms:  validates every finding before reporting
    Degraded:  level 1, shorter timeout
    """
    if not _has("ghauri"):
        log.warning("[ghauri] not found in PATH — skipping")
        return []

    out_file = str(Path(workspace) / "ghauri_out.json")

    base_cmd = [
        "ghauri",
        "-u", target,
        "--batch",
        "--level", "2",
        "--confirm",
        "--timeout", "10",
        "--retries", "2",
        "--flush-session",
        "--output-dir", workspace,
        "--json",
    ]

    degraded_cmd = [
        "ghauri",
        "-u", target,
        "--batch",
        "--level", "1",
        "--timeout", "8",
        "--output-dir", workspace,
        "--json",
    ]

    async with _HEAVY_SEM:
        stdout, stderr, rc = await AutoCorrector.run(
            base_cmd,
            tool_name="ghauri",
            timeout=_TIMEOUT["ghauri"],
            degraded_cmd=degraded_cmd,
            degraded_timeout=150,
        )

    raw = stdout or ""
    try:
        if Path(out_file).exists():
            raw = Path(out_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass

    return AutoCorrector.parse_json_output(raw, "ghauri")


async def _run_dalfox(targets: List[str], workspace: str, blind_server: str = "") -> List[Dict[str, Any]]:
    """
    Dalfox XSS scanner.

    Input:    file with target URLs (supports GET params)
    Blind:    optional OOB callback server for blind XSS detection
    Workers:  50 concurrent goroutines
    Degraded: 10 workers, no blind server
    """
    if not _has("dalfox"):
        log.warning("[dalfox] not found in PATH — skipping")
        return []

    target_file = str(Path(workspace) / "dalfox_targets.txt")
    out_file = str(Path(workspace) / "dalfox_out.json")

    # Only include URLs with query parameters (dalfox needs injection points)
    injectable = [t for t in targets if "?" in t and "=" in t]
    if not injectable:
        log.info("[dalfox] no parameterized URLs — skipping")
        return []

    Path(target_file).write_text("\n".join(injectable), encoding="utf-8")

    base_cmd = [
        "dalfox",
        "file", target_file,
        "--silence",
        "--worker", "50",
        "--timeout", "10",
        "--format", "json",
        "--output", out_file,
        "--no-color",
        "--follow-redirects",
        "--skip-mining-dom",         # reduces noise
        "--header", "X-Forwarded-For: 127.0.0.1",
    ]

    if blind_server:
        base_cmd += ["-b", blind_server]

    degraded_cmd = [
        "dalfox",
        "file", target_file,
        "--silence",
        "--worker", "10",
        "--timeout", "15",
        "--format", "json",
        "--output", out_file,
        "--no-color",
    ]

    async with _HEAVY_SEM:
        stdout, stderr, rc = await AutoCorrector.run(
            base_cmd,
            tool_name="dalfox",
            timeout=_TIMEOUT["dalfox"],
            degraded_cmd=degraded_cmd,
            degraded_timeout=180,
        )

    raw = stdout or ""
    try:
        if Path(out_file).exists():
            raw = Path(out_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass

    return AutoCorrector.parse_json_output(raw, "dalfox")


async def _run_nikto(target: str, workspace: str) -> List[Dict[str, Any]]:
    """
    Nikto web server scanner.

    Tuning:   1 (interesting files), 2 (misconfigs), 3 (info disclosure),
              8 (injections), 0 (file upload)
    maxtime:  10 minutes hard cap
    Degraded: reduced tuning flags, 5m cap
    """
    if not _has("nikto"):
        log.warning("[nikto] not found in PATH — skipping")
        return []

    out_file = str(Path(workspace) / "nikto_out.json")

    base_cmd = [
        "nikto",
        "-h", target,
        "-Tuning", "12380",
        "-maxtime", "10m",
        "-Format", "json",
        "-output", out_file,
        "-nointeractive",
        "-ssl",
        "-C", "all",
    ]

    degraded_cmd = [
        "nikto",
        "-h", target,
        "-Tuning", "123",
        "-maxtime", "5m",
        "-Format", "json",
        "-output", out_file,
        "-nointeractive",
    ]

    async with _HEAVY_SEM:
        stdout, stderr, rc = await AutoCorrector.run(
            base_cmd,
            tool_name="nikto",
            timeout=_TIMEOUT["nikto"],
            degraded_cmd=degraded_cmd,
            degraded_timeout=340,
        )

    raw = stdout or ""
    try:
        if Path(out_file).exists():
            raw = Path(out_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass

    return AutoCorrector.parse_json_output(raw, "nikto")


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING NORMALIZERS
# (Each tool outputs different schema — normalize to ctx.add_finding() contract)
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_nuclei(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize a single Nuclei JSONL record."""
    if not isinstance(item, dict):
        return None
    try:
        info = item.get("info") or {}
        if not isinstance(info, dict):
            info = {}

        sev = (info.get("severity") or "medium").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "MEDIUM"

        template_id = str(item.get("template-id") or item.get("templateID") or "unknown")
        name = str(info.get("name") or template_id)
        host = str(item.get("host") or item.get("matched-at") or "")
        matched_at = str(item.get("matched-at") or host)
        description = str(info.get("description") or "")[:500]
        curl_command = str(item.get("curl-command") or "")[:300]
        matcher_name = str(item.get("matcher-name") or "")

        # Category inference
        tags: List[str] = []
        if isinstance(info.get("tags"), list):
            tags = [str(t).lower() for t in info["tags"]]
        elif isinstance(info.get("tags"), str):
            tags = [t.strip().lower() for t in info["tags"].split(",")]

        category = _infer_category_from_tags(tags, name)

        detail_parts = [description]
        if matcher_name:
            detail_parts.append(f"Matcher: {matcher_name}")
        if curl_command:
            detail_parts.append(f"PoC: {curl_command}")
        detail = "\n".join(p for p in detail_parts if p)

        return {
            "severity": sev,
            "category": category,
            "url": matched_at or host,
            "title": f"[Nuclei] {name}",
            "detail": detail,
            "impact": "",
            "exploit": curl_command,
            "confidence": "HIGH",
            "cwe": "",
            "phase": "step13_vulnscan",
        }
    except Exception as exc:
        log.debug("[nuclei] normalize error: %s — item: %s", exc, str(item)[:100])
        return None


def _normalize_wapiti(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize a single Wapiti vulnerability record."""
    if not isinstance(item, dict):
        return None
    try:
        vuln_type = str(item.get("type") or item.get("category") or "Unknown")
        url = str(item.get("path") or item.get("url") or item.get("http_request", "")[:100])
        level = int(item.get("level") or 1)
        info = str(item.get("info") or item.get("description") or "")[:500]
        parameter = str(item.get("parameter") or "")
        http_req = str(item.get("http_request") or "")[:500]

        sev_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}
        sev = sev_map.get(level, "MEDIUM")

        category = _infer_category_from_name(vuln_type)

        detail_parts = [info]
        if parameter:
            detail_parts.append(f"Parameter: {parameter}")
        if http_req:
            detail_parts.append(f"Request:\n{http_req}")

        return {
            "severity": sev,
            "category": category,
            "url": url,
            "title": f"[Wapiti] {vuln_type}",
            "detail": "\n".join(p for p in detail_parts if p),
            "impact": "",
            "exploit": http_req[:300],
            "confidence": "MEDIUM",
            "cwe": str(item.get("cwe") or ""),
            "phase": "step13_vulnscan",
        }
    except Exception as exc:
        log.debug("[wapiti] normalize error: %s", exc)
        return None


def _normalize_ghauri(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize a Ghauri SQLi finding."""
    if not isinstance(item, dict):
        return None
    try:
        url = str(item.get("url") or item.get("target") or "")
        parameter = str(item.get("parameter") or "")
        technique = str(item.get("technique") or item.get("type") or "SQLi")
        payload = str(item.get("payload") or "")[:200]
        dbms = str(item.get("dbms") or "")

        detail_parts = []
        if parameter:
            detail_parts.append(f"Parameter: {parameter}")
        if technique:
            detail_parts.append(f"Technique: {technique}")
        if dbms:
            detail_parts.append(f"DBMS: {dbms}")
        if payload:
            detail_parts.append(f"Payload: {payload}")

        return {
            "severity": "HIGH",
            "category": "SQLI",
            "url": url,
            "title": f"[Ghauri] SQL Injection — {parameter or 'unknown param'}",
            "detail": "\n".join(detail_parts),
            "impact": "Database read/write, potential RCE via INTO OUTFILE or xp_cmdshell",
            "exploit": payload,
            "confidence": "HIGH",
            "cwe": "CWE-89",
            "phase": "step13_vulnscan",
        }
    except Exception as exc:
        log.debug("[ghauri] normalize error: %s", exc)
        return None


def _normalize_dalfox(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize a Dalfox XSS finding."""
    if not isinstance(item, dict):
        return None
    try:
        url = str(item.get("data") or item.get("url") or item.get("param_url") or "")
        payload = str(item.get("evidence") or item.get("payload") or "")[:300]
        param = str(item.get("parameter") or item.get("param") or "")
        ctype = str(item.get("type") or "Reflected XSS")
        message = str(item.get("message") or "")[:200]
        poc = str(item.get("poc") or item.get("PoC") or payload)[:300]

        detail_parts = []
        if param:
            detail_parts.append(f"Parameter: {param}")
        if message:
            detail_parts.append(f"Detail: {message}")
        if poc:
            detail_parts.append(f"PoC: {poc}")

        return {
            "severity": "HIGH",
            "category": "XSS_REFLECTED",
            "url": url,
            "title": f"[Dalfox] {ctype} — {param or 'unknown param'}",
            "detail": "\n".join(detail_parts),
            "impact": "Session hijacking, credential theft, DOM manipulation, phishing",
            "exploit": poc,
            "confidence": "HIGH",
            "cwe": "CWE-79",
            "phase": "step13_vulnscan",
        }
    except Exception as exc:
        log.debug("[dalfox] normalize error: %s", exc)
        return None


def _normalize_nikto(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize a Nikto finding record."""
    if not isinstance(item, dict):
        return None
    try:
        # Nikto JSON wraps results under host-level objects
        # This normalizer handles both flat records and nested vuln entries
        osvdb = str(item.get("OSVDB") or item.get("id") or "")
        url = str(item.get("url") or item.get("namelink") or "")
        method = str(item.get("method") or "GET")
        msg = str(item.get("msg") or item.get("message") or item.get("description") or "")[:500]
        uri = str(item.get("uri") or "")

        if not msg:
            return None

        full_url = url or uri
        category = _infer_category_from_name(msg)

        sev = "LOW"
        msg_lower = msg.lower()
        if any(k in msg_lower for k in ("injection", "rce", "execute", "remote", "command")):
            sev = "HIGH"
        elif any(k in msg_lower for k in ("disclosure", "exposed", "password", "credentials", "config")):
            sev = "MEDIUM"

        osvdb_ref = f" [OSVDB-{osvdb}]" if osvdb and osvdb != "0" else ""

        return {
            "severity": sev,
            "category": category,
            "url": full_url,
            "title": f"[Nikto]{osvdb_ref} {msg[:80]}",
            "detail": f"{method} {full_url}\n{msg}",
            "impact": "",
            "exploit": f"{method} {full_url}",
            "confidence": "LOW",
            "cwe": "",
            "phase": "step13_vulnscan",
        }
    except Exception as exc:
        log.debug("[nikto] normalize error: %s", exc)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# CATEGORY INFERENCE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _infer_category_from_tags(tags: List[str], name: str) -> str:
    name_lower = name.lower()
    joined = " ".join(tags) + " " + name_lower
    if "xss" in joined:
        return "XSS_REFLECTED"
    if "sqli" in joined or "sql" in joined:
        return "SQLI"
    if "ssrf" in joined:
        return "SSRF"
    if "lfi" in joined or "path-traversal" in joined:
        return "LFI"
    if "ssti" in joined:
        return "SSTI"
    if "crlf" in joined:
        return "CRLF_INJECTION"
    if "cors" in joined:
        return "CORS_MISCONFIG"
    if "takeover" in joined or "subdomain" in joined:
        return "SUBDOMAIN_TAKEOVER"
    if "exposure" in joined or "disclosure" in joined or "token" in joined:
        return "SECRET_LEAK"
    if "default" in joined and ("login" in joined or "cred" in joined):
        return "SECRET_LEAK"
    if "panel" in joined or "admin" in joined:
        return "CONTENT_DISCOVERY"
    if "cve" in joined:
        return "TECH_CVE"
    return "TECH_CVE"


def _infer_category_from_name(name: str) -> str:
    nl = name.lower()
    if "xss" in nl or "cross-site scripting" in nl:
        return "XSS_REFLECTED"
    if "sql" in nl:
        return "SQLI"
    if "ssrf" in nl:
        return "SSRF"
    if "lfi" in nl or "path traversal" in nl or "directory traversal" in nl:
        return "LFI"
    if "ssti" in nl or "template injection" in nl:
        return "SSTI"
    if "crlf" in nl:
        return "CRLF_INJECTION"
    if "cors" in nl:
        return "CORS_MISCONFIG"
    if "open redirect" in nl:
        return "OPEN_REDIRECT"
    if "sensitive" in nl or "disclosure" in nl or "exposed" in nl:
        return "SECRET_LEAK"
    if "backup" in nl or "config" in nl:
        return "CONTENT_DISCOVERY"
    return "TECH_CVE"


# ═══════════════════════════════════════════════════════════════════════════════
# NESSUS INTEGRATION RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

async def _run_nessus(ctx: Ctx, workspace: str) -> List[Dict[str, Any]]:
    """
    Launch Nessus scan via REST API, poll to completion, fetch Critical/High.

    Requires ctx environment variables:
      NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY
    Optional:
      NESSUS_POLICY_ID (default: 0 — uses basic network scan template)
    """
    nessus_url = os.environ.get("NESSUS_URL", "")
    access_key = os.environ.get("NESSUS_ACCESS_KEY", "")
    secret_key = os.environ.get("NESSUS_SECRET_KEY", "")

    if not all([nessus_url, access_key, secret_key]):
        log.info("[nessus] credentials not configured — skipping (set NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY)")
        return []

    from core.nessus_client import NessusClient

    policy_id = int(os.environ.get("NESSUS_POLICY_ID", "0"))
    client = NessusClient(
        base_url=nessus_url,
        access_key=access_key,
        secret_key=secret_key,
        verify_ssl=False,
        timeout=30.0,
    )

    try:
        # Health check before committing to full scan
        alive = await client.health_check()
        if not alive:
            log.warning("[nessus] health check failed — skipping")
            return []

        target = ctx.target_url if hasattr(ctx, "target_url") else ctx.url
        scan_uuid = await client.launch_scan(policy_id=policy_id, target=target)
        log.info("[nessus] scan launched: %s", scan_uuid)

        # Non-blocking poll with overall timeout guard
        try:
            final_status = await asyncio.wait_for(
                client.poll_scan(scan_uuid),
                timeout=float(_TIMEOUT["nessus"]),
            )
        except asyncio.TimeoutError:
            log.warning("[nessus] scan poll timed out after %ds — fetching partial results", _TIMEOUT["nessus"])
            final_status = "timeout"

        if final_status in ("aborted", "canceled", "error"):
            log.warning("[nessus] scan ended with status: %s", final_status)
            return []

        return await client.fetch_results(scan_uuid)

    except Exception as exc:
        log.error("[nessus] fatal error: %s", exc)
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING DEDUPLICATION + PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════

def _dedup_and_persist(
    ctx: Ctx,
    raw_findings: List[Optional[Dict[str, Any]]],
    source_tag: str,
) -> int:
    """Deduplicate findings and persist to ctx. Returns count added."""
    seen: set[str] = set()
    added = 0

    for finding in raw_findings:
        if not finding or not isinstance(finding, dict):
            continue

        # Composite dedup key: category + url (normalized) + title prefix
        key = (
            f"{finding.get('category', '')}|"
            f"{finding.get('url', '')[:100]}|"
            f"{finding.get('title', '')[:60]}"
        )
        if key in seen:
            continue
        seen.add(key)

        try:
            ctx.add_finding(
                severity=finding.get("severity", "LOW"),
                category=finding.get("category", "TECH_CVE"),
                url=finding.get("url", ctx.url),
                title=finding.get("title", "Unknown"),
                detail=finding.get("detail", ""),
                impact=finding.get("impact", ""),
                exploit=finding.get("exploit", ""),
                confidence=finding.get("confidence", "LOW"),
                cwe=finding.get("cwe", ""),
                phase=finding.get("phase", f"step13_{source_tag}"),
            )
            added += 1
        except Exception as exc:
            log.debug("[step13] ctx.add_finding error (%s): %s", source_tag, exc)

    return added


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

async def run(ctx: Ctx) -> None:
    """
    Step 13: Enterprise Vulnerability Scanning Pipeline.

    Execution order (all concurrent where safe):
      1. Nessus REST API scan (independent, long-running)
      2. Nuclei (all live hosts)
      3. Wapiti (primary target)
      4. Dalfox (parameterized URLs from ctx)
      5. Ghauri (primary target + API endpoints)
      6. Nikto (primary target)

    All findings are normalized, deduplicated, and persisted via ctx.add_finding().
    """
    workspace: str = ctx.workspace if hasattr(ctx, "workspace") else str(Path.cwd())
    target: str = ctx.url
    domain: str = ctx.domain
    aggressive: bool = getattr(ctx, "aggressive", False) if hasattr(ctx, "aggressive") else False

    # Derive blind server from env (for Dalfox blind XSS)
    blind_server: str = os.environ.get("BLIND_XSS_SERVER", "")

    # Collect live hosts for tools that support multi-target input
    live_hosts: List[str] = []
    try:
        live_hosts = ctx.live_host_urls() or [target]
    except Exception:
        live_hosts = [target]

    # Collect parameterized URLs for Dalfox
    parameterized_urls: List[str] = []
    try:
        all_urls = list(ctx.urls) if ctx.urls else [target]
        parameterized_urls = [u for u in all_urls if "?" in u and "=" in u][:500]
    except Exception:
        parameterized_urls = []

    # ─── Progress display ─────────────────────────────────────────────────────
    console = Console() if _RICH else None
    if _RICH and console:
        console.rule(f"[bold cyan]STEP {STEP_NUM}: {STEP_NAME}[/bold cyan]")
        console.print(f"  Target   : [white]{target}[/white]")
        console.print(f"  Live hosts: [white]{len(live_hosts)}[/white]")
        console.print(f"  Param URLs: [white]{len(parameterized_urls)}[/white]")
    else:
        log.info("[step13] target=%s live_hosts=%d param_urls=%d", target, len(live_hosts), len(parameterized_urls))

    total_added = 0

    # ─── Phase 1: Launch Nessus independently (long-running, non-blocking) ───
    nessus_task: asyncio.Task[List[Dict[str, Any]]] = asyncio.create_task(
        _run_nessus(ctx, workspace)
    )

    # ─── Phase 2: Concurrent CLI tools ───────────────────────────────────────
    nuclei_task = asyncio.create_task(_run_nuclei(live_hosts, workspace))
    wapiti_task = asyncio.create_task(_run_wapiti(target, workspace, aggressive))
    nikto_task  = asyncio.create_task(_run_nikto(target, workspace))

    # Run Phase 2 concurrently
    nuclei_raw, wapiti_raw, nikto_raw = await asyncio.gather(
        nuclei_task, wapiti_task, nikto_task,
        return_exceptions=False,
    )

    # ─── Phase 3: Dalfox + Ghauri (require parameterized input) ──────────────
    dalfox_task = asyncio.create_task(
        _run_dalfox(parameterized_urls or [target], workspace, blind_server)
    )
    ghauri_task = asyncio.create_task(_run_ghauri(target, workspace))

    dalfox_raw, ghauri_raw = await asyncio.gather(
        dalfox_task, ghauri_task,
        return_exceptions=False,
    )

    # ─── Await Nessus (was running in background during Phases 2+3) ──────────
    try:
        nessus_raw: List[Dict[str, Any]] = await asyncio.wait_for(
            nessus_task, timeout=120.0  # Give it 2 more minutes if still running
        )
    except asyncio.TimeoutError:
        nessus_task.cancel()
        nessus_raw = []
        log.warning("[step13] Nessus task exceeded final wait — results discarded")
    except Exception as exc:
        nessus_raw = []
        log.error("[step13] Nessus task exception: %s", exc)

    # ─── Normalize + Persist ──────────────────────────────────────────────────

    # Nuclei
    nuclei_normalized = [_normalize_nuclei(i) for i in (nuclei_raw or [])]
    n = _dedup_and_persist(ctx, nuclei_normalized, "nuclei")
    total_added += n
    log.info("[step13] nuclei: %d findings → %d persisted", len(nuclei_raw or []), n)

    # Wapiti
    # Wapiti nests findings under vulnerability categories — flatten if needed
    wapiti_flat: List[Dict[str, Any]] = []
    for item in (wapiti_raw or []):
        if isinstance(item, dict):
            # Check if this is a category container
            for key, val in item.items():
                if isinstance(val, list):
                    for sub in val:
                        if isinstance(sub, dict):
                            sub.setdefault("category", key)
                            wapiti_flat.append(sub)
                    break
            else:
                wapiti_flat.append(item)

    wapiti_normalized = [_normalize_wapiti(i) for i in wapiti_flat]
    n = _dedup_and_persist(ctx, wapiti_normalized, "wapiti")
    total_added += n
    log.info("[step13] wapiti: %d findings → %d persisted", len(wapiti_flat), n)

    # Dalfox
    dalfox_normalized = [_normalize_dalfox(i) for i in (dalfox_raw or [])]
    n = _dedup_and_persist(ctx, dalfox_normalized, "dalfox")
    total_added += n
    log.info("[step13] dalfox: %d findings → %d persisted", len(dalfox_raw or []), n)

    # Ghauri
    ghauri_normalized = [_normalize_ghauri(i) for i in (ghauri_raw or [])]
    n = _dedup_and_persist(ctx, ghauri_normalized, "ghauri")
    total_added += n
    log.info("[step13] ghauri: %d findings → %d persisted", len(ghauri_raw or []), n)

    # Nikto — handle Nikto's nested JSON structure
    nikto_flat: List[Dict[str, Any]] = []
    for item in (nikto_raw or []):
        if not isinstance(item, dict):
            continue
        # Nikto can nest under "host" → "vulnerabilities"
        vulns = item.get("vulnerabilities") or item.get("items")
        if isinstance(vulns, list):
            nikto_flat.extend(v for v in vulns if isinstance(v, dict))
        else:
            nikto_flat.append(item)

    nikto_normalized = [_normalize_nikto(i) for i in nikto_flat]
    n = _dedup_and_persist(ctx, nikto_normalized, "nikto")
    total_added += n
    log.info("[step13] nikto: %d findings → %d persisted", len(nikto_flat), n)

    # Nessus (already normalized by NessusClient.fetch_results)
    n = _dedup_and_persist(ctx, nessus_raw, "nessus")
    total_added += n
    log.info("[step13] nessus: %d findings → %d persisted", len(nessus_raw), n)

    # ─── Checkpoint ───────────────────────────────────────────────────────────
    try:
        ctx.save_checkpoint(STEP_NUM)
    except Exception as exc:
        log.warning("[step13] checkpoint save failed: %s", exc)

    # ─── Summary ──────────────────────────────────────────────────────────────
    sev_counts = ctx.findings_by_severity() if hasattr(ctx, "findings_by_severity") else {}

    if _RICH and console:
        console.print(f"\n  [bold green]✓ Step {STEP_NUM} complete[/bold green] — "
                      f"[yellow]{total_added}[/yellow] new findings persisted")
        if sev_counts:
            for sev, cnt in sorted(sev_counts.items()):
                color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "blue"}.get(sev, "white")
                console.print(f"    [{color}]{sev:<8}[/{color}]: {cnt}")
    else:
        log.info("[step13] complete — %d findings added | severity breakdown: %s", total_added, sev_counts)


# ═══════════════════════════════════════════════════════════════════════════
# v15 ADAPTER — conform to the pipeline contract execute(ctx, engine, config)
# ═══════════════════════════════════════════════════════════════════════════
async def execute(ctx: "Ctx", engine: Any = None, config: Any = None) -> "Ctx":
    """Pipeline entrypoint. Bridges Config -> the attributes run() expects,
    then delegates to the full enterprise scan implemented above.

    This is what makes the (formerly orphaned) 42KB scanner actually run.
    """
    # run() reads ctx.workspace and ctx.aggressive; source them from config.
    if config is not None:
        if not getattr(ctx, "workspace", ""):
            try:
                ctx.workspace = getattr(config, "workspace", "") or str(Path.cwd())
            except Exception:
                pass
        if not hasattr(ctx, "aggressive"):
            try:
                ctx.aggressive = bool(getattr(config, "aggressive", False))
            except Exception:
                ctx.aggressive = False
    try:
        await run(ctx)
    except Exception as exc:  # never let one scanner kill the pipeline
        log.error("[step13/execute] vulnscan failed: %s", exc)
    return ctx
