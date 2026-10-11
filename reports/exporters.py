"""
GHOST RECON v2.0 — reports/exporters.py
Machine-readable and plain-text exports next to the HTML report.

  findings.json  — full scan summary + findings (pipe into jq, ticketing, diffing)
  report.md      — triage-ready Markdown (paste into an issue / bug bounty draft)
  findings.sarif — SARIF 2.1.0 for GitHub code scanning / CI dashboards

All exports carry the redacted config only; credentials never leave ghost.db.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from core.config import VERSION, SEVERITIES

__all__ = ["build_summary", "export_json", "export_markdown", "export_sarif", "export_all"]

_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
_SARIF_SCORE = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "0.0"}


def build_summary(ctx: Any, config: Any, elapsed: float) -> Dict[str, Any]:
    stats = ctx.stats()
    sev = ctx.findings_by_severity()
    return {
        "tool": {"name": "ghost", "version": VERSION},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan": {
            "scan_id": ctx.scan_id,
            "target": ctx.target,
            "domain": ctx.domain,
            "root_domain": ctx.root_domain,
            "scope": ctx.scope,
            "scope_rules": ctx.scope_guard.describe() if getattr(ctx, "scope_guard", None) else "",
            "stealth": ctx.stealth,
            "waf": ctx.waf_detected,
            "cdn": ctx.cdn_detected,
            "origin_ip": ctx.origin_ip,
            "tech_stack": ctx.tech_stack,
            "duration_seconds": int(elapsed),
            "completed_steps": sorted(getattr(ctx, "completed_steps", set())),
            "out_of_scope_assets_dropped": len(getattr(ctx, "out_of_scope_hosts", ())),
        },
        "stats": stats,
        "severity_counts": {s: sev.get(s, 0) for s in SEVERITIES},
        "findings": ctx.findings,
        "config": config.to_dict(redact=True) if hasattr(config, "to_dict") else {},
    }


def export_json(summary: Dict[str, Any], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)
    return path


def _md_cell(v: Any, limit: int = 80) -> str:
    s = str(v or "").replace("|", "\\|").replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _fence(text: str) -> str:
    # Pick a fence longer than any backtick run in the content.
    longest, run = 0, 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def export_markdown(summary: Dict[str, Any], path: str) -> str:
    sc = summary["scan"]
    st = summary["stats"]
    sev = summary["severity_counts"]
    fnd: List[Dict[str, Any]] = summary["findings"]
    out: List[str] = []
    out.append(f"# Ghost recon report — {sc['domain']}\n")
    out.append(f"*Generated {summary['generated_at']} by ghost v{summary['tool']['version']}*\n")
    out.append("| | |\n|---|---|")
    for k, v in (("Target", sc["target"]), ("Scope", f"{sc['scope']} ({sc['scope_rules']})"),
                 ("Stealth", sc["stealth"]), ("WAF / CDN", f"{', '.join(map(str, sc['waf'])) or '—'} / {sc['cdn'] or '—'}"),
                 ("Origin IP", sc["origin_ip"] or "—"), ("Duration", f"{sc['duration_seconds'] // 60}m {sc['duration_seconds'] % 60}s"),
                 ("Scan ID", sc["scan_id"])):
        out.append(f"| **{k}** | {_md_cell(v, 120)} |")
    out.append("")
    out.append("## Attack surface\n")
    out.append("| Subdomains | Live hosts | URLs | JS files | Params | API endpoints | Ports | Secrets |")
    out.append("|---:|---:|---:|---:|---:|---:|---:|---:|")
    out.append("| " + " | ".join(str(st.get(k, 0)) for k in
               ("subdomains", "live_hosts", "urls", "js_files", "params", "api_endpoints", "ports", "secrets")) + " |")
    if sc.get("out_of_scope_assets_dropped"):
        out.append(f"\n> {sc['out_of_scope_assets_dropped']} out-of-scope assets were discovered and dropped "
                   f"(see `recon/out_of_scope.txt`); none were probed.")
    out.append("\n## Findings\n")
    out.append(" · ".join(f"**{s}** {sev.get(s, 0)}" for s in SEVERITIES) + "\n")
    if not fnd:
        out.append("_No automated findings. Manual testing recommended._\n")
    else:
        out.append("| # | Severity | CVSS | Category | CWE | Title | URL | Confidence |")
        out.append("|---:|---|---:|---|---|---|---|---|")
        for i, f in enumerate(fnd, 1):
            out.append(f"| {i} | {f.get('severity','')} | {float(f.get('cvss_score') or 0):.1f} | "
                       f"{_md_cell(f.get('category'), 24)} | {_md_cell(f.get('cwe'), 12)} | "
                       f"{_md_cell(f.get('title'), 70)} | {_md_cell(f.get('url'), 70)} | {_md_cell(f.get('confidence'), 10)} |")
        out.append("\n## Details\n")
        for i, f in enumerate(fnd, 1):
            out.append(f"### {i}. [{f.get('severity','')}] {_md_cell(f.get('title'), 200)}\n")
            out.append(f"- **URL:** `{_md_cell(f.get('url'), 300).replace('`', '')}`")
            meta = [x for x in (f.get("category"), f.get("cwe"), f.get("owasp")) if x]
            if meta:
                out.append(f"- **Class:** {' · '.join(map(str, meta))}")
            out.append(f"- **Confidence:** {f.get('confidence','')}  ·  **Phase:** {f.get('phase','')}")
            for label, key in (("Detail", "detail"), ("Impact", "impact")):
                if f.get(key):
                    out.append(f"\n**{label}:** {str(f[key]).strip()}")
            if f.get("exploit"):
                body = str(f["exploit"]).strip()
                fence = _fence(body)
                out.append(f"\n**Reproduction:**\n\n{fence}\n{body}\n{fence}")
            out.append("\n> Automated finding — verify manually before reporting.\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    return path


def export_sarif(summary: Dict[str, Any], path: str) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for f in summary["findings"]:
        sev = str(f.get("severity", "INFO")).upper()
        rule_id = str(f.get("category") or "GENERIC")
        if rule_id not in rules:
            rule: Dict[str, Any] = {
                "id": rule_id,
                "name": rule_id.title().replace("_", ""),
                "shortDescription": {"text": rule_id.replace("_", " ").title()},
                "properties": {"tags": ["security"] + [t for t in (f.get("cwe"), f.get("owasp")) if t]},
            }
            rules[rule_id] = rule
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": f"{f.get('title','')}\n{f.get('detail','')}".strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("url") or summary["scan"]["target"]}}}],
            "partialFingerprints": {"ghost/v1": f"{rule_id}|{f.get('url','')}|{f.get('title','')}"},
            "properties": {
                "severity": sev,
                "security-severity": str(f.get("cvss_score") or _SARIF_SCORE.get(sev, "0.0")),
                "confidence": f.get("confidence", ""),
                "cwe": f.get("cwe", ""),
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ghost", "version": VERSION,
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, default=str)
    return path


def export_all(ctx: Any, config: Any, elapsed: float, formats: List[str], reports_dir: str) -> Dict[str, str]:
    """Write every requested non-HTML format. Returns {format: path}."""
    os.makedirs(reports_dir, exist_ok=True)
    summary = build_summary(ctx, config, elapsed)
    written: Dict[str, str] = {}
    if "json" in formats:
        written["json"] = export_json(summary, os.path.join(reports_dir, "findings.json"))
    if "md" in formats:
        written["md"] = export_markdown(summary, os.path.join(reports_dir, "report.md"))
    if "sarif" in formats:
        written["sarif"] = export_sarif(summary, os.path.join(reports_dir, "findings.sarif"))
    return written
