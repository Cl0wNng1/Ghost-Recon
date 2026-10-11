"""
GHOST RECON v2.0 — reports/html_report.py
Self-contained HTML Dashboard Report with Manual Validation Steps

Upgrades over the previous internal build:
  - VALIDATION MATRIX: Maps every vulnerability category to concrete manual
    verification commands (curl, nmap, nc, Burp Repeater instructions).
  - DYNAMIC INJECTION: Each finding card renders a "Manual Verification" block
    with context-aware commands populated from the finding's URL/IP/port.
  - Screenshot galleries, Chart.js severity/category charts, origin IP alert.
  - Single self-contained HTML file (Tailwind CDN + Chart.js CDN).
"""

from __future__ import annotations

import html as _html
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List


# ═══════════════════════════════════════════════════════════════════════════════
# MANUAL VALIDATION MATRIX
# ═══════════════════════════════════════════════════════════════════════════════
# Maps vulnerability category → list of manual verification step templates.
# Placeholders: {url}, {ip}, {port}, {domain}, {path}, {param}

VALIDATION_MATRIX: Dict[str, List[str]] = {
    "OPEN_PORTS": [
        "nc -nv {ip} {port}",
        "nmap -p {port} -sV -sC {ip}",
        "curl -sk https://{ip}:{port}/ -H 'Host: {domain}' -o /dev/null -w '%{{http_code}}'",
    ],
    "SECRET_LEAK": [
        "curl -s '{url}' | grep -iE '(api[_-]?key|secret|token|password|auth)'",
        "curl -s '{url}' | python3 -m json.tool 2>/dev/null || cat",
        "# Validate: If AWS key → aws sts get-caller-identity --access-key-id <KEY>",
    ],
    "EXPOSED_SECRET": [
        "curl -s '{url}' | grep -iE '(api[_-]?key|secret|token|password)'",
        "# AWS: aws sts get-caller-identity --access-key-id <KEY>",
        "# GCP: curl -H 'Authorization: Bearer <TOKEN>' https://www.googleapis.com/oauth2/v1/tokeninfo",
        "# Stripe: curl https://api.stripe.com/v1/charges -u sk_live_<KEY>:",
    ],
    "SSTI": [
        "# Inject detection payload in Burp Repeater:",
        "curl -s '{url}' --data 'input={{{{7*7}}}}'",
        "curl -s '{url}' --data 'input=${{7*7}}'",
        "# Confirm: response contains '49' → engine identified",
        "# Escalate: tplmap -u '{url}' -d 'input=*' --os-shell",
    ],
    "XSS_REFLECTED": [
        "# 1. Confirm reflection in browser DevTools (Elements tab):",
        "curl -s '{url}' | grep -i '<script\\|onerror\\|onload\\|alert'",
        "# 2. Check CSP header:",
        "curl -sI '{url}' | grep -i content-security-policy",
        "# 3. Manual test in browser: paste payload in param, check execution",
        "# 4. If CSP blocks inline: try event handlers (onfocus, onmouseover)",
    ],
    "SQLI": [
        "# Confirm injectable param in Burp Repeater:",
        "ghauri -u '{url}' --batch --dbs",
        "sqlmap -u '{url}' --batch --risk=2 --level=3 --dbs",
        "# Time-based blind: append ' AND SLEEP(10)-- to param, measure delay",
    ],
    "NUCLEI_VULN": [
        "nuclei -u '{url}' -t <template-id> -debug",
        "curl -sk '{url}' -o /dev/null -w '%{{http_code}}\\n' -D -",
        "# Cross-verify with manual request in Burp Repeater",
    ],
    "CACHE_POISON": [
        "# 1. Baseline (clean request):",
        "curl -sI '{url}' | grep -iE '(x-cache|age|cf-cache|x-varnish)'",
        "# 2. Test unkeyed input reflection:",
        "curl -sI '{url}' -H 'X-Forwarded-Host: evil.com'",
        "curl -sI '{url}' -H 'X-Forwarded-Scheme: http'",
        "# 3. If reflected: repeat without header, check if cached (poisoned)",
    ],
    "CACHE_POISONING": [
        "curl -sI '{url}' | grep -iE '(x-cache|age|cf-cache|x-varnish)'",
        "curl -sI '{url}' -H 'X-Forwarded-Host: evil.com'",
        "curl -sI '{url}' -H 'X-Forwarded-Scheme: http'",
        "# Compare responses: if header reflection persists without header → poisoned",
    ],
    "CONTENT_DISCOVERY": [
        "curl -sk '{url}' -o /dev/null -w 'HTTP %{{http_code}} | Size: %{{size_download}}B\\n'",
        "curl -sk '{url}' | head -50",
        "# Verify: is this a real file or a soft-404/catch-all?",
    ],
    "CDN_BYPASS": [
        "curl -sk https://{ip}/ -H 'Host: {domain}' -o /dev/null -w '%{{http_code}}'",
        "curl -sk https://{ip}/ -H 'Host: {domain}' | head -30",
        "# Compare response with CDN-fronted version:",
        "diff <(curl -sk https://{domain}/ | head -50) <(curl -sk https://{ip}/ -H 'Host: {domain}' | head -50)",
        "nmap -sV -p 80,443,8080,8443 {ip}",
    ],
    "ORIGIN_EXPOSED": [
        "nmap -sV -p 80,443,8080 {ip}",
        "curl -sk https://{ip}/ -H 'Host: {domain}'",
        "# Full bypass: add to /etc/hosts → {ip} {domain} → browse normally",
    ],
    "SHODAN_VULNS": [
        "shodan host {ip}",
        "searchsploit <CVE-ID>",
        "nmap --script=vuln -p <ports> {ip}",
        "# Check exploit-db.com for working PoCs",
    ],
    "SHODAN_CVE": [
        "shodan host {ip}",
        "searchsploit <CVE-ID>",
        "nmap -sV --script=vuln {ip}",
    ],
    "LFI": [
        "curl -s '{url}' | head -20",
        "# Confirm /etc/passwd read:",
        "curl -s '{url}../../../../etc/passwd'",
        "# PHP wrappers:",
        "curl -s '{url}php://filter/convert.base64-encode/resource=index.php'",
        "# Log poisoning: inject payload in User-Agent → include access.log",
    ],
    "CRLF_INJECTION": [
        "curl -sI '{url}%0d%0aSet-Cookie:ghost=1'",
        "curl -sI '{url}%0d%0aX-Injected:true'",
        "# Check if injected header appears in response headers",
    ],
    "CORS_MISCONFIG": [
        "curl -sI '{url}' -H 'Origin: https://evil.com' | grep -i 'access-control'",
        "curl -sI '{url}' -H 'Origin: null' | grep -i 'access-control'",
        "# If Access-Control-Allow-Origin reflects evil.com → exploitable",
    ],
    "SUBDOMAIN_TAKEOVER": [
        "dig CNAME {domain}",
        "# Verify: CNAME target returns NXDOMAIN or service error page",
        "# Claim: register the dangling CNAME target on the service provider",
        "host {domain}",
    ],
    "HTTP_SMUGGLING": [
        "python3 smuggler.py -u '{url}' --log-level warning",
        "# Manual CL.TE test in Burp Repeater:",
        "# Send POST with Content-Length: 6 and Transfer-Encoding: chunked",
        "# Body: 0\\r\\n\\r\\nG  → if next request returns 405 → desync confirmed",
    ],
    "GRAPHQL_INTROSPECTION": [
        "curl -s '{url}' -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' | python3 -m json.tool",
        "# Import schema into InQL (Burp extension) → test all mutations",
        "# Check for missing auth on sensitive mutations",
    ],
    "SSRF": [
        "# Test with Burp Collaborator / interactsh:",
        "curl '{url}?url=http://YOUR_COLLAB_URL'",
        "# Cloud metadata: curl '{url}?url=http://169.254.169.254/latest/meta-data/'",
    ],
    "IDOR": [
        "# Create two accounts (A and B)",
        "# Copy object ID from account A's request",
        "# Replay with account B's session token → check if data returned",
        "curl -s '{url}' -H 'Authorization: Bearer <TOKEN_B>'",
    ],
    "JWT_VULN": [
        "# Decode at https://jwt.io",
        "# Test none algorithm: change alg to 'none', remove signature",
        "# Test weak secret: hashcat -m 16500 <jwt> rockyou.txt",
    ],
    "MASS_ASSIGNMENT": [
        "# Add privilege fields to POST/PUT body:",
        'curl -X POST \'{url}\' -H \'Content-Type: application/json\' -d \'{{\"role\":\"admin\",\"is_admin\":true}}\'',
        "# Check if role/privilege persisted in subsequent GET",
    ],
}

# Fallback for unmapped categories
_DEFAULT_STEPS = [
    "curl -sk '{url}' -o /dev/null -w 'HTTP %{{http_code}} | Size: %{{size_download}}B\\n'",
    "curl -sk '{url}' -D - | head -40",
    "# Manual verification in browser or Burp Repeater required",
]


def _get_validation_steps(finding: Dict[str, Any], domain: str) -> List[str]:
    """
    Get manual validation steps for a finding, with placeholders resolved.
    """
    category = finding.get("category", "")
    url = finding.get("url", "")
    ip = ""
    port = ""

    # Extract IP and port from URL or finding fields
    if url:
        import re
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", url)
        if ip_match:
            ip = ip_match.group(1)
        port_match = re.search(r":(\d+)", url.split("//", 1)[-1] if "//" in url else url)
        if port_match:
            port = port_match.group(1)

    if not ip:
        ip = finding.get("url", "").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    templates = VALIDATION_MATRIX.get(category, _DEFAULT_STEPS)

    steps = []
    for tmpl in templates:
        step = tmpl.replace("{url}", url or "<URL>")
        step = step.replace("{ip}", ip or "<IP>")
        step = step.replace("{port}", port or "<PORT>")
        step = step.replace("{domain}", domain or "<DOMAIN>")
        steps.append(step)

    return steps


# ═══════════════════════════════════════════════════════════════════════════════
# HTML GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_html(
    ctx: Any, config: Any, output_path: str, elapsed: float
) -> str:
    """Generate a single self-contained HTML report file."""
    try:
        stats = ctx.stats()
        findings = ctx.findings
        sev_counts = ctx.findings_by_severity()
        diff = ctx.diff_previous()
    except Exception:
        stats = {}
        findings = []
        sev_counts = {}
        diff = None

    # ─── Build validation steps into findings data ────────────────────────
    enriched_findings = []
    for f in findings[:200]:
        ef = dict(f)
        try:
            ef["validation_steps"] = _get_validation_steps(f, ctx.domain)
        except Exception:
            ef["validation_steps"] = _DEFAULT_STEPS
        enriched_findings.append(ef)

    scan_data = {
        "meta": {
            "tool": "GHOST RECON",
            "version": "2.0.0",
            "scan_id": ctx.scan_id,
            "domain": ctx.domain,
            "root_domain": ctx.root_domain,
            "target": ctx.target,
            "scope": ctx.scope,
            "stealth": ctx.stealth,
            "waf": ctx.waf_detected,
            "origin_ip": ctx.origin_ip,
            "tech_stack": ctx.tech_stack,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": int(elapsed),
        },
        "stats": stats,
        "severity_counts": sev_counts,
        "findings": enriched_findings,
        "diff": diff,
    }

    # ─── Collect screenshots ──────────────────────────────────────────────
    ws = getattr(config, "workspace", ".") or os.path.dirname(output_path)
    screenshot_data: List[Dict] = []

    import base64 as _b64

    ss_dirs = [
        (os.path.join(ws, "recon", "screenshots"), "Standard Ports"),
        (os.path.join(ws, "screenshots", "extended_ports"), "Extended Ports"),
        (os.path.join(ws, "recon", "aquatone_out"), "Aquatone"),
        (
            os.path.join(ws, "screenshots", "extended_ports", "aquatone_out"),
            "Extended Aquatone",
        ),
    ]
    for ss_path, label in ss_dirs:
        if not os.path.isdir(ss_path):
            continue
        from pathlib import Path as _P

        pngs = sorted(_P(ss_path).glob("*.png"))[:50]
        for png in pngs:
            try:
                raw = png.read_bytes()
                if len(raw) > 50:
                    b64 = _b64.b64encode(raw).decode("ascii")
                    fname = png.stem
                    clean_label = fname.replace("_", ":").replace("-", ".")[:60]
                    screenshot_data.append({
                        "src": b64,
                        "label": clean_label,
                        "group": label,
                    })
            except Exception:
                continue

    scan_data["screenshots"] = screenshot_data[:100]

    # v2.0: findings carry attacker-controlled strings (page titles, URLs,
    # response snippets). Escape <, >, & so a value like "</script><script>…"
    # can't break out of this inline <script> and run in the tester's browser.
    data_json = (
        json.dumps(scan_data, default=str, indent=None)
        .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    )
    _h = _html.escape

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GHOST RECON — {_h(ctx.domain)}</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  body {{ background: #0f172a; color: #e2e8f0; font-family: 'Inter', system-ui, sans-serif; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 24px; }}
  .sev-crit {{ color: #ef4444; }} .sev-high {{ color: #f97316; }}
  .sev-med {{ color: #eab308; }} .sev-low {{ color: #3b82f6; }}
  .finding-card {{ background: #1e293b; border-left: 4px solid; border-radius: 8px; padding: 16px; margin: 8px 0; cursor: pointer; }}
  .finding-card.CRITICAL {{ border-color: #ef4444; }} .finding-card.HIGH {{ border-color: #f97316; }}
  .finding-card.MEDIUM {{ border-color: #eab308; }} .finding-card.LOW {{ border-color: #3b82f6; }}
  .finding-detail {{ display: none; margin-top: 12px; padding-top: 12px; border-top: 1px solid #334155; }}
  .finding-card.open .finding-detail {{ display: block; }}
  code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
  pre {{ white-space: pre-wrap; word-break: break-all; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 0.75em; font-weight: 700; }}
  .badge-crit {{ background: #7f1d1d; color: #fca5a5; }} .badge-high {{ background: #7c2d12; color: #fdba74; }}
  .badge-med {{ background: #713f12; color: #fde047; }} .badge-low {{ background: #1e3a5f; color: #93c5fd; }}
  .validation-box {{ background: #0c1222; border: 1px solid #2dd4bf33; border-radius: 8px; padding: 12px; margin-top: 10px; }}
  .validation-box h4 {{ color: #2dd4bf; font-size: 0.85em; font-weight: 700; margin-bottom: 8px; }}
  .validation-step {{ font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 0.78em; color: #a7f3d0; line-height: 1.6; padding: 2px 0; }}
  .validation-step.comment {{ color: #6b7280; font-style: italic; }}
  .ss-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }}
  .ss-card {{ background: #1e293b; border-radius: 8px; overflow: hidden; cursor: pointer; transition: transform 0.2s; }}
  .ss-card:hover {{ transform: scale(1.02); }}
  .ss-card img {{ width: 100%; height: 200px; object-fit: cover; border-bottom: 1px solid #334155; }}
  .ss-card .ss-label {{ padding: 8px 12px; font-size: 0.8em; color: #94a3b8; }}
  .ss-modal {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.9); z-index: 1000; justify-content: center; align-items: center; padding: 20px; }}
  .ss-modal.active {{ display: flex; }}
  .ss-modal img {{ max-width: 95vw; max-height: 90vh; border-radius: 8px; }}
  .copy-btn {{ background: #334155; border: none; color: #94a3b8; padding: 3px 10px; border-radius: 4px; font-size: 0.7em; cursor: pointer; float: right; }}
  .copy-btn:hover {{ background: #475569; color: #e2e8f0; }}
</style>
</head>
<body class="min-h-screen p-6">
<script>const SCAN_DATA = {data_json};</script>

<div class="max-w-7xl mx-auto">
  <div class="text-center mb-8">
    <h1 class="text-4xl font-bold text-red-500 mb-2">👻 GHOST RECON v2.0</h1>
    <p class="text-xl text-slate-400">{_h(ctx.domain)}</p>
    <div class="flex justify-center gap-4 mt-4 text-sm text-slate-500">
      <span>Scope: <strong class="text-slate-300">{_h(ctx.scope.upper())}</strong></span>
      <span>WAF: <strong class="text-slate-300">{_h(', '.join(map(str, ctx.waf_detected)) or 'None')}</strong></span>
      <span>Duration: <strong class="text-slate-300">{int(elapsed // 60)}m {int(elapsed % 60)}s</strong></span>
      <span>Scan: <strong class="text-slate-300">{ctx.scan_id[:8]}</strong></span>
    </div>
  </div>

  <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
    <div class="card text-center"><div class="text-3xl font-bold text-red-400" id="stat-findings">0</div><div class="text-sm text-slate-400">Findings</div></div>
    <div class="card text-center"><div class="text-3xl font-bold text-cyan-400" id="stat-subs">0</div><div class="text-sm text-slate-400">Subdomains</div></div>
    <div class="card text-center"><div class="text-3xl font-bold text-green-400" id="stat-urls">0</div><div class="text-sm text-slate-400">URLs</div></div>
    <div class="card text-center"><div class="text-3xl font-bold text-yellow-400" id="stat-secrets">0</div><div class="text-sm text-slate-400">Secrets</div></div>
    <div class="card text-center"><div class="text-3xl font-bold text-purple-400" id="stat-ports">0</div><div class="text-sm text-slate-400">Ports</div></div>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
    <div class="card"><canvas id="sevChart" height="200"></canvas></div>
    <div class="card"><canvas id="catChart" height="200"></canvas></div>
  </div>

  <div id="origin-alert" class="hidden card mb-6 border border-red-500/30 bg-red-500/10">
    <h3 class="text-lg font-bold text-red-400">🎯 Origin IP Discovered</h3>
    <p class="text-slate-300 mt-1">Direct WAF bypass available: <code id="origin-ip"></code></p>
    <p class="text-sm text-slate-500 mt-1">curl -sk -H 'Host: {ctx.domain}' https://<span id="origin-ip2"></span>/</p>
  </div>

  <div class="mb-8">
    <h2 class="text-2xl font-bold mb-4">🔍 Findings <span class="text-sm font-normal text-slate-500" id="findings-count"></span></h2>
    <div class="flex gap-2 mb-4 flex-wrap">
      <button onclick="filterSev('all')" class="px-3 py-1 rounded bg-slate-700 text-sm hover:bg-slate-600">All</button>
      <button onclick="filterSev('CRITICAL')" class="px-3 py-1 rounded bg-red-900/50 text-sm text-red-400 hover:bg-red-900">Critical</button>
      <button onclick="filterSev('HIGH')" class="px-3 py-1 rounded bg-orange-900/50 text-sm text-orange-400 hover:bg-orange-900">High</button>
      <button onclick="filterSev('MEDIUM')" class="px-3 py-1 rounded bg-yellow-900/50 text-sm text-yellow-400 hover:bg-yellow-900">Medium</button>
    </div>
    <div id="findings-list"></div>
  </div>

  <div id="screenshots-section" class="mb-8 hidden">
    <h2 class="text-2xl font-bold mb-4">📸 Visual Recon <span class="text-sm font-normal text-slate-500" id="ss-count"></span></h2>
    <div class="flex gap-2 mb-4" id="ss-group-buttons"></div>
    <div class="ss-grid" id="ss-grid"></div>
  </div>

  <div class="ss-modal" id="ss-modal" onclick="this.classList.remove('active')">
    <img id="ss-modal-img" src="" alt="Screenshot">
  </div>
</div>

<script>
function escHtml(s) {{
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}}

document.addEventListener('DOMContentLoaded', function() {{
  const D = SCAN_DATA;
  const s = D.stats || {{}};
  const sc = D.severity_counts || {{}};
  const f = D.findings || [];

  document.getElementById('stat-findings').textContent = f.length;
  document.getElementById('stat-subs').textContent = s.subdomains || 0;
  document.getElementById('stat-urls').textContent = s.urls || 0;
  document.getElementById('stat-secrets').textContent = s.secrets || 0;
  document.getElementById('stat-ports').textContent = s.ports || 0;
  document.getElementById('findings-count').textContent = '(' + f.length + ')';

  if (D.meta.origin_ip) {{
    document.getElementById('origin-alert').classList.remove('hidden');
    document.getElementById('origin-ip').textContent = D.meta.origin_ip;
    document.getElementById('origin-ip2').textContent = D.meta.origin_ip;
  }}

  new Chart(document.getElementById('sevChart'), {{
    type: 'doughnut',
    data: {{
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{{ data: [sc.CRITICAL||0, sc.HIGH||0, sc.MEDIUM||0, sc.LOW||0],
        backgroundColor: ['#ef4444','#f97316','#eab308','#3b82f6'] }}]
    }},
    options: {{ plugins: {{ legend: {{ labels: {{ color: '#94a3b8' }} }} }}, responsive: true }}
  }});

  const cats = {{}};
  f.forEach(x => {{ cats[x.category] = (cats[x.category]||0) + 1; }});
  const catLabels = Object.keys(cats).slice(0, 10);
  const catValues = catLabels.map(k => cats[k]);
  new Chart(document.getElementById('catChart'), {{
    type: 'bar',
    data: {{ labels: catLabels, datasets: [{{ label: 'Count', data: catValues,
      backgroundColor: '#6366f1' }}] }},
    options: {{ indexAxis: 'y', plugins: {{ legend: {{ display: false }} }},
      scales: {{ x: {{ ticks: {{ color: '#94a3b8' }} }}, y: {{ ticks: {{ color: '#94a3b8' }} }} }}, responsive: true }}
  }});

  const list = document.getElementById('findings-list');
  f.forEach((item, i) => {{
    const sevClass = item.severity;
    const badgeClass = {{'CRITICAL':'badge-crit','HIGH':'badge-high','MEDIUM':'badge-med','LOW':'badge-low'}}[item.severity] || 'badge-low';

    // Build validation steps HTML
    const vsteps = item.validation_steps || [];
    let vstepsHtml = '';
    if (vsteps.length > 0) {{
      const stepsInner = vsteps.map(st => {{
        const isComment = st.trim().startsWith('#');
        const cls = isComment ? 'validation-step comment' : 'validation-step';
        return '<div class="' + cls + '">' + escHtml(st) + '</div>';
      }}).join('');
      vstepsHtml = `
        <div class="validation-box">
          <h4>🔬 Manual Verification Steps</h4>
          <button class="copy-btn" onclick="event.stopPropagation(); navigator.clipboard.writeText(this.parentElement.innerText.replace('🔬 Manual Verification Steps\\nCopy',''))">Copy</button>
          ${{stepsInner}}
        </div>`;
    }}

    const div = document.createElement('div');
    div.className = 'finding-card ' + String(sevClass).replace(/[^A-Z]/g, '');
    div.dataset.sev = item.severity;
    div.innerHTML = `
      <div class="flex items-center justify-between">
        <div><span class="badge ${{badgeClass}}">${{escHtml(item.severity)}}</span>
        <span class="font-semibold ml-2">${{escHtml(item.title)}}</span></div>
        <span class="text-xs text-slate-500">${{item.cvss_score ? parseFloat(item.cvss_score).toFixed(1) : '—'}} CVSS</span>
      </div>
      <div class="text-sm text-slate-400 mt-1">${{escHtml(item.category)}} ${{item.cwe ? '| ' + escHtml(item.cwe) : ''}} ${{item.owasp ? '| ' + escHtml(item.owasp) : ''}}</div>
      <div class="finding-detail">
        <p class="text-sm"><strong>URL:</strong> <code>${{escHtml(item.url)}}</code></p>
        <p class="text-sm mt-1"><strong>Detail:</strong> ${{escHtml(item.detail) || '—'}}</p>
        <p class="text-sm mt-1"><strong>Impact:</strong> ${{escHtml(item.impact) || '—'}}</p>
        <p class="text-sm mt-1"><strong>Exploit PoC:</strong></p>
        <pre class="bg-slate-900 p-2 rounded text-xs mt-1 overflow-x-auto">${{escHtml(item.exploit) || '—'}}</pre>
        ${{vstepsHtml}}
        <p class="text-xs text-slate-500 mt-2">Confidence: ${{escHtml(item.confidence)}} | Phase: ${{escHtml(item.phase)}} | MITRE: ${{escHtml(item.mitre_tactic || '?')}}/${{escHtml(item.mitre_technique || '?')}}</p>
      </div>`;
    div.addEventListener('click', () => div.classList.toggle('open'));
    list.appendChild(div);
  }});
}});

function filterSev(sev) {{
  document.querySelectorAll('.finding-card').forEach(c => {{
    c.style.display = (sev === 'all' || c.dataset.sev === sev) ? '' : 'none';
  }});
}}

(function() {{
  const ss = SCAN_DATA.screenshots || [];
  if (ss.length === 0) return;

  document.getElementById('screenshots-section').classList.remove('hidden');
  document.getElementById('ss-count').textContent = '(' + ss.length + ')';

  const grid = document.getElementById('ss-grid');
  const btnContainer = document.getElementById('ss-group-buttons');
  const modal = document.getElementById('ss-modal');
  const modalImg = document.getElementById('ss-modal-img');

  const groups = [...new Set(ss.map(s => s.group))];

  const allBtn = document.createElement('button');
  allBtn.textContent = 'All (' + ss.length + ')';
  allBtn.className = 'px-3 py-1 rounded bg-slate-700 text-sm hover:bg-slate-600';
  allBtn.onclick = () => filterSS('all');
  btnContainer.appendChild(allBtn);

  groups.forEach(g => {{
    const count = ss.filter(s => s.group === g).length;
    const btn = document.createElement('button');
    btn.textContent = g + ' (' + count + ')';
    btn.className = 'px-3 py-1 rounded bg-indigo-900/50 text-sm text-indigo-300 hover:bg-indigo-900';
    btn.onclick = () => filterSS(g);
    btnContainer.appendChild(btn);
  }});

  ss.forEach((s, i) => {{
    const card = document.createElement('div');
    card.className = 'ss-card';
    card.dataset.group = s.group;
    const img = document.createElement('img');
    img.src = 'data:image/png;base64,' + s.src;
    img.alt = s.label;
    img.loading = 'lazy';
    img.onclick = (e) => {{
      e.stopPropagation();
      modalImg.src = img.src;
      modal.classList.add('active');
    }};
    const label = document.createElement('div');
    label.className = 'ss-label';
    label.innerHTML = '<span class="text-slate-500">[' + escHtml(s.group) + ']</span> ' + escHtml(s.label);
    card.appendChild(img);
    card.appendChild(label);
    grid.appendChild(card);
  }});

  window.filterSS = function(group) {{
    document.querySelectorAll('.ss-card').forEach(c => {{
      c.style.display = (group === 'all' || c.dataset.group === group) ? '' : 'none';
    }});
  }};
}})();
</script>
<footer class="text-center text-slate-600 text-xs mt-12 pb-8">GHOST RECON v2.0 — Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</footer>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
