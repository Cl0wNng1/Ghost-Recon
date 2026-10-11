"""
GHOST RECON v2.0 — core/notifications.py
Enterprise Notification Engine: Discord (rich embeds), Slack, Telegram.

Upgrades over the previous internal build:
  - LOCAL SCHEMA VALIDATION for Discord embeds (pre-send field truncation)
  - Auto-truncation to Discord hard limits (2048 desc, 256 title, 1024 field)
  - Content-Type: application/json enforced (was missing in v11 curl fallback)
  - Exact resp.status_code + resp.text logged on every failure
  - Exponential backoff retry for 429 rate limiting
  - Embed count cap (≤10 per payload), total char limit (6000)
  - Per-step real-time finding alerts with first manual testing steps
  - httpx-native posting (no curl subprocess dependency)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

log = logging.getLogger("ghost.notifications")

# ═══════════════════════════════════════════════════════════════════════════════
# DISCORD SCHEMA LIMITS (hard ceiling — enforced pre-send)
# ═══════════════════════════════════════════════════════════════════════════════

DISCORD_LIMITS = {
    "title":        256,
    "description": 2048,
    "field_name":   256,
    "field_value": 1024,
    "footer_text": 2048,
    "author_name":  256,
    "embed_count":   10,   # max embeds per message
    "total_chars": 6000,   # total characters across all embeds in one payload
    "content":     2000,   # top-level message content
    "fields_max":    25,   # max fields per embed
}

SEV_COLORS = {
    "CRITICAL": 0xDC2626,
    "HIGH":     0xEA580C,
    "MEDIUM":   0xD97706,
    "LOW":      0x2563EB,
    "INFO":     0x6B7280,
    "SUCCESS":  0x16A34A,
}

SEV_ICONS = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW": "🔵", "INFO": "⚪", "SUCCESS": "✅",
}

# First manual testing step per category (for actionable Discord alerts)
_FIRST_STEP: Dict[str, str] = {
    "EXPOSED_SECRET":        "Copy raw secret → validate with `aws sts get-caller-identity` or curl",
    "GITHUB_LEAK":           "Open GitHub URL → search repo for .env, docker-compose.yml, CI configs",
    "JWT_NONE_ALG":          "Decode at jwt.io → change alg→none → remove signature → replay request",
    "GRAPHQL_INTROSPECTION": "Run InQL (Burp) → import schema → test all mutations for missing auth",
    "BOLA_IDOR":             "Create 2 accounts → swap object IDs between sessions → confirm access",
    "MASS_ASSIGNMENT":       "Add role=admin / is_admin=true to POST body → check if persisted",
    "HTTP_SMUGGLING":        "Confirm: python3 smuggler.py -u <target> --log-level warning",
    "CACHE_POISONING":       "Verify: curl -H 'X-Forwarded-Host: evil.com' <url> → check X-Cache",
    "ORIGIN_EXPOSED":        "Direct: nmap -sV -p 80,443,8080 <origin_ip> (bypasses WAF)",
    "SHODAN_CVE":            "searchsploit <CVE-ID> → check Metasploit → verify version nmap -sV",
    "EXPOSED_INFRA":         "Connect: redis-cli -h <host> | nc <host> 9200 | mongo <host>",
    "REFLECTED_XSS":         "Confirm reflection → check CSP header → context-specific payload",
    "SSTI":                  "Confirm: {{7*7}} → 49 → escalate to RCE with tplmap or SSTImap",
    "LFI":                   "Confirm: ../../../../etc/passwd → read config files → log poisoning",
    "CDN_BYPASS":            "curl -sk https://<origin_ip>/ -H 'Host: target.com' → compare",
    "NUCLEI_VULN":           "Re-verify: nuclei -u '<url>' -t <template-id> -debug",
    "XSS_REFLECTED":         "Confirm in browser → test with CSP bypass → chain to cookie theft",
    "SQLI":                  "Confirm: ghauri -u '<url>' --batch --dbs → extract schema",
    "OPEN_PORTS":            "nmap -sV -p <port> <ip> → identify service → search for exploits",
    "DEFAULT":               "Fetch URL directly → document full response → check auth bypass",
}


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA VALIDATION & TRUNCATION
# ═══════════════════════════════════════════════════════════════════════════════

def _trunc(s: str, limit: int) -> str:
    """Truncate string to limit with ellipsis. Never exceeds limit."""
    s = str(s) if s else ""
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."


def _validate_embed(embed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enforce Discord embed schema compliance.
    Truncates all string fields to their respective hard limits.
    Removes keys with None/empty values.
    """
    validated: Dict[str, Any] = {}

    if embed.get("title"):
        validated["title"] = _trunc(str(embed["title"]), DISCORD_LIMITS["title"])

    if embed.get("description"):
        validated["description"] = _trunc(str(embed["description"]), DISCORD_LIMITS["description"])

    if "color" in embed:
        try:
            validated["color"] = int(embed["color"])
        except (ValueError, TypeError):
            validated["color"] = SEV_COLORS["INFO"]

    if "url" in embed and embed["url"]:
        validated["url"] = str(embed["url"])[:512]

    if "timestamp" in embed and embed["timestamp"]:
        validated["timestamp"] = str(embed["timestamp"])

    # Footer
    if isinstance(embed.get("footer"), dict):
        ft = embed["footer"].get("text", "")
        if ft:
            validated["footer"] = {"text": _trunc(str(ft), DISCORD_LIMITS["footer_text"])}

    # Author
    if isinstance(embed.get("author"), dict):
        name = embed["author"].get("name", "")
        if name:
            validated["author"] = {"name": _trunc(str(name), DISCORD_LIMITS["author_name"])}

    # Fields (max 25)
    if isinstance(embed.get("fields"), list):
        clean_fields = []
        for f in embed["fields"][: DISCORD_LIMITS["fields_max"]]:
            if not isinstance(f, dict):
                continue
            name = _trunc(str(f.get("name", "?")), DISCORD_LIMITS["field_name"])
            value = _trunc(str(f.get("value", "?")), DISCORD_LIMITS["field_value"])
            if name and value:
                clean_fields.append({
                    "name":   name,
                    "value":  value,
                    "inline": bool(f.get("inline", False)),
                })
        if clean_fields:
            validated["fields"] = clean_fields

    return validated


def _enforce_total_chars(embeds: List[Dict]) -> List[Dict]:
    """
    Ensure total embed character count stays under Discord's 6000 limit.
    Truncates later embeds if budget exceeded.
    """
    total = 0
    result = []
    for embed in embeds:
        embed_chars = sum(
            len(str(v)) for v in embed.values()
            if isinstance(v, str)
        )
        if isinstance(embed.get("fields"), list):
            for f in embed["fields"]:
                embed_chars += len(str(f.get("name", ""))) + len(str(f.get("value", "")))
        if isinstance(embed.get("footer"), dict):
            embed_chars += len(str(embed["footer"].get("text", "")))

        if total + embed_chars > DISCORD_LIMITS["total_chars"]:
            result.append({
                "title": "⚠ Report Truncated",
                "description": "Total embed limit reached. See HTML report for full findings.",
                "color": SEV_COLORS["MEDIUM"],
            })
            break
        total += embed_chars
        result.append(embed)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP TRANSPORT (httpx-native, with curl fallback)
# ═══════════════════════════════════════════════════════════════════════════════

async def _post_webhook(
    webhook_url: str, payload: Dict[str, Any], retries: int = 3
) -> bool:
    """
    POST a Discord/Slack webhook payload.
    - Explicit Content-Type: application/json
    - Exact status_code + body logged on every failure
    - Exponential backoff for 429 rate limiting
    Returns True on success (200/204).
    """
    try:
        import httpx as _httpx
        _has_httpx = True
    except ImportError:
        _has_httpx = False

    payload_bytes = json.dumps(payload).encode("utf-8")

    for attempt in range(retries):
        try:
            if _has_httpx:
                async with _httpx.AsyncClient(timeout=15.0, verify=False) as client:
                    resp = await client.post(
                        webhook_url,
                        content=payload_bytes,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent":   "Ghost-SecDevOps/12.0",
                        },
                    )

                if resp.status_code in (200, 204):
                    return True

                # 429 rate limited — extract retry_after
                if resp.status_code == 429:
                    try:
                        retry_data = resp.json()
                        retry_after = float(retry_data.get("retry_after", 5.0))
                    except Exception:
                        retry_after = 5.0
                    log.warning(
                        f"[Webhook] 429 Rate Limited — retry_after={retry_after:.1f}s "
                        f"(attempt {attempt + 1}/{retries})"
                    )
                    await asyncio.sleep(retry_after)
                    continue

                # All other failures — log exact status + body
                log.error(
                    f"[Webhook] POST failed: HTTP {resp.status_code} | "
                    f"Body: {resp.text[:500]}"
                )
                return False

            else:
                # Curl fallback — still enforce Content-Type
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sS", "-m", "15", "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-H", "User-Agent: Ghost-SecDevOps/12.0",
                    "-d", json.dumps(payload),
                    "-w", "\n%{http_code}",
                    webhook_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)
                output = (stdout or b"").decode("utf-8", errors="ignore")
                lines = output.strip().rsplit("\n", 1)
                status_code = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0
                body = lines[0] if len(lines) > 1 else output

                if status_code in (200, 204):
                    return True

                if status_code == 429:
                    log.warning(f"[Webhook] 429 via curl (attempt {attempt + 1}/{retries})")
                    await asyncio.sleep(5.0 * (attempt + 1))
                    continue

                log.error(f"[Webhook] curl POST failed: HTTP {status_code} | Body: {body[:500]}")
                return False

        except asyncio.TimeoutError:
            log.error(f"[Webhook] Timeout on attempt {attempt + 1}/{retries}")
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
        except Exception as e:
            log.error(f"[Webhook] Unexpected error: {e}")
            return False

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# DISCORD NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

async def _discord(webhook_url: str, ctx: Any, config: Any, elapsed: float) -> bool:
    """
    Send Discord notification with schema-validated, truncated embeds.
    Includes executive summary + per-finding embeds for CRITICAL/HIGH.
    """
    try:
        stats = ctx.stats()
        sev = ctx.findings_by_severity()
        total = ctx.finding_count()
        crits = sev.get("CRITICAL", 0)
        highs = sev.get("HIGH", 0)
        color = (
            SEV_COLORS["CRITICAL"] if crits > 0
            else SEV_COLORS["HIGH"] if highs > 0
            else SEV_COLORS["SUCCESS"]
        )
        minutes = int(elapsed // 60)

        # Build summary embed
        sev_text = "\n".join(
            f"{SEV_ICONS.get(k, '?')} **{k}**: {v}"
            for k, v in sorted(sev.items(), key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x[0]) if x[0] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else 5)
            if v > 0
        ) or "No findings."

        waf_text = ", ".join(ctx.waf_detected) if ctx.waf_detected else "None"

        summary_embed = _validate_embed({
            "title": f"👻 Ghost v12 — {ctx.domain}",
            "description": (
                f"**Duration:** {minutes}m {int(elapsed % 60)}s | "
                f"**Stealth:** {ctx.stealth.upper()}\n"
                f"**Subs:** {stats.get('subdomains', 0)} | "
                f"**Live:** {stats.get('live_hosts', 0)} | "
                f"**URLs:** {stats.get('urls', 0)}\n"
                f"**JS:** {stats.get('js_files', 0)} | "
                f"**APIs:** {stats.get('api_endpoints', 0)} | "
                f"**Secrets:** {stats.get('secrets', 0)}\n"
                f"**WAF/CDN:** {waf_text}"
                + (f" | **Origin:** {ctx.origin_ip}" if ctx.origin_ip else "")
                + f"\n\n**Findings ({total}):**\n{sev_text}"
            ),
            "color": color,
            "footer": {"text": f"Ghost v12 | {datetime.now():%Y-%m-%d %H:%M:%S} | {ctx.scan_id[:8]}"},
        })

        embeds: List[Dict] = [summary_embed]

        # Per-finding embeds for CRITICAL + HIGH (max 9 to stay under 10 total)
        actionable = [f for f in ctx.findings[:20] if f.get("severity") in ("CRITICAL", "HIGH")]

        for finding in actionable[:9]:
            sv = finding.get("severity", "INFO")
            cat = finding.get("category", "DEFAULT")
            first_step = _FIRST_STEP.get(cat, _FIRST_STEP["DEFAULT"])

            embed = _validate_embed({
                "title": f"{SEV_ICONS.get(sv, '?')} [{sv}] {finding.get('title', '?')}",
                "description": (
                    f"**URL:** {finding.get('url', '?')}\n"
                    f"**Category:** `{cat}`\n"
                    f"**Detail:** {finding.get('detail', '')}\n\n"
                    f"🔬 **First Step:**\n`{first_step}`"
                ),
                "color": SEV_COLORS.get(sv, SEV_COLORS["INFO"]),
                "fields": [
                    {"name": "Phase", "value": finding.get("phase", "?"), "inline": True},
                    {"name": "CWE", "value": finding.get("cwe", "N/A"), "inline": True},
                    {"name": "PoC", "value": str(finding.get("exploit", "N/A"))[:200], "inline": False},
                ],
            })
            embeds.append(embed)

        if len(actionable) > 9:
            embeds.append(_validate_embed({
                "title": f"⚠ +{len(actionable) - 9} More Critical/High Findings",
                "description": "Check the HTML report for full manual testing guidance.",
                "color": SEV_COLORS["MEDIUM"],
            }))

        # Enforce hard limits
        embeds = embeds[: DISCORD_LIMITS["embed_count"]]
        embeds = _enforce_total_chars(embeds)

        payload = {
            "username":   "Ghost-SecDevOps",
            "avatar_url": "https://i.imgur.com/kT7tCm9.png",
            "embeds":     embeds,
        }

        return await _post_webhook(webhook_url, payload)

    except Exception as e:
        log.error(f"[Discord] Build error: {e}")
        return False


async def send_discord_finding_alert(
    webhook_url: str,
    findings: List[Dict],
    step_num: int,
    step_label: str,
) -> None:
    """
    Real-time per-step alert when new CRITICAL/HIGH findings are discovered.
    Includes first manual testing step for immediate action.
    """
    if not webhook_url or not findings:
        return

    embeds: List[Dict] = []
    for f in findings[:9]:
        sv = f.get("severity", "INFO")
        cat = f.get("category", "DEFAULT")
        first_step = _FIRST_STEP.get(cat, _FIRST_STEP["DEFAULT"])

        embed = _validate_embed({
            "title": f"🚨 [{sv}] {f.get('title', 'Unknown')}",
            "description": (
                f"**URL:** {f.get('url', '?')}\n"
                f"**Category:** `{cat}`\n"
                f"**Detail:** {f.get('detail', '')}\n\n"
                f"🔬 **Verify now:**\n`{first_step}`"
            ),
            "color": SEV_COLORS.get(sv, SEV_COLORS["INFO"]),
            "footer": {"text": f"Step {step_num:02d}: {step_label}"},
        })
        embeds.append(embed)

    if not embeds:
        return

    payload = {
        "username": "Ghost-SecDevOps",
        "content":  _trunc(
            f"⚡ **Step {step_num:02d} — {step_label}** | {len(findings)} new finding(s)",
            DISCORD_LIMITS["content"],
        ),
        "embeds": embeds[: DISCORD_LIMITS["embed_count"]],
    }

    await _post_webhook(webhook_url, payload)


# ═══════════════════════════════════════════════════════════════════════════════
# SLACK / TELEGRAM
# ═══════════════════════════════════════════════════════════════════════════════

async def _slack(webhook_url: str, ctx: Any, config: Any, elapsed: float) -> bool:
    """Send Slack notification."""
    try:
        total = ctx.finding_count()
        sev = ctx.findings_by_severity()
        crits = sev.get("CRITICAL", 0)
        emoji = "🔴" if crits > 0 else "🟢"

        text = (
            f"{emoji} *GHOST RECON v12* — `{ctx.domain}`\n"
            f"Findings: *{total}* (CRIT: {crits}, HIGH: {sev.get('HIGH', 0)})\n"
            f"Subs: {len(ctx.subdomains)} | URLs: {ctx.url_count()} | Duration: {int(elapsed // 60)}m"
        )
        payload = {"text": text}
        return await _post_webhook(webhook_url, payload)
    except Exception as e:
        log.error(f"[Slack] Error: {e}")
        return False


async def _telegram(bot_token: str, chat_id: str, ctx: Any, elapsed: float) -> bool:
    """Send Telegram notification."""
    try:
        total = ctx.finding_count()
        sev = ctx.findings_by_severity()
        crits = sev.get("CRITICAL", 0)
        emoji = "🔴" if crits > 0 else "🟢"

        text = (
            f"{emoji} GHOST RECON v12 — {ctx.domain}\n"
            f"Findings: {total} (CRIT: {crits}, HIGH: {sev.get('HIGH', 0)})\n"
            f"Subs: {len(ctx.subdomains)} | Duration: {int(elapsed // 60)}m"
        )
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        return await _post_webhook(url, payload)
    except Exception as e:
        log.error(f"[Telegram] Error: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

async def notify_all(ctx: Any, config: Any, elapsed: float) -> None:
    """Send notifications to all configured channels. Never raises."""
    tasks = []

    discord_url = getattr(config, "discord_webhook", "") or os.environ.get("DISCORD_WEBHOOK", "")
    if discord_url:
        tasks.append(("Discord", _discord(discord_url, ctx, config, elapsed)))

    slack_url = getattr(config, "slack_webhook", "") or os.environ.get("SLACK_WEBHOOK", "")
    if slack_url:
        tasks.append(("Slack", _slack(slack_url, ctx, config, elapsed)))

    tg_bot = getattr(config, "telegram_bot", "") or os.environ.get("TELEGRAM_BOT", "")
    tg_chat = getattr(config, "telegram_chat", "") or os.environ.get("TELEGRAM_CHAT", "")
    if tg_bot and tg_chat:
        tasks.append(("Telegram", _telegram(tg_bot, tg_chat, ctx, elapsed)))

    if not tasks:
        return

    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
    for (name, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            log.error(f"[{name}] Exception: {result}")
        elif result is False:
            log.warning(f"[{name}] Notification delivery failed")
        else:
            log.debug(f"[{name}] Notification sent successfully")
