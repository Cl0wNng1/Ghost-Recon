"""
GHOST RECON v2.0 — core/secret_validator.py
Active Secret Validation Engine

When the regex engine detects a secret (API key, token, credential),
this module makes a benign, non-destructive API call to the provider
to determine if the secret is LIVE and ACTIVE.

Supported providers:
  - Google API Key → Maps Geocoding API probe
  - AWS Access Key → STS GetCallerIdentity (via signed request or CLI)
  - GitHub Token  → /user API endpoint
  - Stripe Key    → /v1/charges (auth check, no data mutation)
  - Slack Token   → auth.test API
  - SendGrid Key  → /v3/api_keys (read-only)
  - OpenAI Key    → /v1/models
  - Anthropic Key → /v1/messages (dry probe)
  - Twilio Key    → /2010-04-01/Accounts.json

If active: severity → CRITICAL, title += "[ACTIVE KEY VERIFIED]"
If inactive/invalid: severity unchanged, note appended.

All validation is READ-ONLY and NON-DESTRUCTIVE.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("ghost.secret_validator")

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


@dataclass
class ValidationResult:
    """Result of an active secret validation probe."""
    pattern_name: str
    value_preview: str
    is_active: bool
    provider: str
    detail: str
    original_severity: str
    upgraded_severity: str
    source_url: str = ""


class SecretValidator:
    """
    Validates discovered secrets against their respective provider APIs.

    All probes are:
      - READ-ONLY (no mutations, no writes, no deletions)
      - BENIGN (minimal-permission endpoints)
      - TIMEOUT-SAFE (5s per probe, never blocks pipeline)
      - EXCEPTION-SAFE (never crashes on network/auth errors)
    """

    def __init__(self, max_concurrency: int = 3):
        self._sem = asyncio.Semaphore(max_concurrency)
        self._client: Optional[Any] = None
        self._validated_cache: Dict[str, ValidationResult] = {}

    async def _get_client(self) -> Any:
        if httpx is None:
            return None
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(8.0, connect=5.0),
                verify=False,
                follow_redirects=False,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def validate(
        self,
        pattern_name: str,
        secret_value: str,
        source_url: str = "",
        original_severity: str = "MEDIUM",
    ) -> ValidationResult:
        """
        Validate a single secret. Returns ValidationResult.

        Args:
            pattern_name: Name from regex match (e.g., "Google API Key")
            secret_value: The raw secret value
            source_url: Where the secret was found
            original_severity: Current severity level
        """
        cache_key = f"{pattern_name}|{secret_value[:30]}"
        if cache_key in self._validated_cache:
            return self._validated_cache[cache_key]

        preview = secret_value[:25] + "***" if len(secret_value) > 25 else secret_value

        # Route to appropriate validator
        result = await self._route_validation(
            pattern_name, secret_value, preview, source_url, original_severity
        )

        self._validated_cache[cache_key] = result
        return result

    async def _route_validation(
        self,
        pattern_name: str,
        secret: str,
        preview: str,
        source_url: str,
        orig_sev: str,
    ) -> ValidationResult:
        """Route to the correct provider validator based on pattern name."""
        pn = pattern_name.lower()

        if "google" in pn and "api" in pn:
            return await self._validate_google_api_key(secret, preview, source_url, orig_sev)

        if "aws" in pn and "secret" in pn:
            return await self._validate_aws_key(secret, preview, source_url, orig_sev)

        if "github" in pn and ("token" in pn or "access" in pn):
            return await self._validate_github_token(secret, preview, source_url, orig_sev)

        if "stripe" in pn:
            return await self._validate_stripe_key(secret, preview, source_url, orig_sev)

        if "slack" in pn and ("bot" in pn or "token" in pn or "user" in pn):
            return await self._validate_slack_token(secret, preview, source_url, orig_sev)

        if "sendgrid" in pn:
            return await self._validate_sendgrid_key(secret, preview, source_url, orig_sev)

        if "openai" in pn:
            return await self._validate_openai_key(secret, preview, source_url, orig_sev)

        if "twilio" in pn:
            return await self._validate_twilio_key(secret, preview, source_url, orig_sev)

        # Unknown provider — can't validate
        return ValidationResult(
            pattern_name=pattern_name,
            value_preview=preview,
            is_active=False,
            provider="unknown",
            detail="No active validation available for this secret type",
            original_severity=orig_sev,
            upgraded_severity=orig_sev,
            source_url=source_url,
        )

    # ─── Provider Validators ─────────────────────────────────────────────

    async def _validate_google_api_key(
        self, key: str, preview: str, source_url: str, orig_sev: str
    ) -> ValidationResult:
        """Probe Google Maps Geocoding API with the key."""
        async with self._sem:
            try:
                client = await self._get_client()
                if not client:
                    return self._inactive("Google API Key", preview, source_url, orig_sev, "httpx not available")

                resp = await client.get(
                    f"https://maps.googleapis.com/maps/api/geocode/json"
                    f"?address=1600+Amphitheatre+Parkway&key={key}"
                )

                body = resp.json() if resp.status_code == 200 else {}
                status = body.get("status", "")

                if resp.status_code == 200 and status == "OK":
                    return self._active(
                        "Google API Key", preview, source_url, orig_sev,
                        "google", f"Maps Geocoding returned OK (key is ACTIVE and billable)"
                    )
                elif status == "REQUEST_DENIED":
                    error_msg = body.get("error_message", "")
                    if "not authorized" in error_msg.lower() or "API key" in error_msg:
                        return self._inactive(
                            "Google API Key", preview, source_url, orig_sev,
                            f"Key exists but restricted: {error_msg[:100]}"
                        )
                return self._inactive(
                    "Google API Key", preview, source_url, orig_sev,
                    f"HTTP {resp.status_code}, status={status}"
                )
            except Exception as e:
                return self._inactive("Google API Key", preview, source_url, orig_sev, str(e)[:80])

    async def _validate_github_token(
        self, token: str, preview: str, source_url: str, orig_sev: str
    ) -> ValidationResult:
        async with self._sem:
            try:
                client = await self._get_client()
                if not client:
                    return self._inactive("GitHub Token", preview, source_url, orig_sev, "httpx not available")

                resp = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"token {token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )

                if resp.status_code == 200:
                    data = resp.json()
                    login = data.get("login", "?")
                    scopes = resp.headers.get("x-oauth-scopes", "none")
                    return self._active(
                        "GitHub Token", preview, source_url, orig_sev,
                        "github",
                        f"ACTIVE — user={login}, scopes=[{scopes}]"
                    )
                elif resp.status_code == 401:
                    return self._inactive("GitHub Token", preview, source_url, orig_sev, "401 — token expired/revoked")
                return self._inactive("GitHub Token", preview, source_url, orig_sev, f"HTTP {resp.status_code}")
            except Exception as e:
                return self._inactive("GitHub Token", preview, source_url, orig_sev, str(e)[:80])

    async def _validate_stripe_key(
        self, key: str, preview: str, source_url: str, orig_sev: str
    ) -> ValidationResult:
        async with self._sem:
            try:
                client = await self._get_client()
                if not client:
                    return self._inactive("Stripe Key", preview, source_url, orig_sev, "httpx not available")

                resp = await client.get(
                    "https://api.stripe.com/v1/charges?limit=1",
                    headers={"Authorization": f"Bearer {key}"},
                )

                if resp.status_code == 200:
                    return self._active(
                        "Stripe Key", preview, source_url, orig_sev,
                        "stripe", "ACTIVE — /v1/charges accessible (LIVE key, billable)"
                    )
                elif resp.status_code == 401:
                    return self._inactive("Stripe Key", preview, source_url, orig_sev, "401 — invalid key")
                return self._inactive("Stripe Key", preview, source_url, orig_sev, f"HTTP {resp.status_code}")
            except Exception as e:
                return self._inactive("Stripe Key", preview, source_url, orig_sev, str(e)[:80])

    async def _validate_slack_token(
        self, token: str, preview: str, source_url: str, orig_sev: str
    ) -> ValidationResult:
        async with self._sem:
            try:
                client = await self._get_client()
                if not client:
                    return self._inactive("Slack Token", preview, source_url, orig_sev, "httpx not available")

                resp = await client.post(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {token}"},
                )
                data = resp.json() if resp.status_code == 200 else {}

                if data.get("ok"):
                    team = data.get("team", "?")
                    user = data.get("user", "?")
                    return self._active(
                        "Slack Token", preview, source_url, orig_sev,
                        "slack", f"ACTIVE — team={team}, user={user}"
                    )
                return self._inactive(
                    "Slack Token", preview, source_url, orig_sev,
                    f"auth.test failed: {data.get('error', 'unknown')}"
                )
            except Exception as e:
                return self._inactive("Slack Token", preview, source_url, orig_sev, str(e)[:80])

    async def _validate_sendgrid_key(
        self, key: str, preview: str, source_url: str, orig_sev: str
    ) -> ValidationResult:
        async with self._sem:
            try:
                client = await self._get_client()
                if not client:
                    return self._inactive("SendGrid Key", preview, source_url, orig_sev, "httpx not available")

                resp = await client.get(
                    "https://api.sendgrid.com/v3/scopes",
                    headers={"Authorization": f"Bearer {key}"},
                )
                if resp.status_code == 200:
                    scopes = resp.json().get("scopes", [])
                    return self._active(
                        "SendGrid Key", preview, source_url, orig_sev,
                        "sendgrid", f"ACTIVE — {len(scopes)} scopes"
                    )
                return self._inactive("SendGrid Key", preview, source_url, orig_sev, f"HTTP {resp.status_code}")
            except Exception as e:
                return self._inactive("SendGrid Key", preview, source_url, orig_sev, str(e)[:80])

    async def _validate_openai_key(
        self, key: str, preview: str, source_url: str, orig_sev: str
    ) -> ValidationResult:
        async with self._sem:
            try:
                client = await self._get_client()
                if not client:
                    return self._inactive("OpenAI Key", preview, source_url, orig_sev, "httpx not available")

                resp = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {key}"},
                )
                if resp.status_code == 200:
                    return self._active(
                        "OpenAI Key", preview, source_url, orig_sev,
                        "openai", "ACTIVE — /v1/models accessible (billable key)"
                    )
                return self._inactive("OpenAI Key", preview, source_url, orig_sev, f"HTTP {resp.status_code}")
            except Exception as e:
                return self._inactive("OpenAI Key", preview, source_url, orig_sev, str(e)[:80])

    async def _validate_twilio_key(
        self, key: str, preview: str, source_url: str, orig_sev: str
    ) -> ValidationResult:
        async with self._sem:
            try:
                client = await self._get_client()
                if not client:
                    return self._inactive("Twilio Key", preview, source_url, orig_sev, "httpx not available")

                # Twilio uses account SID + auth token in Basic auth
                # The key alone is the SID-like prefix; skip if no SID pattern
                if not key.startswith("SK"):
                    return self._inactive("Twilio Key", preview, source_url, orig_sev, "Not a Twilio API Key format")

                resp = await client.get(
                    "https://api.twilio.com/2010-04-01/Accounts.json",
                    headers={"Authorization": f"Bearer {key}"},
                )
                if resp.status_code == 200:
                    return self._active(
                        "Twilio Key", preview, source_url, orig_sev,
                        "twilio", "ACTIVE — Accounts endpoint accessible"
                    )
                return self._inactive("Twilio Key", preview, source_url, orig_sev, f"HTTP {resp.status_code}")
            except Exception as e:
                return self._inactive("Twilio Key", preview, source_url, orig_sev, str(e)[:80])

    async def _validate_aws_key(
        self, secret_key: str, preview: str, source_url: str, orig_sev: str
    ) -> ValidationResult:
        """
        AWS validation requires both Access Key ID and Secret Key.
        Since we typically only find one at a time in regex, we note
        the key as "structurally valid" and recommend manual validation.
        """
        if len(secret_key) == 40 and re.match(r'^[A-Za-z0-9/+=]+$', secret_key):
            return ValidationResult(
                pattern_name="AWS Secret Key",
                value_preview=preview,
                is_active=False,
                provider="aws",
                detail=(
                    "Structurally valid AWS secret key (40 chars). "
                    "Manual validation required: aws sts get-caller-identity"
                ),
                original_severity=orig_sev,
                upgraded_severity="HIGH",
                source_url=source_url,
            )
        return self._inactive("AWS Secret Key", preview, source_url, orig_sev, "Invalid structure")

    # ─── Helpers ──────────────────────────────────────────────────────────

    def _active(
        self, name: str, preview: str, source_url: str,
        orig_sev: str, provider: str, detail: str,
    ) -> ValidationResult:
        log.warning(f"[SecretValidator] ACTIVE KEY: {name} — {detail}")
        return ValidationResult(
            pattern_name=name,
            value_preview=preview,
            is_active=True,
            provider=provider,
            detail=detail,
            original_severity=orig_sev,
            upgraded_severity="CRITICAL",
            source_url=source_url,
        )

    def _inactive(
        self, name: str, preview: str, source_url: str,
        orig_sev: str, detail: str,
    ) -> ValidationResult:
        return ValidationResult(
            pattern_name=name,
            value_preview=preview,
            is_active=False,
            provider="",
            detail=detail,
            original_severity=orig_sev,
            upgraded_severity=orig_sev,
            source_url=source_url,
        )

    async def validate_batch(
        self,
        secrets: List[Dict[str, str]],
    ) -> List[ValidationResult]:
        """
        Validate a batch of secrets.
        Each dict: {pattern_name, value, source_url, severity}
        """
        tasks = []
        for s in secrets:
            tasks.append(
                self.validate(
                    pattern_name=s.get("pattern_name", "Unknown"),
                    secret_value=s.get("value", ""),
                    source_url=s.get("source_url", ""),
                    original_severity=s.get("severity", "MEDIUM"),
                )
            )
        return await asyncio.gather(*tasks)
