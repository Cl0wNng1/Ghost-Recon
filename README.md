<div align="center">

# 👻 Ghost Recon

**A scope-aware, resumable recon and AppSec pipeline for authorised web security testing.**

![version](https://img.shields.io/badge/version-2.0.0-red)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![tests](https://img.shields.io/badge/tests-49%20passing-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

</div>

Ghost chains the usual bug-bounty and pentest toolkit (subfinder, httpx, katana, gau, nuclei, ffuf, dalfox and more) with its own async engine. The result is one 17-step pipeline that runs from asset discovery to authenticated access-control testing.

Everything it finds goes into a SQLite database, so a scan can be interrupted and resumed, diffed against the last run, and exported as HTML, JSON, Markdown or SARIF.

> [!WARNING]
> **Only run Ghost against systems you own or have explicit, written permission to test.** Several steps send active probes and payloads. Read the [Responsible use](#responsible-use) section before your first run.

---

## Contents

- [Highlights](#highlights)
- [Install](#install)
- [Quick start](#quick-start)
- [The pipeline](#the-pipeline)
- [Scope control](#scope-control)
- [Authenticated scanning and access-control testing](#authenticated-scanning-and-access-control-testing)
- [Config files](#config-files)
- [Output and CI integration](#output-and-ci-integration)
- [Resuming and stealth](#resuming-and-stealth)
- [CLI reference](#cli-reference)
- [Project layout](#project-layout)
- [Development](#development)
- [Known limitations](#known-limitations)
- [Responsible use](#responsible-use)

## Highlights

- **17-step pipeline.** It covers passive discovery, DNS and CDN triage, live-host verification, URL, JS and parameter mining, secret detection and validation, vuln scanning, content discovery, fuzzing, deep API discovery and multi-role IDOR/BOLA diffing.
- **Scope enforced in three places.** Asset storage, the HTTP engine and the shared client all check scope. Out-of-scope hosts are logged to `recon/out_of_scope.txt` and never probed, and redirects that leave scope are not followed.
- **Authenticated scans.** Cookie, bearer, raw-header or form-login sessions (with CSRF scraping) are verified up front and then used by every in-process request.
- **Access-control diffing.** Each candidate endpoint is requested as `anon`, `userA`, `userB`, `admin` and so on. Responses are compared to flag missing auth, BOLA and BFLA.
- **Resumable.** Checkpoints record the completed steps. `Ctrl-C` finishes the current step, saves state and writes reports, and `--resume` picks up where the scan stopped.
- **CI-ready.** JSON, Markdown and SARIF 2.1.0 exports are produced, and `--fail-on high` makes the run exit with code 2.
- **Stealth profiles.** A global token bucket, jitter and cooldowns are shared by every step, with adaptive back-off on 429/503 and Cloudflare challenges.

## Install

**Requirements:** Python 3.10+, Go 1.21+ for the external tools, and Linux or macOS.

```bash
git clone https://github.com/Cl0wNng1/ghost-recon.git
cd ghost-recon

# Python deps only (enough for the built-in engine, reports and tests)
pip install -r requirements.txt

# Optional: full external toolchain (subfinder, httpx, nuclei, ffuf, katana, dalfox, ...)
chmod +x install.sh && ./install.sh
```

Run `python3 ghost.py -u example.com --steps 0` to see which tools were detected. Missing optional tools are skipped gracefully, and the step falls back to the built-in engine where it can.

> [!NOTE]
> `pip install httpx[cli]` installs a Python program that is also called `httpx`. Ghost v2.0 detects that and looks for ProjectDiscovery's binary instead (`~/go/bin/httpx` or Kali's `httpx-toolkit`). Make sure one of them is installed.

## Quick start

```bash
# 1. See what will happen. No traffic is sent and no files are written.
python3 ghost.py -u example.com --dry-run

# 2. Single host, default (medium) stealth
python3 ghost.py -u https://app.example.com

# 3. Full wildcard program, slow and careful, with exclusions
python3 ghost.py -u '*.example.com' --stealth high --exclude legacy.example.com,status.example.com

# 4. Just recon: discovery through URL mining
python3 ghost.py -u example.com --steps 0-4

# 5. Through Burp
python3 ghost.py -u app.example.com --proxy http://127.0.0.1:8080
```

Results land in `./hunt_<domain>_<timestamp>/` (override with `-o`):

```
hunt_example_com_20261011_120000/
├── ghost.db                 # all assets, findings, checkpoints (SQLite)
├── auth_session.json        # only for authenticated scans, mode 0600
├── recon/  enum/  fuzz/  vulns/  secrets/  nuclei/  osint/
├── recon/out_of_scope.txt   # assets discovered but dropped by scope rules
└── reports/
    ├── report.html          # interactive report
    ├── report.md            # triage-ready Markdown
    ├── findings.json        # machine-readable summary
    └── findings.sarif       # SARIF 2.1.0
```

## The pipeline

Steps run in the order below. The **ID** is what you pass to `--steps` and `--skip-steps`, and `python3 ghost.py --list-steps` prints this table.

| # | ID | Step | Traffic to target |
|--:|--:|---|---|
| 1 | 0 | Dependency and environment validation | none |
| 2 | 1 | Attack surface discovery (subfinder, crt.sh, OTX, SecurityTrails, VirusTotal, permutations, ASN) | passive (third-party APIs) |
| 3 | 2 | DNS resolution, CNAME and CDN triage, wildcard detection | DNS only |
| 4 | 3 | Live-host verification, tech and WAF fingerprinting, screenshots | light |
| 5 | 15 | Authentication and session setup | light |
| 6 | 4 | URL and endpoint discovery (gau, waybackurls, katana, urlscan, crawl) | moderate |
| 7 | 5 | JavaScript analysis (routes, endpoints, secrets) | moderate |
| 8 | 6 | Secret discovery and validation | moderate |
| 9 | 7 | Parameter discovery (arjun, paramspider, gf, heuristic) | moderate |
| 10 | 8 | Vulnerability scanning (nuclei, dalfox, ghauri, wapiti, nikto, optional Nessus) | **active** |
| 11 | 9 | Network discovery (ports and services) | **active** |
| 12 | 10 | Sensitive files and cloud bucket exposure | moderate |
| 13 | 11 | Backup and artifact discovery | moderate |
| 14 | 12 | Content discovery (ffuf, dirsearch) | **active** |
| 15 | 13 | Advanced fuzzing (SQLi, XSS, SSTI, LFI, SSRF, CRLF, 403 bypass) | **active** |
| 16 | 14 | Deep API discovery (OpenAPI, GraphQL, versioned routes) | moderate |
| 17 | 16 | Access-control and IDOR testing (multi-role diffing) | moderate |

Payload sets live in `payloads/*.yml` and can be edited without touching code.

## Scope control

Scope is decided in one place (`core/scope.py`) and enforced in three:

1. **Data layer.** Assets outside scope are never written to the database, so no later step can reach them.
2. **The HTTP engine.** Requests to the target that fall outside scope are refused. Redirects are followed one hop at a time, and a hop that leaves scope is not followed.
3. **The shared HTTP client.** It applies the same checks to authenticated and authz traffic.

| You pass | In scope |
|---|---|
| `-u app.example.com` | `app.example.com` and `www.app.example.com` |
| `-u '*.example.com'` or `--wildcard` | `example.com` and every subdomain at any depth |
| `-u 203.0.113.10` | that IP only |
| `--scope-file scope.txt` | exactly what the file allows |
| `--include api.partner.io` | the default scope plus these hosts or CIDRs |
| `--exclude a.example.com,10.0.0.0/8` | removes these. **Deny always wins.** |

**Scope file format** (see [`examples/scope.example.txt`](examples/scope.example.txt)):

```text
example.com
*.example.com          # any depth
203.0.113.0/24
!legacy.example.com    # '!' or '-' marks out-of-scope
```

A few more rules apply:

- **Private, loopback and link-local addresses are blocked** unless you pass `--allow-private` or allow-list the CIDR.
- **`--strict-scope`** turns any out-of-scope request into a hard error and also drops third-party JavaScript (CDN-hosted bundles) from analysis.
- **`--origin <ip>`** adds that origin IP to scope automatically.

## Authenticated scanning and access-control testing

```bash
# Bearer / cookie / raw header
python3 ghost.py -u app.example.com --auth-bearer "$TOKEN"
python3 ghost.py -u app.example.com --auth-cookie 'session=abc; csrftoken=xyz'
python3 ghost.py -u app.example.com --auth-mode raw --auth-header 'X-Api-Key: k123'

# Form login (CSRF token scraped automatically); keep the password out of shell history
export GHOST_AUTH_PASSWORD='...'
python3 ghost.py -u app.example.com --login-url https://app.example.com/login \
  --username tester@example.com --user-field email \
  --auth-verify-url https://app.example.com/account --auth-success 'Sign out'
```

**How the session is handled:**

- Ghost checks the session against `--auth-verify-url` before the authenticated steps run. If the check fails, it warns loudly and the rest of the scan runs unauthenticated.
- The session is saved with mode `0600` so `--resume` stays logged in.
- Credentials are **redacted** everywhere Ghost serialises its configuration: `ghost.db`, the JSON export and the dry-run output.

**Access-control and IDOR testing (step 16).** Give Ghost two or more roles. Each `--role` takes the form `NAME:TYPE:VALUE`, where `TYPE` is `cookie`, `bearer` or `header`. An `anon` role is added for you.

```bash
python3 ghost.py -u app.example.com \
  --role userA:bearer:$TOKEN_A \
  --role userB:bearer:$TOKEN_B \
  --role admin:cookie:'session=...'
```

Ghost picks endpoints that carry object references (`?id=`, `/orders/1001`, UUIDs) and requests each one as every role. Two patterns get flagged:

- A lower-privileged role receives a response that matches a higher-privileged one (BOLA/BFLA, CWE-639).
- `anon` succeeds where an authenticated role gets a `401`, `403` or redirect (missing auth, CWE-284).

## Config files

Any setting can live in YAML or JSON, and CLI flags override the file. See [`examples/engagement.example.yml`](examples/engagement.example.yml):

```yaml
url: "*.example.com"
stealth: high
scope_file: scope.txt
scope_enforce: true
fail_on: HIGH
authz_roles:
  anon:  {}
  userA: {cookie: "session=...", rank: 1}
  admin: {bearer: "...", rank: 10}
```

```bash
python3 ghost.py --config engagement.local.yml           # *.local.yml is git-ignored
python3 ghost.py --config engagement.local.yml --dry-run  # check it first
```

## Output and CI integration

| Format | File | Use it for |
|---|---|---|
| `html` | `reports/report.html` | Interactive triage, screenshots and manual-verification steps |
| `md` | `reports/report.md` | Pasting into a ticket or a bug-bounty draft |
| `json` | `reports/findings.json` | `jq`, dashboards, diffing between runs |
| `sarif` | `reports/findings.sarif` | GitHub code scanning and other SARIF viewers |

Choose formats with `--format json,md`. All four are written by default.

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Usage or setup error |
| `2` | `--fail-on` threshold reached |
| `130` | Interrupted (state was saved; resume with `--resume`) |

```yaml
# .github/workflows/ghost.yml (scan your own staging environment)
- run: pip install -r requirements.txt
- run: python3 ghost.py --config ci/staging.yml -o out --format sarif,json --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: out/reports/findings.sarif }
```

## Resuming and stealth

```bash
python3 ghost.py --resume ./hunt_example_com_20261011_120000/
```

- **What gets restored.** The original target, scope, step selection and the saved authenticated session. Steps that failed are not marked complete and will run again.
- **Changing output on resume.** Only `--format` and `--fail-on` can be changed.
- **Comparing runs.** When a previous scan of the same domain exists, the summary shows a **delta**: new and resolved findings, and new and removed subdomains.

| Profile | req/s | Concurrency | Jitter | Cooldown |
|---|--:|--:|--:|---|
| `low` (fastest) | 30 | 15 | 0.1 s | 3 s every 200 requests |
| `medium` (default) | 10 | 8 | 0.3 s | 8 s every 100 requests |
| `high` | 3 | 5 | 0.8 s | 15 s every 50 requests |
| `turbo` (slowest, quietest) | 1 | 2 | 2.0 s | 30 s every 25 requests |

`--rate` and `--concurrency` override the profile. `--aggressive` means the `low` profile plus `--osint` and `--logic`.

## CLI reference

```text
Target       -u/--url  --config FILE  --resume DIR
Execution    --steps IDS  --skip-steps IDS  --stealth P  --rate N  --concurrency N
             --user-agent UA  -o DIR  --list-steps  --dry-run  --no-banner  -V/--version
Scope        --wildcard  --scope-file F  --include LIST  --exclude LIST  --strict-scope  --allow-private
Output       --format html,json,md,sarif  --fail-on CRITICAL|HIGH|MEDIUM|LOW|INFO
Features     --aggressive  --osint  --logic  --notify  --skip-subs  --skip-nuclei
Network      --proxy URL  --proxy-file F  --resolver-file F  --origin IP
Auth         --auth-mode  --auth-cookie  --auth-bearer  --auth-header  --login-url  --login-post-url
             --username  --password  --user-field  --pass-field  --csrf-field
             --auth-verify-url  --auth-success  --auth-failure
Authz        --role NAME:TYPE:VALUE  --authz-max-endpoints N  (--auth-a/--auth-b legacy)
API keys     --github-token  --shodan-key  --securitytrails-key  (or env vars, below)
Notify       --discord-webhook  --slack-webhook  --telegram-bot  --telegram-chat
```

**Environment variables:**

| Purpose | Variables |
|---|---|
| OSINT API keys | `GITHUB_TOKEN`, `SHODAN_API_KEY`, `SECURITYTRAILS_KEY`, `VIRUSTOTAL_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET` |
| Credentials | `GHOST_AUTH_BEARER`, `GHOST_AUTH_COOKIE`, `GHOST_AUTH_PASSWORD`, `AUTH_TOKEN_A`, `AUTH_TOKEN_B` |
| Notifications | `DISCORD_WEBHOOK`, `SLACK_WEBHOOK`, `TELEGRAM_BOT`, `TELEGRAM_CHAT` |

## Project layout

```
ghost.py              Orchestrator: CLI, persistent event loop, checkpoints, reports
ghost_core.py         Async HTTP engine (httpx, HTTP/2), adaptive rate limiting, response validators
core/
  pipeline.py         Step registry (execution order) + persistent event loop + resume mapping
  config.py           CLI / config-file parsing, stealth profiles, credential redaction
  scope.py            ScopeGuard: allow/deny hosts, globs, CIDRs, private-range policy
  context.py          Ctx: the only interface steps use to read and write scan state
  db.py               SQLite schema, checkpoints, cross-scan diffing
  http.py             Shared scope-aware, rate-limited aiohttp client + AuthSession
  authz_matrix.py     Multi-role response diffing
  api_clients.py      OSINT providers      secret_validator.py  Live key validation
  cdn_intel.py        CDN / origin intel   nessus_client.py     Optional Nessus API
  tools.py            External binary resolution
modules/              One file per pipeline step, each exposing async execute(ctx, engine, config)
payloads/             YAML payload and pattern sets
reports/              html_report.py + exporters.py (JSON / Markdown / SARIF)
examples/             Sample engagement config and scope file
docs/                 CLI syntax reference for the underlying tools
tests/                Offline test suite (pytest)
```

**Adding a step:**

1. Create `modules/stepXX_name.py` with `async def execute(ctx, engine, config) -> ctx`.
2. Register it in `core/pipeline.py`.
3. Write assets through `ctx.add_*()` so scope filtering applies automatically.
4. Use `engine.get(url)` (scope label `"target"`) for target traffic.

## Development

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

The suite is fully offline. Network tests start a throwaway keep-alive server on `127.0.0.1`, which is the condition that exposed the event-loop bug fixed in v2.0.

## Known limitations

- **External tools don't share the session.** Tools like nuclei and ffuf receive pre-filtered, in-scope target lists and the same rate ceiling, but not the authenticated session or per-request scope checks.
- **Subdomain probing uses default ports.** Only the exact target URL is verified on a non-standard port.
- **Findings are leads, not confirmed vulnerabilities.** Verify each one manually before reporting. The HTML report includes verification steps.

## Responsible use

Ghost is built for security professionals working within an authorised scope: bug-bounty programs, contracted penetration tests and your own infrastructure.

- Read and follow each program's rules: scope, rate limits, prohibited test types, and the required User-Agent or headers (`--user-agent`).
- Prefer `--dry-run`, `--scope-file` and `--strict-scope` on any engagement with a tight scope.
- Steps 8, 9, 12 and 13 send active probes. Skip them with `--skip-steps 8,9,12,13` where the rules require it.
- Unauthorised scanning is illegal in most jurisdictions. The authors accept no liability for misuse.

## License

Released under the [MIT License](LICENSE). See [CHANGELOG.md](CHANGELOG.md) for release history.
