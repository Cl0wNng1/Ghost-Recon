# Changelog

All notable changes to Ghost Recon. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [SemVer](https://semver.org/).

## [2.0.0] — 2026-10-11

First public release. Version numbering restarts at 2.0 for the public repository; earlier builds (internally v10–v15) were never published.

### Fixed — correctness
- **Every step after the first silently scanned nothing.** Each step ran in its own `asyncio.run()`, but the shared httpx engine, aiohttp client and module-level semaphores were created on the first step's loop. Against any keep-alive server, later requests failed with "Event loop is closed" and were swallowed as `code=0`. The whole pipeline now runs on one persistent loop (`core/pipeline.py`), and both HTTP clients rebind if they ever see a new loop.
- **`--resume` skipped most of the pipeline.** Checkpoints stored `step_id + 1`, but the auth step (ID 15) runs fifth, so resuming after it skipped steps 4–14. Checkpoints now store the explicit set of completed steps, and legacy checkpoints are mapped through the execution order. A step that fails is no longer marked complete.
- **Stealth profiles were ignored by the shared HTTP client.** `Config.stealth_profile` is a property but was called as a method. The `TypeError` was swallowed, so jitter and cooldowns never applied.
- **The authenticated session never reached most steps.** Only the shared aiohttp client carried it, and most steps use the engine. The engine now sends session headers and cookies on in-scope target requests (never to third-party intel APIs).
- **The access-control step never added known-good paths**, because `ctx.paths_200` (a property) was called as a function.
- **ProjectDiscovery `httpx` could be shadowed by the Python `httpx` CLI**, which made verification report "0 alive". The binary is now resolved by `core/tools.py`.
- **Small sensitive files were missed.** `.git/HEAD` (about 21 bytes) and short `.env` files fell under the `size > 50` cut-off. They are now detected by content signature.
- **A target on a non-default port was never registered as a live host.** The exact target URL is now always verified.
- `parse_target` now uses the public suffix list (`example.co.uk`, `user.github.io`), keeps ports and handles IPv6.

### Fixed — security
- **Scope guard was built on the wrong base.** `-u app.example.com` put the target itself out of scope, and `*.sub.example.com` widened to all of `example.com`. The base is now the target host.
- **A CIDR-only allow-list admitted every hostname.** It now admits none unless a host rule matches.
- **The scope guard was never wired in.** Scope is now enforced when assets are stored, in the engine (including each redirect hop) and in the shared client. Single-scope scans no longer probe every subdomain of the registrable domain.
- **Credentials were stored in plaintext in `ghost.db`.** Auth passwords, cookies, bearer tokens, raw auth headers and role tokens were saved unredacted. All credential fields are now fully masked whenever config is serialised.
- **`auth_session.json` was world-readable.** It is now created with mode `0600`.
- **Stored XSS in the HTML report.** Finding data from a hostile target (titles, URLs, response snippets) could break out of the inline `<script>` and run in the tester's browser. JSON is now escaped for script context, and every rendered field and attribute is escaped.
- The `gf` stage no longer builds a `bash -c` command string from the workspace path.

### Added
- **CLI flags for everything that was config-only:**
  - Authentication: `--auth-mode`, `--auth-cookie`, `--auth-bearer`, `--auth-header`, `--login-url`, `--username`, `--password`, `--auth-verify-url`, …
  - Access-control roles: `--role NAME:TYPE:VALUE`. The legacy `--auth-a` and `--auth-b` now feed this step.
  - Scope: `--scope-file`, `--include`, `--exclude`, `--strict-scope`, `--allow-private`.
- **`--config FILE`** (YAML or JSON). CLI flags override the file, and unknown keys are rejected.
- **`--dry-run`** shows the resolved config, scope and planned steps, and sends no traffic.
- **Run control:** `--list-steps`, `--skip-steps`, `--rate`, `--concurrency`, `--user-agent`, `--no-banner`, `--version`.
- **Exports:** `reports/findings.json`, `reports/report.md` and `reports/findings.sarif` (SARIF 2.1.0), selectable with `--format`.
- **`--fail-on SEVERITY`** exits with code 2 for CI. Interrupted runs exit with 130 after saving state and writing reports.
- `recon/out_of_scope.txt` records every asset that scope rules dropped.
- The shared HTTP client now honours `--proxy`.
- Offline regression suite (`tests/test_v2.py`, 25 tests). The orchestrator tests no longer touch the network or write into the repo.
- Packaging: `requirements.txt`, `requirements-dev.txt`, `.gitignore`, `LICENSE`, `examples/`, `docs/`.

### Changed
- The step registry moved to `core/pipeline.py`.
- `install.sh` now installs Ghost's Python requirements plus ffuf, dalfox, assetfinder, gf and crlfuzz, and prints the correct run command.
- `CLI_FAILOVER_MATRIX.sh` moved to `docs/` and no longer executes if run.
- Removed the deprecated `step08_vulnscan` and `step14_api` modules.

## Pre-2.0 (unreleased internal builds)

- **v15:** authenticated scanning, `ScopeGuard`, shared rate-limited client, multi-role authz matrix, and the enterprise vuln scanner wired in as step 8.
- **v14:** OSINT API sources, subdomain permutation, BOLA token flags, Nessus client.
- **v13:** OSINT clients and live secret validation.
- **v12:** CDN-aware triage, payload registry, HTML report.
- **v11:** SQLite-backed context and resumable checkpoints.
