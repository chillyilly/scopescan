# ScopeScan

**Attack surface security scanner** enumerate subdomains from 5 OSINT sources, then run 7 security scanning modules to identify vulnerabilities, misconfigurations, and exposure across an organization's entire subdomain footprint.

```
$ python3 scopescan.py example.com

[+] Found 342 subdomains
  [✓] Takeover:  2 vulnerable subdomains       ●∙ ◈ ∙●
  [✓] SSL/TLS:   14 issues found               ∙· ◆  ·∙
  [✓] Headers:   87 issues found               ●∙ ◇  ·
  [✓] Ports:     23 open ports                  ·  ◈ ∙●
  [✓] Cloud:     AWS, Cloudflare                ∙· ◆  ∙∙
  [✓] Tech:      56 technologies detected       ●∙ ◈ ··
  [✓] DNS:       19 issues found                ·◈●

Overall Grade: C  Score: 64/100
Issues: 3 critical, 12 high, 45 medium, 28 low
```

---

## Features

### Subdomain Enumeration (no API keys required)

| Source | Method | Key Required |
|--------|--------|:---:|
| **crt.sh** | Certificate Transparency logs | No |
| **HackerTarget** | Passive DNS / host search API | No |
| **RapidDNS** | DNS database scraping | No |
| **VirusTotal** | Ghetto scraping | Maybe |
| **SecurityTrails** | REST API | Yes (optional) |

The VirusTotal scraper works decently, but can't pull 10k subdomains yet — no API key needed.

All sources run concurrently and results are deduplicated.

### 7 Security Scanning Modules

#### 1. Subdomain Takeover Scanner
- Resolves CNAME chains for every subdomain
- Checks against **30+ known vulnerable services** (Heroku, Azure, S3, CloudFront, GitHub Pages, Netlify, Vercel, Shopify, Ghost, Pantheon, etc.)
- **HTTP confirmation probes** — fetches the subdomain and matches response body against service-specific fingerprints ("no such app", "NoSuchBucket", "There isn't a GitHub Pages site here", etc.)
- Distinguishes dangling CNAMEs (target doesn't resolve) from live-but-claimable services

#### 2. SSL/TLS Certificate Auditor
- Connects to port 443 on each subdomain and pulls the certificate
- Checks: expired, expiring soon (<7d / <30d), self-signed, hostname mismatch (CN/SAN vs subdomain), missing Subject Alternative Names, wildcard abuse
- Parses issuer, subject, serial number, validity dates, SAN count

#### 3. HTTP Security Header Scanner
- Fetches both HTTPS and HTTP for each subdomain
- Audits: **HSTS** (missing, short max-age, no includeSubDomains), **CSP** (missing, unsafe-inline, unsafe-eval, wildcard sources), **X-Frame-Options**, **X-Content-Type-Options**, **CORS** (wildcard origin, credentials with wildcard), **Referrer-Policy**, **Permissions-Policy**
- Detects HTTP-to-HTTPS redirect absence
- Flags info leaks: `Server` header version disclosure, `X-Powered-By`
- Flags deprecated `X-XSS-Protection`

#### 4. Exposed Service Discovery
- TCP connect scan across **28 common ports** (FTP, SSH, SMTP, HTTP, HTTPS, MySQL, PostgreSQL, Redis, Elasticsearch, MongoDB, Memcached, etcd, Kibana, Grafana, Jupyter, RDP, VNC, RabbitMQ, MSSQL, SMB, etc.)
- Banner grabbing on open ports
- Severity classification: databases/admin panels = **critical**, dev tools = **high**, HTTP alternates = **medium**

#### 5. Cloud Asset Inventory
- Resolves subdomain IPs and maps them to **cloud providers** using live IP range data from AWS (`ip-ranges.json`) and Cloudflare (`ips-v4`)
- **CDN detection** from response headers and CNAME chains (CloudFront, Fastly, Akamai, Cloudflare, Vercel, Netlify)
- ASN-based fallback identification for GCP, Azure, DigitalOcean, Linode, OVH, Hetzner

#### 6. Web Technology Fingerprinter
- **Server identification** from `Server` header (nginx, Apache, IIS versions)
- **Framework detection** from `X-Powered-By`, cookies (`PHPSESSID`=PHP, `JSESSIONID`=Java, `ASP.NET_SessionId`=.NET)
- **CMS detection**: WordPress (`/wp-content/`), meta generator tags (Drupal, Joomla, etc.)
- **WAF detection** against **10 WAF signatures**: Cloudflare, AWS WAF, Akamai, Sucuri, Incapsula/Imperva, Fastly, F5 BIG-IP, ModSecurity, Barracuda, DDoS-Guard
- **JS framework detection**: React, Angular, Vue.js, jQuery

#### 7. DNS Zone Health Auditor
- **CAA records** — flags missing Certificate Authority Authorization
- **DNSSEC** — checks for DS records at parent zone
- **AXFR zone transfer testing** — attempts zone transfer against nameservers (critical if successful)
- **NS consistency** — verifies nameservers resolve and there are ≥2
- **Orphaned records** — detects A records pointing to IPs that don't respond on 80/443

### Risk Scoring

Each subdomain gets a composite risk score based on findings from all modules:

- **Per-module weighting**: Takeover (1.5x), Ports (1.3x), SSL (1.2x), DNS (1.0x), Headers (0.8x), Cloud (0.6x), Tech (0.5x)
- **Exponential decay scoring**: `score = 100 × e^(-raw/30)` — a few critical findings drop the score fast, many low findings don't dominate
- **Letter grades**: A (90-100), B (75-89), C (60-74), D (40-59), F (0-39)
- **Overall posture** = average score across all subdomains

### Output Formats

- **Interactive terminal viewer** with posture dashboard, rankings, per-subdomain drill-down, module views, severity filters, and subdomain search
- **HTML report** — dark-themed, self-contained single file with summary dashboard, stat cards, module tables with severity coloring, collapsible per-subdomain details, sortable tables
- **CSV** — flat spreadsheet with one row per subdomain
- **JSON** — complete structured data dump

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/scopescan.git
cd scopescan

# Install required dependencies
python3 -m venv .venv
source .venv/bin/activate
pip3 install dnspython requests playwright playwright-stealth
playwright install firefox
```

### Dependencies

| Package | Required | Purpose |
|---------|:---:|---------|
| `dnspython` | Yes | DNS record queries (A, AAAA, CNAME, NS, TXT, MX, CAA, SOA, TLSA, AXFR) |
| `requests` | Yes | HTTP requests for OSINT sources, header scanning, tech fingerprinting |
| `playwright` | No | Headless browser for VirusTotal scraping |
| `playwright-stealth` | No | Anti-detection patches for headless browser |

Python 3.8+ required. All scanning modules use only the Python standard library (`ssl`, `socket`, `ipaddress`) beyond the two required packages.

---

## Usage

### Interactive Mode

```bash
python3 scopescan.py
```

Prompts for a domain, enumerates subdomains, then presents a menu:

```
=== ScopeScan ===
  Domain: example.com | 342 subdomains

  1) List subdomains
  2) Validate subdomains (DNS)
  3) Full scan (all modules)
  4) Subdomain Takeover scan
  5) SSL/TLS Certificate audit
  6) HTTP Security Headers
  7) Exposed Service Discovery
  8) Cloud Asset Inventory
  9) Web Technology Fingerprint
  10) DNS Zone Health
  11) View results [results ready]
  12) Export results
  q) Quit
```

Run individual modules (options 4-10) or a full scan (option 3). After scanning, option 11 opens the **results viewer**:

```
══════════════════════════════════════════════════════════════
  RESULTS VIEWER — example.com
  Grade: C  Score: 64/100  Subdomains: 342
  Issues: 3 critical, 12 high, 45 medium, 28 low
══════════════════════════════════════════════════════════════

  Views:
    1) Security Posture Dashboard
    2) Subdomain Risk Rankings
    3) Search subdomain

  By Module:
    4-10) Takeover / SSL / Headers / Ports / Cloud / Tech / DNS

  By Severity:
    c) All Critical issues
    h) All High issues
    m) All Medium issues
```

The rankings view is paginated and lets you enter a subdomain's rank number to drill into its full detail — every module's findings, header check grid, open ports, cloud provider, technology stack, and DNS health status.

### CLI Mode

```bash
# Full scan with all modules, auto-export
python3 scopescan.py example.com

# Specific modules only
python3 scopescan.py example.com --modules takeover,ssl,headers

# Custom output path
python3 scopescan.py example.com -o /path/to/report

# Load subdomains from file (skip enumeration)
python3 scopescan.py example.com --subs-file subdomains.txt

# Skip enumeration, scan root domain only
python3 scopescan.py example.com --skip-enum

# Adjust concurrency
python3 scopescan.py example.com --workers 25

# Verbose output
python3 scopescan.py example.com --debug
```

### CLI Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Target domain (omit for interactive mode) |
| `-o, --output` | Output base path (generates `.csv`, `.json`, `.html`) |
| `--modules` | Comma-separated module list: `takeover,ssl,headers,ports,cloud,tech,dns` |
| `--subs-file` | Load subdomains from a file (one per line) instead of enumerating |
| `--skip-enum` | Skip subdomain enumeration; scan root domain only |
| `--workers` | Thread pool concurrency level (default: 15) |
| `--debug` | Verbose output with per-source and per-subdomain progress |

### API Keys (Optional)

Set these for additional subdomain sources:

```bash
# Environment variables
export SECURITYTRAILS_API_KEY="your_key_here"
export VT_API_KEY="your_key_here"

# Or edit the top of scopescan.py
SECURITYTRAILS_API_KEY = "your_key_here"
VT_API_KEY = "your_key_here"
```

Without API keys, the tool still works using crt.sh, HackerTarget, RapidDNS, and the VirusTotal browser scraper.

---

## Example Output

### Terminal — Posture Dashboard

```
══════════════════════════════════════════════════════════════════
  ██████╗    Score: 64/100
  ██╔════╝   Fair — several issues need attention
  ██║
  ██║
  ╚██████╗
   ╚═════╝

  Issue Distribution (87 total across 342 subdomains):

  CRIT  ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 3
  HIGH  ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 12
  MED   ████████████████████████████████████████░░ 45
  LOW   ███████████████████████████░░░░░░░░░░░░░░░ 28
  INFO  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0
══════════════════════════════════════════════════════════════════
```

### Terminal — Header Scan Grid

```
  www.example.com                        HSTS:✓ CSP:✗ XFO:✗ XCTO:✓ Ref:✗ Perm:✗
  api.example.com                        HSTS:✓ CSP:✓ XFO:✓ XCTO:✓ Ref:✓ Perm:✗
  staging.example.com                    HSTS:✗ CSP:✗ XFO:✗ XCTO:✗ Ref:✗ Perm:✗
```

### Terminal — Subdomain Detail Drill-Down

```
════════════════════════════════════════════════════════════════
  staging.example.com
  Grade: F  Score: 12/100  Risk: Critical
  Issues: 9
════════════════════════════════════════════════════════════════

  Module Risk Contribution:
    headers      █████████████████████████ 8.4
    ssl          ████████████████         5.2
    ports        ████████████             4.1
    dns          ██████                   2.0

  [SSL/TLS]
    Subject:  *.example.com
    Issuer:   Let's Encrypt
    Expiry:   Mar 15 2026 (expired -8d)
    [CRIT] Certificate expired 8 days ago

  [HEADERS]
    HTTPS: yes  HTTP: yes  HTTP->HTTPS: no
    HSTS:✗  CSP:✗  XFO:✗  XCTO:✗  Ref:✗  Perm:✗
    [HIGH] No Strict-Transport-Security header
    [HIGH] HTTP accessible without redirect to HTTPS
    [MED ] No Content-Security-Policy header

  [OPEN PORTS] (52.10.44.123)
    [CRIT] 6379/Redis
    [CRIT] 9200/Elasticsearch
    [HIGH] 8888/Jupyter  Jupyter Notebook 6.4.12
```

### HTML Report

The HTML export generates a self-contained dark-themed report with:
- Overall letter grade badge
- Summary stat cards grid
- Per-module findings tables with severity coloring
- Collapsible per-subdomain detail sections
- Table sorting and severity filtering via inline JavaScript

---

## How It Works

```
User Input (domain)
    │
    ▼
Subdomain Enumeration ─── 5 OSINT sources (concurrent)
    │
    ▼
DNS Validation (optional) ─── filter to resolving subdomains
    │
    ▼
┌───────────────────────────────────────────────┐
│  7 Scanning Modules (each uses ThreadPool)    │
│                                               │
│  ┌─ Takeover ── CNAME + HTTP fingerprint      │
│  ├─ SSL/TLS ── cert chain analysis            │
│  ├─ Headers ── security header audit          │
│  ├─ Ports ──── TCP connect + banner grab      │
│  ├─ Cloud ──── IP→provider + CDN detection    │
│  ├─ Tech ───── server/framework/WAF/CMS       │
│  └─ DNS ────── CAA/DNSSEC/AXFR/NS health      │
└───────────────────────────────────────────────┘
    │
    ▼
Per-Subdomain Risk Scoring (weighted, exponential decay)
    │
    ▼
Overall Security Posture (A-F grade)
    │
    ▼
Export: CSV / JSON / HTML / Interactive Viewer
```

---

## Usage

This tool is designed for **authorized security testing** and **defensive security auditing**. Use it to:

- Audit your own organization's attack surface
- Assess subdomain security posture during penetration tests (with authorization)
- Identify forgotten/orphaned subdomains and services
- Verify SSL certificate health across your infrastructure
- Discover exposed internal services

---

## License

MIT
