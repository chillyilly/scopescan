#!/usr/bin/env python3
"""
ScopeScan — Comprehensive Attack Surface Security Scanner.

Performs deep security analysis across a domain's subdomains using 7 scanning modules:

  1. Subdomain Takeover Scanner — dangling CNAMEs + HTTP fingerprint confirmation
  2. SSL/TLS Certificate Auditor — expiry, self-signed, hostname mismatch, SAN checks
  3. HTTP Security Header Scanner — HSTS, CSP, CORS, X-Frame-Options, info leaks
  4. Exposed Service Discovery — TCP connect scan + banner grab on common ports
  5. Cloud Asset Inventory — IP-to-cloud mapping, CDN detection
  6. Web Technology Fingerprinter — CMS, frameworks, WAF, server stack
  7. DNS Zone Health Auditor — CAA, DNSSEC, AXFR, orphaned records

  Output:
    - Interactive terminal UI or CLI one-shot mode
    - Export to CSV, JSON, and dark-themed HTML report
"""

# ----- User Configuration -----
SECURITYTRAILS_API_KEY = ""   # or set env SECURITYTRAILS_API_KEY
VT_API_KEY = ""               # or set env VT_API_KEY

import os
import re
import csv
import sys
import json
import signal
import argparse
import time
import base64
import struct
import socket
import ssl
import ipaddress
import random
import math
import warnings
from html import escape as html_escape
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

import requests
from dns.resolver import resolve, Resolver, NXDOMAIN, NoAnswer, Timeout, NoNameservers
import dns.resolver
import dns.rdatatype

# ── Globals ──────────────────────────────────────────────────────────────────

SECURITYTRAILS_API_KEY = SECURITYTRAILS_API_KEY or os.getenv("SECURITYTRAILS_API_KEY", "")
VT_API_KEY = VT_API_KEY or os.getenv("VT_API_KEY", "")

KNOWN_MAIL_PROVIDERS = {
    "google.com":              "Google Workspace",
    "googlemail.com":          "Google Workspace",
    "outlook.com":             "Microsoft 365",
    "protection.outlook.com":  "Microsoft 365",
    "pphosted.com":            "Proofpoint",
    "mimecast.com":            "Mimecast",
    "mailgun.org":             "Mailgun",
    "sendgrid.net":            "SendGrid",
    "amazonses.com":           "Amazon SES",
    "zendesk.com":             "Zendesk",
    "freshdesk.com":           "Freshdesk",
    "mandrillapp.com":         "Mandrill/Mailchimp",
    "postmarkapp.com":         "Postmark",
    "sparkpostmail.com":       "SparkPost",
    "messagelabs.com":         "Broadcom/Symantec",
    "barracudanetworks.com":   "Barracuda",
    "fireeyecloud.com":        "Trellix/FireEye",
    "mailchimp.com":           "Mailchimp",
    "hubspotemail.net":        "HubSpot",
    "exacttarget.com":         "Salesforce MC",
    "cust-spf.exacttarget.com":"Salesforce MC",
    "secureserver.net":        "GoDaddy",
    "emailsrvr.com":           "Rackspace",
    "zoho.com":                "Zoho",
}

SPF_INCLUDE_PROVIDERS = {
    "google.com":              "Google Workspace",
    "_spf.google.com":         "Google Workspace",
    "protection.outlook.com":  "Microsoft 365",
    "spf.protection.outlook.com": "Microsoft 365",
    "pphosted.com":            "Proofpoint",
    "mimecast":                "Mimecast",
    "mailgun.org":             "Mailgun",
    "sendgrid.net":            "SendGrid",
    "amazonses.com":           "Amazon SES",
    "mandrillapp.com":         "Mandrill/Mailchimp",
    "servers.mcsv.net":        "Mailchimp",
    "postmarkapp.com":         "Postmark",
    "sparkpostmail.com":       "SparkPost",
    "zendesk.com":             "Zendesk",
    "freshdesk.com":           "Freshdesk",
    "zoho.com":                "Zoho",
    "secureserver.net":        "GoDaddy",
    "emailsrvr.com":           "Rackspace",
    "hubspotemail.net":        "HubSpot",
    "exacttarget.com":         "Salesforce MC",
}

# ── Constants ────────────────────────────────────────────────────────────────

TAKEOVER_HTTP_FINGERPRINTS = {
    ".herokuapp.com": ["no such app", "There is no app configured at that hostname"],
    ".herokudns.com": ["no such app"],
    ".azurewebsites.net": ["404 Web Site not found"],
    ".cloudapp.net": ["not found"],
    ".blob.core.windows.net": ["The specified container does not exist", "BlobNotFound"],
    ".trafficmanager.net": ["not found"],
    ".cloudfront.net": ["Bad Request", "ERROR: The request could not be satisfied"],
    ".s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist", "AllAccessDisabled"],
    ".s3-website": ["NoSuchBucket"],
    ".elasticbeanstalk.com": ["404 Not Found"],
    ".ghost.io": ["Site not found"],
    ".pantheonsite.io": ["404 Unknown Site"],
    ".domains.tumblr.com": ["There's nothing here", "Whatever you were looking for"],
    ".wordpress.com": ["Do you want to register"],
    ".myshopify.com": ["Sorry, this shop is currently unavailable"],
    ".zendesk.com": ["Help Center Closed"],
    ".freshdesk.com": ["There is no helpdesk here"],
    ".uservoice.com": ["This UserVoice subdomain is currently available"],
    ".surge.sh": ["project not found"],
    ".bitbucket.io": ["Repository not found"],
    ".ghost.org": ["Site not found"],
    ".statuspage.io": ["Status page launched"],
    ".unbounce.com": ["The requested URL was not found"],
    ".feedpress.me": ["The feed has not been found"],
    ".netlify.app": ["Not Found - Request ID"],
    ".vercel.app": ["The deployment could not be found"],
    ".fly.dev": ["not found"],
    ".pages.dev": ["your worker is not returning"],
    ".appspot.com": ["Error: Not Found", "The requested URL was not found"],
    ".github.io": ["There isn't a GitHub Pages site here"],
}

TAKEOVER_FINGERPRINTS = [
    ".herokuapp.com",
    ".herokudns.com",
    ".azurewebsites.net",
    ".cloudapp.net",
    ".trafficmanager.net",
    ".blob.core.windows.net",
    ".cloudfront.net",
    ".s3.amazonaws.com",
    ".s3-website",
    ".elasticbeanstalk.com",
    ".ghost.io",
    ".pantheonsite.io",
    ".domains.tumblr.com",
    ".wordpress.com",
    ".myshopify.com",
    ".zendesk.com",
    ".freshdesk.com",
    ".uservoice.com",
    ".surge.sh",
    ".bitbucket.io",
    ".ghost.org",
    ".helpjuice.com",
    ".helpscoutdocs.com",
    ".mashery.com",
    ".statuspage.io",
    ".teamwork.com",
    ".thinkific.com",
    ".unbounce.com",
    ".feedpress.me",
    ".cargocollective.com",
    ".smartling.com",
    ".acquia-test.co",
    ".proposify.biz",
    ".simplebooklet.com",
    ".getresponse.com",
    ".vend-dns.com",
    ".appspot.com",
    ".fly.dev",
    ".netlify.app",
    ".vercel.app",
    ".render.com",
    ".pages.dev",
]

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport", 27017: "MongoDB",
    11211: "Memcached", 2379: "etcd", 5601: "Kibana", 3000: "Grafana/Dev",
    8888: "Jupyter", 4443: "HTTPS-Alt2", 15672: "RabbitMQ-Mgmt",
}

EXPOSED_SERVICE_SEVERITY = {
    "critical": {3306, 5432, 6379, 27017, 11211, 2379, 9200, 9300, 1433, 5900},
    "high": {5601, 8888, 3000, 445, 3389, 15672, 25},
    "medium": {8080, 8443, 4443, 21},
    "low": {22, 80, 443, 53, 110, 143, 993, 995},
}

REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"
]
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

WAF_SIGNATURES = {
    "Cloudflare": {"headers": {"Server": "cloudflare", "CF-RAY": ""}, "cookies": ["__cfduid", "__cf_bm", "cf_clearance"]},
    "AWS WAF": {"headers": {"x-amzn-requestid": ""}, "cookies": ["awsalb", "awsalbcors"]},
    "Akamai": {"headers": {"x-akamai-transformed": ""}, "cookies": ["akamai_generated_"]},
    "Sucuri": {"headers": {"x-sucuri-id": "", "server": "Sucuri"}, "cookies": []},
    "Incapsula/Imperva": {"headers": {"x-iinfo": ""}, "cookies": ["incap_ses_", "visid_incap_"]},
    "Fastly": {"headers": {"x-fastly-request-id": "", "via": "varnish"}, "cookies": []},
    "F5 BIG-IP": {"headers": {"server": "BigIP", "x-cnection": ""}, "cookies": ["BIGipServer"]},
    "ModSecurity": {"headers": {"server": "Mod_Security"}, "cookies": []},
    "Barracuda": {"headers": {"server": "BarracudaHTTPD"}, "cookies": ["barra_counter_session"]},
    "DDoS-Guard": {"headers": {"server": "ddos-guard"}, "cookies": []},
}

CLOUD_ASN_MAP = {
    16509: "AWS", 14618: "AWS", 8075: "Azure", 8068: "Azure",
    15169: "GCP", 396982: "GCP", 13335: "Cloudflare", 14061: "DigitalOcean",
    63949: "Linode/Akamai", 20940: "Akamai", 16276: "OVH",
    24940: "Hetzner", 36351: "SoftLayer/IBM", 19551: "Incapsula",
}

SEVERITY_WEIGHTS = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.0}
RISK_COLORS = {"Critical": "#e74c3c", "High": "#e67e22", "Medium": "#f1c40f", "Low": "#3498db", "Info": "#95a5a6"}

# ── Signal Handler ───────────────────────────────────────────────────────────

def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ── DNS Helpers ──────────────────────────────────────────────────────────────

def _resolver(timeout=3, lifetime=6):
    r = Resolver()
    r.timeout = timeout
    r.lifetime = lifetime
    return r

def query_txt(domain, timeout=3):
    try:
        answers = _resolver(timeout).resolve(domain, "TXT")
        return [
            txt.decode("utf-8")
            for rdata in answers
            for txt in rdata.strings
        ]
    except (NXDOMAIN, NoAnswer, Timeout, NoNameservers):
        return []
    except Exception:
        return []

def query_mx(domain, timeout=3):
    try:
        answers = _resolver(timeout).resolve(domain, "MX")
        return sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0],
        )
    except (NXDOMAIN, NoAnswer, Timeout, NoNameservers):
        return []
    except Exception:
        return []

def query_a(domain, timeout=2):
    try:
        answers = _resolver(timeout).resolve(domain, "A")
        return [str(r) for r in answers]
    except Exception:
        return []

def query_aaaa(domain, timeout=2):
    try:
        answers = _resolver(timeout).resolve(domain, "AAAA")
        return [str(r) for r in answers]
    except Exception:
        return []

def query_cname(domain, timeout=2):
    try:
        answers = _resolver(timeout).resolve(domain, "CNAME")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []

def query_ns(domain, timeout=2):
    try:
        answers = _resolver(timeout).resolve(domain, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []

def query_tlsa(domain, port=25, timeout=3):
    """Query DANE TLSA records for SMTP (RFC 7672)."""
    name = f"_{port}._tcp.{domain}"
    try:
        answers = _resolver(timeout).resolve(name, "TLSA")
        results = []
        for rdata in answers:
            results.append({
                "usage": rdata.usage,
                "selector": rdata.selector,
                "mtype": rdata.mtype,
                "cert": rdata.cert.hex(),
            })
        return results
    except Exception:
        return []

def query_caa(domain, timeout=2):
    """Query CAA records, returns list of dicts with flags/tag/value."""
    try:
        answers = _resolver(timeout).resolve(domain, "CAA")
        results = []
        for rdata in answers:
            results.append({
                "flags": rdata.flags,
                "tag": rdata.tag.decode("utf-8") if isinstance(rdata.tag, bytes) else str(rdata.tag),
                "value": rdata.value.decode("utf-8") if isinstance(rdata.value, bytes) else str(rdata.value),
            })
        return results
    except Exception:
        return []

def query_soa(domain, timeout=2):
    """Query SOA, returns dict with mname/rname/serial/refresh/retry/expire/minimum."""
    try:
        answers = _resolver(timeout).resolve(domain, "SOA")
        for rdata in answers:
            return {
                "mname": str(rdata.mname).rstrip("."),
                "rname": str(rdata.rname).rstrip("."),
                "serial": rdata.serial,
                "refresh": rdata.refresh,
                "retry": rdata.retry,
                "expire": rdata.expire,
                "minimum": rdata.minimum,
            }
    except Exception:
        return None

def try_axfr(domain, ns, timeout=5):
    """Attempt AXFR zone transfer against a nameserver, returns list of record strings or empty list."""
    try:
        import dns.query
        import dns.zone
        ns_ips = query_a(ns)
        if not ns_ips:
            return []
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ips[0], domain, timeout=timeout))
        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                records.append(f"{name} {rdataset.rdtype.name} {rdataset}")
        return records
    except Exception:
        return []

# ── Subdomain Enumeration Sources ────────────────────────────────────────────

def get_crtsh_subdomains(domain, debug=False):
    """Query crt.sh Certificate Transparency logs for subdomains.

    crt.sh is a free service that can be slow (30-60s for large domains)
    and returns 503 when overloaded. We retry up to 3 times with backoff
    and use a generous timeout.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0"}
    max_retries = 3

    for attempt in range(1, max_retries + 1):
        try:
            if debug and attempt > 1:
                print(f"  [crt.sh] Retry {attempt}/{max_retries}...")
            resp = requests.get(url, headers=headers, timeout=60)
            if resp.status_code == 503:
                if debug:
                    print(f"  [crt.sh] 503 (overloaded), "
                          f"waiting {10 * attempt}s...")
                time.sleep(10 * attempt)
                continue
            if resp.status_code != 200:
                raise Exception(f"HTTP {resp.status_code}")
            if not resp.headers.get("Content-Type", "").startswith("application/json"):
                raise Exception("non-JSON response")
            text = resp.text.strip()
            if not text.startswith("["):
                raise Exception("unexpected format")
            seen = set()
            for entry in resp.json():
                for sub in entry.get("name_value", "").splitlines():
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and "*" not in sub:
                        seen.add(sub)
            if debug:
                print(f"  [crt.sh] {len(seen)} subdomains")
            return seen
        except requests.exceptions.Timeout:
            if debug:
                print(f"  [crt.sh] Timeout on attempt {attempt} (60s), "
                      f"{'retrying' if attempt < max_retries else 'giving up'}...")
            if attempt < max_retries:
                time.sleep(5)
                continue
        except Exception as e:
            if debug:
                print(f"  [crt.sh] Error: {e}")
            break
    return set()

def get_securitytrails_subdomains(domain, debug=False):
    if not SECURITYTRAILS_API_KEY:
        if debug:
            print("  [securitytrails] No API key, skipping")
        return set()
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        r = requests.get(url, headers={"APIKEY": SECURITYTRAILS_API_KEY}, timeout=15)
        data = r.json()
        subs = {f"{s}.{domain}" for s in data.get("subdomains", [])}
        if debug:
            print(f"  [securitytrails] {len(subs)} subdomains")
        return subs
    except Exception as e:
        if debug:
            print(f"  [securitytrails] Error: {e}")
        return set()

def _vt_click_load_more(page, target_idx):
    """Click the Nth vt-ui-button.load-more web component in the shadow DOM."""
    return page.evaluate("""(targetIdx) => {
        let idx = 0;
        function search(root, d) {
            if (d > 10) return false;
            const els = root.querySelectorAll ?
                root.querySelectorAll('*') : [];
            for (const el of els) {
                if (el.shadowRoot && search(el.shadowRoot, d + 1))
                    return true;
                if (el.tagName === 'VT-UI-BUTTON' &&
                    (el.className || '').toString().includes('load-more')) {
                    idx++;
                    if (idx === targetIdx) {
                        el.scrollIntoView({block: 'center'});
                        el.click();
                        return true;
                    }
                }
            }
            return false;
        }
        return search(document, 0);
    }""", target_idx)


def _vt_scrape_headless(domain, debug=False):
    """Scrape VirusTotal subdomains using a stealth headless browser.

    Applies anti-detection patches (navigator.webdriver, WebGL, plugins, etc.)
    to appear as a normal browser session. Loads the relations page, intercepts
    subdomain API responses, then clicks the load-more button to paginate.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        if debug:
            print("  [virustotal/browser] playwright not installed, skipping")
        return set()

    # Optional stealth patches
    stealth_obj = None
    try:
        from playwright_stealth import Stealth
        stealth_obj = Stealth(
            navigator_webdriver=True,
            navigator_plugins=True,
            navigator_languages=True,
            navigator_platform=True,
            navigator_vendor=True,
            navigator_user_agent=True,
            webgl_vendor=True,
            chrome_runtime=True,
            chrome_app=True,
            hairline=True,
            media_codecs=True,
            navigator_hardware_concurrency=True,
            iframe_content_window=True,
            navigator_permissions=True,
            sec_ch_ua=True,
            error_prototype=True,
        )
    except ImportError:
        pass

    all_subs = set()
    start_time = time.time()
    max_duration = 120

    def _handle_response(response):
        if "/subdomains" in response.url and response.status == 200:
            try:
                data = response.json()
                for entry in data.get("data", []):
                    sid = entry.get("id")
                    if sid:
                        all_subs.add(sid)
            except Exception:
                pass

    try:
        with sync_playwright() as p:
            # Use Firefox — fewer headless detection vectors than Chromium
            browser = p.firefox.launch(headless=True)

            # Realistic browser context
            context = browser.new_context(
                viewport={
                    "width": random.choice([1366, 1440, 1536, 1920]),
                    "height": random.choice([768, 900, 864, 1080]),
                },
                locale="en-US",
                timezone_id="America/New_York",
                color_scheme="dark",
            )

            # Apply stealth patches if available
            if stealth_obj:
                stealth_obj.apply_stealth_sync(context)
                if debug:
                    print("  [virustotal/browser] Stealth patches applied")

            page = context.new_page()
            page.on("response", _handle_response)

            # Simulate human: visit VT homepage first, then navigate
            if debug:
                print("  [virustotal/browser] Visiting homepage first...")
            page.goto("https://www.virustotal.com/gui/home/search",
                      wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(random.randint(2000, 4000))

            # Dismiss cookie/CAPTCHA overlays
            page.evaluate("""() => {
                document.querySelectorAll(
                    'captcha-dialog, vt-ui-cookie-dialog, .modal-backdrop, .cookie-banner'
                ).forEach(el => el.remove());
            }""")
            page.wait_for_timeout(random.randint(500, 1500))

            # Simulate human mouse movement
            page.mouse.move(
                random.randint(200, 800),
                random.randint(200, 600),
                steps=random.randint(5, 15)
            )

            # Navigate to the target domain's relations page
            gui_url = f"https://www.virustotal.com/gui/domain/{domain}/relations"
            if debug:
                print(f"  [virustotal/browser] Navigating to {domain}")
            page.goto(gui_url, wait_until="domcontentloaded", timeout=30000)

            # Wait for initial API calls with human-like patience
            page.wait_for_timeout(random.randint(3000, 5000))

            # Dismiss any CAPTCHA/overlays that appeared
            page.evaluate("""() => {
                document.querySelectorAll(
                    'captcha-dialog, vt-ui-cookie-dialog, .modal-backdrop'
                ).forEach(el => el.remove());
                // Also remove from shadow DOM
                function clean(root, d) {
                    if (d > 5) return;
                    const els = root.querySelectorAll ?
                        root.querySelectorAll('*') : [];
                    for (const el of els) {
                        if (el.shadowRoot) clean(el.shadowRoot, d + 1);
                        if (el.tagName === 'CAPTCHA-DIALOG' ||
                            el.tagName === 'VT-UI-COOKIE-DIALOG')
                            el.remove();
                    }
                }
                clean(document, 0);
            }""")

            # Wait for subdomain data to load
            page.wait_for_timeout(random.randint(4000, 6000))

            if debug:
                print(f"  [virustotal/browser] Initial page captured "
                      f"{len(all_subs)} subdomains")

            if len(all_subs) == 0:
                if debug:
                    print("  [virustotal/browser] No initial data — "
                          "likely CAPTCHA blocked. Aborting gracefully.")
                browser.close()
                return all_subs

            # Simulate a small scroll (human behavior)
            page.mouse.wheel(0, random.randint(200, 500))
            page.wait_for_timeout(random.randint(800, 1500))

            # Find which load-more button is for subdomains by probing
            total_btns = page.evaluate("""() => {
                let count = 0;
                function search(root, d) {
                    if (d > 10) return;
                    const els = root.querySelectorAll ?
                        root.querySelectorAll('*') : [];
                    for (const el of els) {
                        if (el.shadowRoot) search(el.shadowRoot, d + 1);
                        if (el.tagName === 'VT-UI-BUTTON' &&
                            (el.className || '').toString().includes('load-more'))
                            count++;
                    }
                }
                search(document, 0);
                return count;
            }""")

            sub_btn_idx = None
            for test_idx in range(1, min(total_btns + 1, 8)):
                prev = len(all_subs)
                _vt_click_load_more(page, test_idx)
                page.wait_for_timeout(random.randint(1500, 2500))
                if len(all_subs) > prev:
                    sub_btn_idx = test_idx
                    if debug:
                        print(f"  [virustotal/browser] Subdomain button is "
                              f"#{test_idx} (+{len(all_subs) - prev})")
                    break

            if sub_btn_idx is None:
                if debug:
                    print(f"  [virustotal/browser] Could not identify subdomain "
                          f"button among {total_btns}")
            else:
                # Click repeatedly with human-like timing
                max_clicks = 200
                stale = 0
                clicks = 1
                while clicks < max_clicks and (time.time() - start_time) < max_duration:
                    prev_count = len(all_subs)
                    _vt_click_load_more(page, sub_btn_idx)
                    # Randomized wait between clicks
                    page.wait_for_timeout(random.randint(1200, 2200))
                    if len(all_subs) > prev_count:
                        clicks += 1
                        stale = 0
                        if debug and clicks % 5 == 0:
                            print(f"  [virustotal/browser] {len(all_subs)} "
                                  f"subdomains ({clicks} pages)...")
                    else:
                        stale += 1
                        if stale >= 3:
                            break

            elapsed = time.time() - start_time
            if debug:
                print(f"  [virustotal/browser] Done: {len(all_subs)} subdomains "
                      f"in {elapsed:.1f}s")

            browser.close()
    except Exception as e:
        if debug:
            print(f"  [virustotal/browser] Error: {e}")

    return all_subs


def get_virustotal_subdomains(domain, debug=False):
    """Harvest subdomains from VirusTotal using three methods in priority order:

    1. Headless browser (playwright) — scrapes the public website at
       /gui/domain/{domain}/relations with full JS execution, intercepts
       the /ui/ API responses, and clicks through pagination. No API key needed.
    2. v3 API — if an API key is configured, uses the authenticated endpoint.
    3. Graceful skip if neither works.
    """
    all_subs = set()

    # --- Method 1: Headless browser scrape (no API key required) ---
    all_subs = _vt_scrape_headless(domain, debug)
    if all_subs:
        return all_subs

    # --- Method 2: Fallback to v3 API (requires API key) ---
    if not VT_API_KEY:
        if debug:
            print("  [virustotal/api] No API key and browser scrape yielded 0, skipping")
        return all_subs
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": VT_API_KEY}
        while url:
            r = requests.get(url, headers=headers, timeout=15)
            data = r.json()
            for entry in data.get("data", []):
                sid = entry.get("id")
                if sid:
                    all_subs.add(sid)
            url = data.get("links", {}).get("next")
        if debug:
            print(f"  [virustotal/api] {len(all_subs)} subdomains total")
        return all_subs
    except Exception as e:
        if debug:
            print(f"  [virustotal/api] Error: {e}")
        return all_subs

def get_hackertarget_subdomains(domain, debug=False):
    """Query HackerTarget's free host search API. No key required.
    Returns plain text: hostname,ip per line.
    """
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}")
        # Check for API error messages (plain text starting with "error")
        if r.text.strip().lower().startswith("error"):
            raise Exception(r.text.strip()[:100])
        subs = set()
        for line in r.text.strip().splitlines():
            parts = line.split(",")
            if parts and parts[0].strip().endswith(domain):
                subs.add(parts[0].strip().lower())
        if debug:
            print(f"  [hackertarget] {len(subs)} subdomains")
        return subs
    except Exception as e:
        if debug:
            print(f"  [hackertarget] Error: {e}")
        return set()

def get_rapiddns_subdomains(domain, debug=False):
    """Scrape RapidDNS.io for subdomains. No key required.
    Returns an HTML page with subdomains in table rows.
    """
    try:
        url = f"https://rapiddns.io/subdomain/{quote(domain)}?full=1"
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=25)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}")
        pattern = r"([\w][\w\.-]*\." + re.escape(domain) + r")"
        subs = {s.lower() for s in re.findall(pattern, r.text)}
        if debug:
            print(f"  [rapiddns] {len(subs)} subdomains")
        return subs
    except Exception as e:
        if debug:
            print(f"  [rapiddns] Error: {e}")
        return set()

def enumerate_subdomains(domain, debug=False, workers=5):
    """Fetch subdomains from all OSINT sources concurrently."""
    sources = [
        get_crtsh_subdomains,
        get_securitytrails_subdomains,
        get_virustotal_subdomains,
        get_hackertarget_subdomains,
        get_rapiddns_subdomains,
    ]
    all_subs = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fn, domain, debug): fn.__name__ for fn in sources}
        for future in as_completed(futures):
            try:
                all_subs.update(future.result())
            except Exception:
                pass
    return sorted(all_subs)

# ── DNS Validation (concurrent) ──────────────────────────────────────────────

def validate_subdomains(subdomains, workers=20):
    """Return set of subdomains that resolve A or AAAA records."""
    valid = set()

    def _check(sub):
        if query_a(sub) or query_aaaa(sub):
            return sub
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(_check, subdomains):
            if result:
                valid.add(result)
    return valid

# ── Module 1: Subdomain Takeover Scanner ─────────────────────────────────────

def scan_takeover(subdomain, timeout=5):
    """Check single subdomain for takeover vulnerability."""
    result = {"subdomain": subdomain, "cnames": [], "vulnerable": False,
              "service": None, "http_confirmed": False, "severity": "info",
              "message": "", "issues": []}
    cnames = query_cname(subdomain)
    if not cnames:
        return result
    result["cnames"] = cnames
    for target in cnames:
        # Check against known vulnerable services
        for pattern in TAKEOVER_FINGERPRINTS:
            if pattern in target.lower():
                result["service"] = pattern
                # Check if CNAME target resolves
                a = query_a(target)
                aaaa = query_aaaa(target)
                if not a and not aaaa:
                    result["vulnerable"] = True
                    result["severity"] = "critical"
                    result["message"] = f"Dangling CNAME to {target} (service: {pattern})"
                    result["issues"].append({"severity": "critical", "code": "TAKEOVER_DANGLING",
                        "message": f"CNAME -> {target} does not resolve. Known vulnerable service: {pattern}"})
                # HTTP confirmation probe
                if pattern in TAKEOVER_HTTP_FINGERPRINTS:
                    try:
                        r = requests.get(f"https://{subdomain}", timeout=timeout, verify=False,
                                        headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
                        body = r.text[:5000].lower()
                        for fingerprint in TAKEOVER_HTTP_FINGERPRINTS[pattern]:
                            if fingerprint.lower() in body:
                                result["http_confirmed"] = True
                                result["vulnerable"] = True
                                result["severity"] = "critical"
                                result["message"] = f"Takeover confirmed: {fingerprint}"
                                result["issues"].append({"severity": "critical", "code": "TAKEOVER_CONFIRMED",
                                    "message": f"HTTP response matches takeover fingerprint for {pattern}: '{fingerprint}'"})
                                break
                    except Exception:
                        pass
                break
    return result

def scan_takeover_batch(subdomains, workers=20):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_takeover, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    return results

# ── Module 2: SSL/TLS Certificate Auditor ────────────────────────────────────

def audit_ssl(subdomain, port=443, timeout=5):
    """Connect to subdomain:port and audit the TLS certificate."""
    result = {"subdomain": subdomain, "reachable": False, "cert": None, "issues": []}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((subdomain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=subdomain) as ssock:
                result["reachable"] = True
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                # Parse certificate
                cert_info = {}
                if cert_dict:
                    # Subject
                    subj = dict(x[0] for x in cert_dict.get("subject", ()))
                    cert_info["subject"] = subj.get("commonName", "")
                    # Issuer
                    iss = dict(x[0] for x in cert_dict.get("issuer", ()))
                    cert_info["issuer"] = iss.get("commonName", "")
                    cert_info["issuer_org"] = iss.get("organizationName", "")
                    # Dates
                    cert_info["not_before"] = cert_dict.get("notBefore", "")
                    cert_info["not_after"] = cert_dict.get("notAfter", "")
                    # Parse expiry
                    try:
                        expiry = parsedate_to_datetime(cert_info["not_after"].replace("GMT", "+0000"))
                        now = datetime.now(timezone.utc)
                        cert_info["days_until_expiry"] = (expiry - now).days
                    except Exception:
                        cert_info["days_until_expiry"] = None
                    # SANs
                    sans = []
                    for type_val in cert_dict.get("subjectAltName", ()):
                        if type_val[0] == "DNS":
                            sans.append(type_val[1])
                    cert_info["sans"] = sans
                    cert_info["san_count"] = len(sans)
                    # Self-signed check
                    cert_info["is_self_signed"] = (cert_info["subject"] == cert_info["issuer"])
                    # Wildcard
                    cert_info["is_wildcard"] = any(s.startswith("*.") for s in sans) or cert_info["subject"].startswith("*.")
                    # Serial
                    cert_info["serial"] = cert_dict.get("serialNumber", "")
                    # Version
                    cert_info["version"] = cert_dict.get("version", 0)

                    result["cert"] = cert_info

                    # Now generate issues
                    issues = result["issues"]
                    days = cert_info.get("days_until_expiry")
                    if days is not None:
                        if days < 0:
                            issues.append({"severity": "critical", "code": "CERT_EXPIRED",
                                "message": f"Certificate expired {abs(days)} days ago"})
                        elif days < 7:
                            issues.append({"severity": "high", "code": "CERT_EXPIRING_SOON",
                                "message": f"Certificate expires in {days} days"})
                        elif days < 30:
                            issues.append({"severity": "medium", "code": "CERT_EXPIRING",
                                "message": f"Certificate expires in {days} days"})
                    if cert_info["is_self_signed"]:
                        issues.append({"severity": "high", "code": "CERT_SELF_SIGNED",
                            "message": "Certificate is self-signed"})
                    # Hostname mismatch
                    hostname_match = False
                    for san in sans:
                        if san == subdomain:
                            hostname_match = True
                            break
                        if san.startswith("*."):
                            wildcard_base = san[2:]
                            if subdomain.endswith(wildcard_base) and subdomain.count(".") == san.count("."):
                                hostname_match = True
                                break
                    if not hostname_match and cert_info["subject"] != subdomain:
                        issues.append({"severity": "critical", "code": "CERT_HOSTNAME_MISMATCH",
                            "message": f"Certificate CN/SAN does not match {subdomain}"})
                    if not sans:
                        issues.append({"severity": "medium", "code": "CERT_NO_SAN",
                            "message": "Certificate has no Subject Alternative Names"})
                else:
                    result["issues"].append({"severity": "medium", "code": "CERT_UNPARSEABLE",
                        "message": "Could not parse certificate details"})
    except ssl.SSLError as e:
        result["issues"].append({"severity": "high", "code": "SSL_ERROR",
            "message": f"TLS error: {str(e)[:100]}"})
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass  # not reachable on 443, not an issue per se
    except Exception as e:
        result["issues"].append({"severity": "low", "code": "SSL_SCAN_ERROR",
            "message": f"Scan error: {str(e)[:100]}"})
    return result

def audit_ssl_batch(subdomains, workers=15):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(audit_ssl, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    return results

# ── Module 3: HTTP Security Header Scanner ───────────────────────────────────

def scan_headers(subdomain, timeout=8):
    """Fetch HTTP/HTTPS response and audit security headers."""
    result = {"subdomain": subdomain, "https_reachable": False, "http_reachable": False,
              "http_redirects_to_https": False, "headers": {}, "issues": []}

    headers_dict = {}
    # Try HTTPS first
    try:
        r = requests.get(f"https://{subdomain}", timeout=timeout, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        result["https_reachable"] = True
        headers_dict = {k.lower(): v for k, v in r.headers.items()}
        result["status_code"] = r.status_code
    except Exception:
        pass

    # Try HTTP
    try:
        r_http = requests.get(f"http://{subdomain}", timeout=timeout,
                             headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
        result["http_reachable"] = True
        if r_http.status_code in (301, 302, 307, 308):
            loc = r_http.headers.get("Location", "")
            if loc.startswith("https://"):
                result["http_redirects_to_https"] = True
    except Exception:
        pass

    if not headers_dict:
        return result

    result["headers"] = headers_dict
    issues = result["issues"]

    # HSTS
    hsts = headers_dict.get("strict-transport-security", "")
    if not hsts:
        issues.append({"severity": "high", "code": "HSTS_MISSING",
            "message": "No Strict-Transport-Security header"})
    else:
        if "includesubdomains" not in hsts.lower():
            issues.append({"severity": "low", "code": "HSTS_NO_SUBDOMAINS",
                "message": "HSTS missing includeSubDomains"})
        try:
            max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
            if max_age < 31536000:
                issues.append({"severity": "low", "code": "HSTS_SHORT",
                    "message": f"HSTS max-age={max_age} (< 1 year)"})
        except Exception:
            pass

    # CSP
    csp = headers_dict.get("content-security-policy", "")
    if not csp:
        issues.append({"severity": "medium", "code": "CSP_MISSING",
            "message": "No Content-Security-Policy header"})
    else:
        if "'unsafe-inline'" in csp:
            issues.append({"severity": "medium", "code": "CSP_UNSAFE_INLINE",
                "message": "CSP allows 'unsafe-inline'"})
        if "'unsafe-eval'" in csp:
            issues.append({"severity": "medium", "code": "CSP_UNSAFE_EVAL",
                "message": "CSP allows 'unsafe-eval'"})
        if "script-src *" in csp or "default-src *" in csp:
            issues.append({"severity": "high", "code": "CSP_WILDCARD",
                "message": "CSP uses wildcard source"})

    # X-Frame-Options
    if "x-frame-options" not in headers_dict:
        issues.append({"severity": "medium", "code": "XFRAME_MISSING",
            "message": "No X-Frame-Options header"})

    # X-Content-Type-Options
    xcto = headers_dict.get("x-content-type-options", "")
    if xcto.lower() != "nosniff":
        issues.append({"severity": "medium", "code": "XCTO_MISSING",
            "message": "No X-Content-Type-Options: nosniff"})

    # CORS
    acao = headers_dict.get("access-control-allow-origin", "")
    if acao == "*":
        acac = headers_dict.get("access-control-allow-credentials", "")
        if acac.lower() == "true":
            issues.append({"severity": "critical", "code": "CORS_CRED_WILDCARD",
                "message": "CORS: wildcard origin with credentials allowed"})
        else:
            issues.append({"severity": "high", "code": "CORS_WILDCARD",
                "message": "CORS: Access-Control-Allow-Origin: *"})

    # Referrer-Policy
    if "referrer-policy" not in headers_dict:
        issues.append({"severity": "low", "code": "REFERRER_MISSING",
            "message": "No Referrer-Policy header"})

    # Permissions-Policy
    if "permissions-policy" not in headers_dict:
        issues.append({"severity": "low", "code": "PERMISSIONS_MISSING",
            "message": "No Permissions-Policy header"})

    # Info leaks
    server = headers_dict.get("server", "")
    if server and "/" in server:
        issues.append({"severity": "low", "code": "SERVER_LEAK",
            "message": f"Server header reveals: {server}"})
    powered = headers_dict.get("x-powered-by", "")
    if powered:
        issues.append({"severity": "low", "code": "POWERED_BY_LEAK",
            "message": f"X-Powered-By: {powered}"})

    # HTTP without redirect
    if result["http_reachable"] and not result["http_redirects_to_https"]:
        issues.append({"severity": "high", "code": "HTTP_NO_REDIRECT",
            "message": "HTTP accessible without redirect to HTTPS"})

    # Deprecated X-XSS-Protection
    if "x-xss-protection" in headers_dict:
        issues.append({"severity": "low", "code": "XSS_PROTECTION_DEPRECATED",
            "message": "X-XSS-Protection is deprecated and can introduce issues"})

    return result

def scan_headers_batch(subdomains, workers=15):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_headers, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    return results

# ── Module 4: Exposed Service Discovery ──────────────────────────────────────

def scan_ports(subdomain, ports=None, timeout=2):
    """TCP connect scan + banner grab."""
    ports = ports or list(COMMON_PORTS.keys())
    result = {"subdomain": subdomain, "ip": None, "open_ports": [], "issues": []}

    ips = query_a(subdomain)
    if not ips:
        return result
    result["ip"] = ips[0]

    for port in ports:
        try:
            sock = socket.create_connection((result["ip"], port), timeout=timeout)
            service = COMMON_PORTS.get(port, f"port-{port}")
            banner = None
            try:
                sock.settimeout(2)
                # Send a probe for HTTP ports
                if port in (80, 8080, 8443, 443, 4443):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + subdomain.encode() + b"\r\n\r\n")
                banner_bytes = sock.recv(1024)
                banner = banner_bytes.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass
            finally:
                sock.close()

            # Determine severity
            sev = "info"
            for severity, port_set in EXPOSED_SERVICE_SEVERITY.items():
                if port in port_set:
                    sev = severity
                    break

            entry = {"port": port, "service": service, "banner": banner, "severity": sev}
            result["open_ports"].append(entry)

            if sev in ("critical", "high"):
                result["issues"].append({"severity": sev, "code": f"EXPOSED_{service.upper().replace('/', '_').replace('-', '_')}",
                    "message": f"Port {port} ({service}) is open" + (f": {banner[:80]}" if banner else "")})
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    return result

def scan_ports_batch(subdomains, ports=None, workers=10):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_ports, sub, ports): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    return results

# ── Module 5: Cloud Asset Inventory ──────────────────────────────────────────

def _load_cloud_ranges():
    """Fetch cloud provider IP ranges. Returns dict of provider -> list of (ip_network, service, region)."""
    ranges = {}
    # AWS
    try:
        r = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=10)
        if r.ok:
            aws_nets = []
            for prefix in r.json().get("prefixes", []):
                try:
                    aws_nets.append((ipaddress.ip_network(prefix["ip_prefix"]), prefix.get("service", ""), prefix.get("region", "")))
                except Exception:
                    pass
            ranges["AWS"] = aws_nets
    except Exception:
        ranges["AWS"] = []

    # Cloudflare
    try:
        r = requests.get("https://www.cloudflare.com/ips-v4", timeout=10)
        if r.ok:
            ranges["Cloudflare"] = [(ipaddress.ip_network(line.strip()), "CDN", "") for line in r.text.strip().splitlines() if line.strip()]
    except Exception:
        ranges["Cloudflare"] = []

    # For GCP/Azure — use ASN fallback (their range lists are very large)
    return ranges

_cloud_ranges_cache = None

def identify_cloud_provider(ip_str):
    """Map IP to cloud provider."""
    global _cloud_ranges_cache
    if _cloud_ranges_cache is None:
        _cloud_ranges_cache = _load_cloud_ranges()

    result = {"provider": None, "region": None, "service": None, "method": None}
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return result

    for provider, nets in _cloud_ranges_cache.items():
        for net_info in nets:
            net, svc, region = net_info
            if ip in net:
                result["provider"] = provider
                result["service"] = svc
                result["region"] = region
                result["method"] = "ip_range"
                return result

    return result

def detect_cdn(headers, cnames):
    """Detect CDN from headers and CNAME chain."""
    if not headers:
        return None
    h = {k.lower(): v.lower() for k, v in headers.items()}
    if "cf-ray" in h or h.get("server", "") == "cloudflare":
        return "Cloudflare"
    if "x-amz-cf-id" in h or "x-amz-cf-pop" in h:
        return "CloudFront"
    if "x-fastly-request-id" in h:
        return "Fastly"
    if "x-akamai-transformed" in h:
        return "Akamai"
    if "x-vercel-id" in h:
        return "Vercel"
    if "x-nf-request-id" in h:
        return "Netlify"
    for cn in (cnames or []):
        cn = cn.lower()
        if "cloudfront.net" in cn:
            return "CloudFront"
        if "akamaiedge.net" in cn or "akamai.net" in cn:
            return "Akamai"
        if "fastly.net" in cn:
            return "Fastly"
        if "edgecastcdn" in cn:
            return "Edgecast"
    return None

def inventory_cloud(subdomain, timeout=5):
    """Full cloud asset inventory for a subdomain."""
    result = {"subdomain": subdomain, "ips": [], "cloud_provider": None,
              "cloud_region": None, "cloud_service": None, "cdn": None, "issues": []}
    ips = query_a(subdomain)
    result["ips"] = ips
    cnames = query_cname(subdomain)

    if ips:
        cloud = identify_cloud_provider(ips[0])
        result["cloud_provider"] = cloud["provider"]
        result["cloud_region"] = cloud["region"]
        result["cloud_service"] = cloud["service"]

    # Detect CDN via headers
    try:
        r = requests.get(f"https://{subdomain}", timeout=timeout, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        result["cdn"] = detect_cdn(dict(r.headers), cnames)
    except Exception:
        result["cdn"] = detect_cdn({}, cnames)

    return result

def inventory_cloud_batch(subdomains, workers=15):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(inventory_cloud, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    return results

# ── Module 6: Web Technology Fingerprinter ───────────────────────────────────

def fingerprint_tech(subdomain, timeout=8):
    """Fingerprint web technologies."""
    result = {"subdomain": subdomain, "technologies": [], "waf": None, "server": None, "issues": []}

    try:
        r = requests.get(f"https://{subdomain}", timeout=timeout, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        body = r.text[:50000]
        cookies = {c.name: c.value for c in r.cookies}
    except Exception:
        return result

    # Server
    server = headers.get("server", "")
    if server:
        result["server"] = server
        result["technologies"].append({"name": server.split("/")[0], "category": "Server",
            "version": server.split("/")[1] if "/" in server else None, "confidence": "high"})

    # X-Powered-By
    powered = headers.get("x-powered-by", "")
    if powered:
        result["technologies"].append({"name": powered.split("/")[0], "category": "Framework",
            "version": powered.split("/")[1] if "/" in powered else None, "confidence": "high"})

    # WAF detection
    for waf_name, sigs in WAF_SIGNATURES.items():
        detected = False
        for hdr, val in sigs.get("headers", {}).items():
            h_val = headers.get(hdr.lower(), "")
            if val == "" and h_val:
                detected = True
                break
            elif val and val.lower() in h_val.lower():
                detected = True
                break
        if not detected:
            for cookie_pattern in sigs.get("cookies", []):
                for cname in cookies:
                    if cookie_pattern.lower() in cname.lower():
                        detected = True
                        break
        if detected:
            result["waf"] = waf_name
            result["technologies"].append({"name": waf_name, "category": "WAF", "version": None, "confidence": "high"})
            break

    # CMS detection from body
    body_lower = body.lower()
    # WordPress
    if "/wp-content/" in body or "/wp-includes/" in body:
        result["technologies"].append({"name": "WordPress", "category": "CMS", "version": None, "confidence": "high"})
    # Meta generator
    gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', body, re.I)
    if gen_match:
        gen = gen_match.group(1)
        result["technologies"].append({"name": gen.split()[0], "category": "CMS",
            "version": gen.split()[1] if len(gen.split()) > 1 else None, "confidence": "high"})

    # JS frameworks from body
    if "react" in body_lower and ("reactdom" in body_lower or "react-dom" in body_lower or "_react" in body_lower):
        result["technologies"].append({"name": "React", "category": "JS Framework", "version": None, "confidence": "medium"})
    if "angular" in body_lower and ("ng-version" in body_lower or "ng-app" in body_lower):
        result["technologies"].append({"name": "Angular", "category": "JS Framework", "version": None, "confidence": "medium"})
    if "vue" in body_lower and ("__vue__" in body_lower or "vue.js" in body_lower or "vuejs" in body_lower):
        result["technologies"].append({"name": "Vue.js", "category": "JS Framework", "version": None, "confidence": "medium"})
    if "jquery" in body_lower:
        result["technologies"].append({"name": "jQuery", "category": "JS Library", "version": None, "confidence": "medium"})

    # Cookie-based detection
    if "PHPSESSID" in cookies or "phpsessid" in str(cookies).lower():
        result["technologies"].append({"name": "PHP", "category": "Language", "version": None, "confidence": "high"})
    if "JSESSIONID" in cookies:
        result["technologies"].append({"name": "Java", "category": "Language", "version": None, "confidence": "high"})
    if "ASP.NET_SessionId" in cookies:
        result["technologies"].append({"name": "ASP.NET", "category": "Framework", "version": None, "confidence": "high"})

    return result

def fingerprint_tech_batch(subdomains, workers=10):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fingerprint_tech, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    return results

# ── Module 7: DNS Zone Health Auditor ────────────────────────────────────────

def audit_dns_health(subdomain, parent_domain):
    """Comprehensive DNS health audit."""
    result = {"subdomain": subdomain, "caa": [], "dnssec": {"has_ds": False, "has_dnskey": False},
              "soa": None, "ns_records": [], "ns_consistent": True, "axfr_vulnerable": False,
              "orphaned": False, "issues": []}

    # CAA
    caa = query_caa(subdomain) or query_caa(parent_domain)
    result["caa"] = caa
    if not caa:
        result["issues"].append({"severity": "medium", "code": "CAA_MISSING",
            "message": "No CAA records (any CA can issue certificates)"})

    # DNSSEC
    ds = []
    try:
        answers = _resolver(2).resolve(parent_domain, "DS")
        ds = [str(r) for r in answers]
    except Exception:
        pass
    result["dnssec"]["has_ds"] = len(ds) > 0
    if not ds:
        result["issues"].append({"severity": "medium", "code": "DNSSEC_MISSING",
            "message": "No DNSSEC DS records at parent zone"})

    # SOA
    soa = query_soa(subdomain) or query_soa(parent_domain)
    result["soa"] = soa

    # NS
    ns_records = query_ns(parent_domain)
    result["ns_records"] = ns_records
    if len(ns_records) < 2:
        result["issues"].append({"severity": "medium", "code": "NS_SINGLE",
            "message": f"Only {len(ns_records)} nameserver(s) (should have >=2)"})

    # Check NS resolution
    for ns in ns_records:
        a = query_a(ns)
        if not a:
            result["ns_consistent"] = False
            result["issues"].append({"severity": "high", "code": "NS_UNRESOLVABLE",
                "message": f"Nameserver {ns} does not resolve"})

    # AXFR test
    for ns in ns_records[:2]:  # test first 2 NS only
        records = try_axfr(parent_domain, ns)
        if records:
            result["axfr_vulnerable"] = True
            result["issues"].append({"severity": "critical", "code": "AXFR_OPEN",
                "message": f"Zone transfer (AXFR) succeeded against {ns} — exposes entire zone"})
            break

    # Orphaned check — A record points to unresponsive IP
    ips = query_a(subdomain)
    if ips:
        try:
            sock = socket.create_connection((ips[0], 80), timeout=3)
            sock.close()
        except Exception:
            try:
                sock = socket.create_connection((ips[0], 443), timeout=3)
                sock.close()
            except Exception:
                result["orphaned"] = True
                result["issues"].append({"severity": "medium", "code": "ORPHANED_RECORD",
                    "message": f"A record -> {ips[0]} does not respond on 80/443"})

    return result

def audit_dns_batch(subdomains, parent_domain, workers=15):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(audit_dns_health, sub, parent_domain): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    return results

# ── Composite Risk Scoring ───────────────────────────────────────────────────

MODULE_WEIGHTS = {
    "takeover": 1.5, "ssl": 1.2, "headers": 0.8,
    "ports": 1.3, "cloud": 0.6, "tech": 0.5, "dns": 1.0,
}

def compute_subdomain_risk(subdomain, module_results):
    """Compute composite risk for one subdomain."""
    all_issues = []
    module_scores = {}
    for mod_name, mod_data in module_results.items():
        issues = mod_data.get("issues", [])
        raw = sum(SEVERITY_WEIGHTS.get(i.get("severity", "info"), 0) for i in issues)
        weight = MODULE_WEIGHTS.get(mod_name, 1.0)
        module_scores[mod_name] = raw * weight
        for i in issues:
            i["module"] = mod_name
        all_issues.extend(issues)

    raw_total = sum(module_scores.values())
    # Normalize to 0-100 (inverse: higher raw = worse security = lower score)
    # Sigmoid-like decay: gentle for low issues, steep drop for criticals
    # At raw=5 -> ~85, raw=15 -> ~65, raw=30 -> ~45, raw=60 -> ~25, raw=100 -> ~10
    normalized = int(100 * math.exp(-raw_total / 30))
    normalized = max(0, min(100, normalized))

    if normalized >= 90:
        grade = "A"
    elif normalized >= 75:
        grade = "B"
    elif normalized >= 60:
        grade = "C"
    elif normalized >= 40:
        grade = "D"
    else:
        grade = "F"

    if normalized >= 90:
        risk_level = "Info"
    elif normalized >= 75:
        risk_level = "Low"
    elif normalized >= 60:
        risk_level = "Medium"
    elif normalized >= 40:
        risk_level = "High"
    else:
        risk_level = "Critical"

    all_issues.sort(key=lambda i: -SEVERITY_WEIGHTS.get(i.get("severity", "info"), 0))

    return {
        "subdomain": subdomain,
        "raw_score": raw_total,
        "normalized_score": normalized,
        "letter_grade": grade,
        "risk_level": risk_level,
        "module_scores": module_scores,
        "top_findings": all_issues[:5],
        "all_issues": all_issues,
    }

def compute_overall_posture(risks):
    """Compute overall posture from all subdomain risks."""
    if not risks:
        return {"score": 100, "letter_grade": "A", "risk_distribution": {}, "top_issues": []}
    avg = sum(r["normalized_score"] for r in risks) / len(risks)
    score = int(avg)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    all_issues = []
    for r in risks:
        for i in r["all_issues"]:
            sev = i.get("severity", "info")
            dist[sev] = dist.get(sev, 0) + 1
            all_issues.append(i)
    all_issues.sort(key=lambda i: -SEVERITY_WEIGHTS.get(i.get("severity", "info"), 0))

    return {"score": score, "letter_grade": grade, "risk_distribution": dist, "top_issues": all_issues[:10]}

# ── Full Scan Orchestrator ───────────────────────────────────────────────────

# ── Starburst Spinner ────────────────────────────────────────────────────────

class _Starburst:
    """Animated starburst spinner that runs in a background thread.

    Displays an evolving starburst pattern to the right of the current line
    while a long-running operation executes.
    """
    # Spiral cross-section animation — rotating arms with depth illusion
    # Simulates looking down the axis of a spinning spiral/helix
    FRAMES = [
        "  ─       ",
        "   ╲      ",
        "    │     ",
        "      ╱   ",
        "     ─    ",
        "      ╲   ",
        "    │     ",
        "   ╱      ",
        "  ─       ",
        "   ╲      ",
        "    │     ",
        "      ╱   ",
        "     ─    ",
        "      ╲   ",
        "    │     ",
        "   ╱      ",
    ]

    @staticmethod
    def _generate_frames():
        """Generate spiral cross-section frames procedurally.

        Models two spiral arms rotating around a center point, viewed
        head-on. The arms have varying thickness to convey depth — thicker
        when the arm is 'closer' to the viewer.
        """
        import math
        width = 11
        center = width // 2
        n_frames = 32
        frames = []
        # Characters by depth: nearest to farthest
        chars_near = "█▓▒░"
        chars_arm = "◉◎●○∙"

        for f in range(n_frames):
            angle = (2 * math.pi * f) / n_frames
            buf = [" "] * width

            # Two spiral arms, 180° apart
            for arm_offset in [0, math.pi]:
                a = angle + arm_offset
                # Arm tip position oscillates across the width
                x = center + math.sin(a) * (center - 1)
                ix = int(round(x))
                ix = max(0, min(width - 1, ix))

                # Depth: cos(a) determines how "close" the arm is
                # cos=1 means closest (brightest), cos=-1 means farthest (dimmest)
                depth = (math.cos(a) + 1) / 2  # 0..1

                if depth > 0.6:
                    ch = "●"
                elif depth > 0.3:
                    ch = "∙"
                else:
                    ch = "·"

                buf[ix] = ch

                # Add a trail/wake character adjacent
                trail_x = ix - (1 if math.sin(a) > 0 else -1)
                if 0 <= trail_x < width and buf[trail_x] == " ":
                    if depth > 0.5:
                        buf[trail_x] = "∙"
                    elif depth > 0.2:
                        buf[trail_x] = "·"

            # Center hub
            hub_chars = "◇◈◆◈"
            buf[center] = hub_chars[f % len(hub_chars)]

            frames.append("".join(buf))
        return frames

    def __init__(self, message=""):
        self._message = message
        self._stop = threading.Event()
        self._thread = None
        self._frames = self._generate_frames()

    def start(self, message=None):
        if message:
            self._message = message
        self._stop.clear()
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def _animate(self):
        idx = 0
        n = len(self._frames)
        while not self._stop.is_set():
            frame = self._frames[idx % n]
            sys.stdout.write(f"\033[2K\r  {self._message}  {frame}")
            sys.stdout.flush()
            idx += 1
            self._stop.wait(0.08)  # faster rotation for spiral effect
        sys.stdout.write(f"\033[2K\r")
        sys.stdout.flush()

    def stop(self, final_message=None):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        if final_message:
            print(f"  {final_message}")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def _run_with_starburst(message, func, *args, **kwargs):
    """Run func(*args, **kwargs) while displaying a starburst animation.
    Returns the function's result."""
    spinner = _Starburst(message)
    spinner.start()
    try:
        result = func(*args, **kwargs)
    finally:
        spinner.stop()
    return result


def full_scan(domain, subdomains, modules=None, debug=False, workers=15):
    """Run all (or selected) modules across subdomains."""
    all_modules = ["takeover", "ssl", "headers", "ports", "cloud", "tech", "dns"]
    modules = modules or all_modules

    print(f"[*] ScopeScan: {len(subdomains)} subdomains, modules: {', '.join(modules)}")

    module_results = {}

    if "takeover" in modules:
        module_results["takeover"] = _run_with_starburst(
            "Subdomain Takeover Scanner", scan_takeover_batch, subdomains, workers)
        vuln = sum(1 for r in module_results["takeover"] if r["vulnerable"])
        print(f"  [✓] Takeover:  {vuln} vulnerable subdomains")

    if "ssl" in modules:
        module_results["ssl"] = _run_with_starburst(
            "SSL/TLS Certificate Auditor", audit_ssl_batch, subdomains, min(workers, 15))
        issues_count = sum(len(r["issues"]) for r in module_results["ssl"])
        print(f"  [✓] SSL/TLS:   {issues_count} issues found")

    if "headers" in modules:
        module_results["headers"] = _run_with_starburst(
            "HTTP Security Headers", scan_headers_batch, subdomains, min(workers, 15))
        issues_count = sum(len(r["issues"]) for r in module_results["headers"])
        print(f"  [✓] Headers:   {issues_count} issues found")

    if "ports" in modules:
        module_results["ports"] = _run_with_starburst(
            "Exposed Service Discovery", scan_ports_batch, subdomains, None, min(workers, 10))
        open_count = sum(len(r["open_ports"]) for r in module_results["ports"])
        print(f"  [✓] Ports:     {open_count} open ports")

    if "cloud" in modules:
        module_results["cloud"] = _run_with_starburst(
            "Cloud Asset Inventory", inventory_cloud_batch, subdomains, workers)
        providers = set(r["cloud_provider"] for r in module_results["cloud"] if r["cloud_provider"])
        print(f"  [✓] Cloud:     {', '.join(providers) or 'none identified'}")

    if "tech" in modules:
        module_results["tech"] = _run_with_starburst(
            "Web Technology Fingerprinter", fingerprint_tech_batch, subdomains, min(workers, 10))
        tech_count = sum(len(r["technologies"]) for r in module_results["tech"])
        print(f"  [✓] Tech:      {tech_count} technologies detected")

    if "dns" in modules:
        module_results["dns"] = _run_with_starburst(
            "DNS Zone Health Auditor", audit_dns_batch, subdomains, domain, min(workers, 15))
        issues_count = sum(len(r["issues"]) for r in module_results["dns"])
        print(f"  [✓] DNS:       {issues_count} issues found")

    # Merge per-subdomain
    per_sub = {}
    for mod_name, results in module_results.items():
        for r in results:
            sub = r["subdomain"]
            if sub not in per_sub:
                per_sub[sub] = {}
            per_sub[sub][mod_name] = r

    # Compute risks
    risks = []
    for sub, mod_data in per_sub.items():
        risk = compute_subdomain_risk(sub, mod_data)
        risk["modules"] = mod_data
        risks.append(risk)
    risks.sort(key=lambda r: r["normalized_score"])

    posture = compute_overall_posture(risks)

    # Build summary
    summary = {
        "total_subdomains": len(subdomains),
        "modules_run": modules,
        "overall_posture": posture,
    }
    # Count issues per severity
    for sev in ["critical", "high", "medium", "low", "info"]:
        summary[sev] = posture["risk_distribution"].get(sev, 0)

    return {
        "domain": domain,
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "overall_posture": posture,
        "per_subdomain": risks,
        "module_results": module_results,
    }

# ── Export: CSV ──────────────────────────────────────────────────────────────

def export_csv(scan, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Subdomain", "Score", "Grade", "Risk", "Takeover", "SSL Issues",
                     "Header Issues", "Open Ports", "Cloud Provider", "Technologies", "DNS Issues"])
        for r in scan["per_subdomain"]:
            mods = r.get("modules", {})
            takeover = "YES" if mods.get("takeover", {}).get("vulnerable") else "no"
            ssl_issues = len(mods.get("ssl", {}).get("issues", []))
            hdr_issues = len(mods.get("headers", {}).get("issues", []))
            ports = ",".join(str(p["port"]) for p in mods.get("ports", {}).get("open_ports", []))
            cloud = mods.get("cloud", {}).get("cloud_provider", "") or ""
            techs = ",".join(t["name"] for t in mods.get("tech", {}).get("technologies", []))
            dns_issues = len(mods.get("dns", {}).get("issues", []))
            w.writerow([r["subdomain"], r["normalized_score"], r["letter_grade"],
                        r["risk_level"], takeover, ssl_issues, hdr_issues, ports, cloud, techs, dns_issues])
    print(f"[+] CSV: {path}")

# ── Export: JSON ─────────────────────────────────────────────────────────────

def export_json(scan, path):
    with open(path, "w") as f:
        json.dump(scan, f, indent=2, default=str)
    print(f"[+] JSON: {path}")

# ── Export: HTML Report ──────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#e74c3c", "high": "#e67e22",
    "medium": "#f1c40f", "low": "#3498db", "info": "#95a5a6",
}
GRADE_COLORS = {"A": "#2ea043", "B": "#3fb950", "C": "#d29922", "D": "#e67e22", "F": "#e74c3c"}

def export_html(scan, path):
    domain = html_escape(scan["domain"])
    timestamp = html_escape(scan.get("scan_timestamp", ""))
    posture = scan["overall_posture"]
    summary = scan["summary"]
    per_sub = scan["per_subdomain"]
    module_results = scan.get("module_results", {})

    grade = posture["letter_grade"]
    grade_color = GRADE_COLORS.get(grade, "#95a5a6")
    score = posture["score"]
    dist = posture.get("risk_distribution", {})

    # Stat counts
    total_subs = summary.get("total_subdomains", 0)
    crit_count = dist.get("critical", 0)
    high_count = dist.get("high", 0)
    med_count = dist.get("medium", 0)
    low_count = dist.get("low", 0)
    takeover_count = sum(1 for r in module_results.get("takeover", []) if r.get("vulnerable"))
    expired_certs = sum(1 for r in module_results.get("ssl", [])
                        for i in r.get("issues", []) if i.get("code") == "CERT_EXPIRED")
    missing_hsts = sum(1 for r in module_results.get("headers", [])
                       for i in r.get("issues", []) if i.get("code") == "HSTS_MISSING")
    exposed_services = sum(len(r.get("open_ports", [])) for r in module_results.get("ports", [])
                           if any(p.get("severity") in ("critical", "high") for p in r.get("open_ports", [])))

    # --- Build takeover table ---
    takeover_rows = ""
    for r in module_results.get("takeover", []):
        if r.get("vulnerable"):
            cnames_str = html_escape(", ".join(r.get("cnames", [])))
            svc = html_escape(r.get("service", "") or "")
            confirmed = "Yes" if r.get("http_confirmed") else "No"
            msg = html_escape(r.get("message", ""))
            takeover_rows += f'<tr><td>{html_escape(r["subdomain"])}</td><td>{cnames_str}</td><td>{svc}</td><td>{confirmed}</td><td>{msg}</td></tr>\n'

    # --- Build SSL table ---
    ssl_rows = ""
    for r in module_results.get("ssl", []):
        if r.get("reachable") and r.get("cert"):
            cert = r["cert"]
            days = cert.get("days_until_expiry")
            if days is not None:
                if days < 0:
                    days_str = f'<span style="color:#e74c3c;font-weight:bold">{days}d (EXPIRED)</span>'
                elif days < 7:
                    days_str = f'<span style="color:#e74c3c">{days}d</span>'
                elif days < 30:
                    days_str = f'<span style="color:#f1c40f">{days}d</span>'
                else:
                    days_str = f'<span style="color:#2ea043">{days}d</span>'
            else:
                days_str = "N/A"
            self_signed = '<span style="color:#e74c3c">Yes</span>' if cert.get("is_self_signed") else "No"
            issuer = html_escape(cert.get("issuer", ""))
            subject = html_escape(cert.get("subject", ""))
            ssl_rows += f'<tr><td>{html_escape(r["subdomain"])}</td><td>{subject}</td><td>{issuer}</td><td>{days_str}</td><td>{self_signed}</td><td>{cert.get("san_count", 0)}</td></tr>\n'

    # --- Build headers table ---
    hdr_rows = ""
    hdr_names = ["strict-transport-security", "content-security-policy", "x-content-type-options",
                 "x-frame-options", "referrer-policy", "permissions-policy"]
    hdr_short = ["HSTS", "CSP", "XCTO", "XFO", "Ref-Pol", "Perm-Pol"]
    for r in module_results.get("headers", []):
        if r.get("https_reachable"):
            hdrs = r.get("headers", {})
            cells = ""
            for h in hdr_names:
                if h in hdrs:
                    cells += '<td style="color:#2ea043;text-align:center">&#10003;</td>'
                else:
                    cells += '<td style="color:#e74c3c;text-align:center">&#10007;</td>'
            issue_count = len(r.get("issues", []))
            hdr_rows += f'<tr><td>{html_escape(r["subdomain"])}</td>{cells}<td>{issue_count}</td></tr>\n'

    # --- Build ports table ---
    port_rows = ""
    for r in module_results.get("ports", []):
        if r.get("open_ports"):
            for p in r["open_ports"]:
                sev = p.get("severity", "info")
                color = SEVERITY_COLORS.get(sev, "#95a5a6")
                banner_str = html_escape((p.get("banner") or "")[:80])
                port_rows += (f'<tr><td>{html_escape(r["subdomain"])}</td><td>{r.get("ip","")}</td>'
                              f'<td>{p["port"]}</td><td>{html_escape(p["service"])}</td>'
                              f'<td style="color:{color};font-weight:bold">{sev}</td>'
                              f'<td class="mono">{banner_str}</td></tr>\n')

    # --- Build cloud table ---
    cloud_rows = ""
    for r in module_results.get("cloud", []):
        if r.get("cloud_provider") or r.get("cdn"):
            cloud_rows += (f'<tr><td>{html_escape(r["subdomain"])}</td>'
                           f'<td>{html_escape(r.get("cloud_provider","") or "")}</td>'
                           f'<td>{html_escape(r.get("cloud_region","") or "")}</td>'
                           f'<td>{html_escape(r.get("cloud_service","") or "")}</td>'
                           f'<td>{html_escape(r.get("cdn","") or "")}</td></tr>\n')

    # --- Build tech table ---
    tech_rows = ""
    for r in module_results.get("tech", []):
        if r.get("technologies"):
            for t in r["technologies"]:
                tech_rows += (f'<tr><td>{html_escape(r["subdomain"])}</td>'
                              f'<td>{html_escape(t["name"])}</td>'
                              f'<td>{html_escape(t.get("category",""))}</td>'
                              f'<td>{html_escape(t.get("version","") or "")}</td>'
                              f'<td>{html_escape(t.get("confidence",""))}</td></tr>\n')

    # --- Build DNS table ---
    dns_rows = ""
    for r in module_results.get("dns", []):
        caa_str = "Yes" if r.get("caa") else '<span style="color:#e74c3c">No</span>'
        dnssec_str = "Yes" if r.get("dnssec", {}).get("has_ds") else '<span style="color:#e74c3c">No</span>'
        axfr_str = '<span style="color:#e74c3c;font-weight:bold">VULNERABLE</span>' if r.get("axfr_vulnerable") else "Safe"
        orphaned_str = '<span style="color:#f1c40f">Yes</span>' if r.get("orphaned") else "No"
        issue_count = len(r.get("issues", []))
        dns_rows += (f'<tr><td>{html_escape(r["subdomain"])}</td><td>{caa_str}</td>'
                     f'<td>{dnssec_str}</td><td>{axfr_str}</td><td>{orphaned_str}</td>'
                     f'<td>{issue_count}</td></tr>\n')

    # --- Build per-subdomain detail sections ---
    detail_sections = ""
    for r in per_sub:
        sub = html_escape(r["subdomain"])
        g = r["letter_grade"]
        gc = GRADE_COLORS.get(g, "#95a5a6")
        rl = r["risk_level"]
        ns = r["normalized_score"]
        issues_html = ""
        for i in r.get("all_issues", []):
            ic = SEVERITY_COLORS.get(i.get("severity", "info"), "#95a5a6")
            mod = html_escape(i.get("module", ""))
            code = html_escape(i.get("code", ""))
            msg = html_escape(i.get("message", ""))
            issues_html += f'<div style="margin:2px 0;"><span style="color:{ic};font-weight:bold">[{i.get("severity","info").upper()}]</span> <code>{mod}/{code}</code> {msg}</div>\n'
        if not issues_html:
            issues_html = '<div style="color:#2ea043">No issues found</div>'
        detail_sections += f"""<details class="sub-detail" data-risk="{rl.lower()}">
<summary><span style="color:{gc};font-weight:bold;font-size:1.2em">{g}</span> &nbsp;
<strong>{sub}</strong> &mdash; Score: {ns}/100, Risk: {rl}</summary>
<div style="padding:8px 16px">{issues_html}</div>
</details>\n"""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>ScopeScan Security Report &mdash; {domain}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0d1117; color: #c9d1d9; margin: 0; padding: 2em; line-height: 1.5; }}
  h1, h2, h3 {{ color: #58a6ff; margin-top: 1.5em; }}
  h1 {{ text-align: center; font-size: 2em; margin-bottom: 0.2em; }}
  .timestamp {{ text-align: center; color: #8b949e; font-size: 0.9em; margin-bottom: 2em; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2em; }}
  th, td {{ border: 1px solid #30363d; padding: 6px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #161b22; color: #58a6ff; position: sticky; top: 0; cursor: pointer; user-select: none; }}
  th:hover {{ background: #1c2129; }}
  tr:nth-child(even) {{ background: #161b22; }}
  .mono {{ font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 12px; word-break: break-all; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                   gap: 12px; margin: 1em 0 2em; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 16px; text-align: center; }}
  .stat .num {{ font-size: 2em; font-weight: bold; }}
  .stat .label {{ font-size: 0.85em; color: #8b949e; }}
  .section {{ background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
              padding: 16px; margin-bottom: 1.5em; }}
  .grade-circle {{ width: 120px; height: 120px; border-radius: 50%; display: flex;
                   align-items: center; justify-content: center; margin: 0 auto 0.5em;
                   font-size: 3em; font-weight: bold; color: #fff; }}
  .posture-card {{ text-align: center; margin: 2em 0; }}
  .posture-card .score-text {{ font-size: 1.2em; color: #8b949e; }}
  a {{ color: #58a6ff; }}
  details.sub-detail {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px;
                        margin-bottom: 6px; padding: 4px 12px; }}
  details.sub-detail summary {{ cursor: pointer; padding: 6px 0; }}
  details.sub-detail summary:hover {{ color: #58a6ff; }}
  .controls {{ margin: 1em 0; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
  .controls input {{ background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
                     border-radius: 4px; padding: 6px 12px; font-size: 14px; width: 300px; }}
  .controls button {{ background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
                      border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 13px; }}
  .controls button:hover {{ background: #1c2129; }}
  .controls button.active {{ background: #58a6ff; color: #0d1117; border-color: #58a6ff; }}
</style></head><body>

<h1>ScopeScan Security Report &mdash; {domain}</h1>
<div class="timestamp">Generated: {timestamp}</div>

<div class="posture-card">
  <div class="grade-circle" style="background:{grade_color}">{grade}</div>
  <div class="score-text">Overall Security Score: <strong>{score}/100</strong></div>
</div>

<div class="summary-grid">
  <div class="stat"><div class="num">{total_subs}</div><div class="label">Total Subdomains</div></div>
  <div class="stat"><div class="num" style="color:#e74c3c">{crit_count}</div><div class="label">Critical</div></div>
  <div class="stat"><div class="num" style="color:#e67e22">{high_count}</div><div class="label">High</div></div>
  <div class="stat"><div class="num" style="color:#f1c40f">{med_count}</div><div class="label">Medium</div></div>
  <div class="stat"><div class="num" style="color:#3498db">{low_count}</div><div class="label">Low</div></div>
  <div class="stat"><div class="num" style="color:#e74c3c">{takeover_count}</div><div class="label">Takeover Vuln</div></div>
  <div class="stat"><div class="num" style="color:#e74c3c">{expired_certs}</div><div class="label">Expired Certs</div></div>
  <div class="stat"><div class="num" style="color:#e67e22">{missing_hsts}</div><div class="label">Missing HSTS</div></div>
  <div class="stat"><div class="num" style="color:#e67e22">{exposed_services}</div><div class="label">Exposed Services</div></div>
</div>

{'<div class="section"><h2>Subdomain Takeover</h2>' + '<table><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>HTTP Confirmed</th><th>Details</th></tr>' + takeover_rows + '</table></div>' if takeover_rows else '<div class="section"><h2>Subdomain Takeover</h2><p style="color:#2ea043">No vulnerable subdomains found.</p></div>'}

{'<div class="section"><h2>SSL/TLS Certificates</h2><table><tr><th>Subdomain</th><th>Subject</th><th>Issuer</th><th>Expiry</th><th>Self-Signed</th><th>SANs</th></tr>' + ssl_rows + '</table></div>' if ssl_rows else ''}

{'<div class="section"><h2>HTTP Security Headers</h2><table><tr><th>Subdomain</th>' + ''.join(f'<th>{s}</th>' for s in hdr_short) + '<th>Issues</th></tr>' + hdr_rows + '</table></div>' if hdr_rows else ''}

{'<div class="section"><h2>Exposed Services</h2><table><tr><th>Subdomain</th><th>IP</th><th>Port</th><th>Service</th><th>Severity</th><th>Banner</th></tr>' + port_rows + '</table></div>' if port_rows else ''}

{'<div class="section"><h2>Cloud Assets</h2><table><tr><th>Subdomain</th><th>Provider</th><th>Region</th><th>Service</th><th>CDN</th></tr>' + cloud_rows + '</table></div>' if cloud_rows else ''}

{'<div class="section"><h2>Technologies</h2><table><tr><th>Subdomain</th><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th></tr>' + tech_rows + '</table></div>' if tech_rows else ''}

{'<div class="section"><h2>DNS Zone Health</h2><table><tr><th>Subdomain</th><th>CAA</th><th>DNSSEC</th><th>AXFR</th><th>Orphaned</th><th>Issues</th></tr>' + dns_rows + '</table></div>' if dns_rows else ''}

<div class="section">
<h2>Per-Subdomain Details</h2>
<div class="controls">
  <input type="text" id="subSearch" placeholder="Search subdomains..." oninput="filterSubs()">
  <button onclick="toggleFilter('all')" class="active" id="btn-all">All</button>
  <button onclick="toggleFilter('critical')" id="btn-critical">Critical</button>
  <button onclick="toggleFilter('high')" id="btn-high">High</button>
  <button onclick="toggleFilter('medium')" id="btn-medium">Medium</button>
  <button onclick="toggleFilter('low')" id="btn-low">Low</button>
  <button onclick="toggleFilter('info')" id="btn-info">Info</button>
</div>
{detail_sections}
</div>

<script>
let activeFilter = 'all';
function toggleFilter(level) {{
  activeFilter = level;
  document.querySelectorAll('.controls button').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + level).classList.add('active');
  filterSubs();
}}
function filterSubs() {{
  const q = document.getElementById('subSearch').value.toLowerCase();
  document.querySelectorAll('.sub-detail').forEach(d => {{
    const text = d.querySelector('summary').textContent.toLowerCase();
    const risk = d.dataset.risk;
    const matchText = !q || text.includes(q);
    const matchRisk = activeFilter === 'all' || risk === activeFilter;
    d.style.display = (matchText && matchRisk) ? '' : 'none';
  }});
}}
document.querySelectorAll('th').forEach(th => {{
  th.addEventListener('click', function() {{
    const table = this.closest('table');
    const idx = Array.from(this.parentNode.children).indexOf(this);
    const rows = Array.from(table.querySelectorAll('tbody tr, tr')).slice(1);
    const dir = this.dataset.dir === 'asc' ? 'desc' : 'asc';
    this.dataset.dir = dir;
    rows.sort((a, b) => {{
      const at = (a.children[idx] || {{}}).textContent || '';
      const bt = (b.children[idx] || {{}}).textContent || '';
      const an = parseFloat(at), bn = parseFloat(bt);
      if (!isNaN(an) && !isNaN(bn)) return dir === 'asc' ? an - bn : bn - an;
      return dir === 'asc' ? at.localeCompare(bt) : bt.localeCompare(at);
    }});
    rows.forEach(r => table.appendChild(r));
  }});
}});
</script>

</body></html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"[+] HTML: {path}")

# ── Interactive Mode ─────────────────────────────────────────────────────────

# ── Results Viewer ───────────────────────────────────────────────────────────

_SEV_ICON = {"critical": "!!", "high": "! ", "medium": "~ ", "low": ". ", "info": "  "}
_SEV_LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}

def _bar(value, max_val, width=30, fill="█", empty="░"):
    """Render a simple text progress bar."""
    if max_val <= 0:
        return empty * width
    ratio = min(value / max_val, 1.0)
    filled = int(ratio * width)
    return fill * filled + empty * (width - filled)

def _print_divider(char="─", width=80):
    print(char * width)

def _view_posture(scan):
    """Display the overall security posture dashboard."""
    posture = scan["overall_posture"]
    grade = posture["letter_grade"]
    score = posture["score"]
    dist = posture.get("risk_distribution", {})
    total_issues = sum(dist.values())
    total_subs = scan["summary"]["total_subdomains"]

    print()
    _print_divider("═")
    # Large grade display
    grade_art = {
        "A": "  ██████╗    Score: {s}/100\n ██╔══██╗   {desc}\n ██████╔╝\n ██╔══██╗\n ██║  ██║\n ╚═════╝ ",
        "B": "  ██████╗    Score: {s}/100\n ██╔══██╗   {desc}\n ██████╔╝\n ██╔══██╗\n ██████╔╝\n ╚═════╝ ",
        "C": "  ██████╗    Score: {s}/100\n ██╔════╝   {desc}\n ██║      \n ██║      \n ╚██████╗ \n  ╚═════╝ ",
        "D": "  ██████╗    Score: {s}/100\n ██╔══██╗   {desc}\n ██║  ██║\n ██║  ██║\n ██████╔╝\n ╚═════╝ ",
        "F": "  ██████╗    Score: {s}/100\n ██╔════╝   {desc}\n █████╗  \n ██╔══╝  \n ██║     \n ╚═╝     ",
    }
    if score >= 90:
        desc = "Excellent — minimal attack surface"
    elif score >= 75:
        desc = "Good — minor improvements recommended"
    elif score >= 60:
        desc = "Fair — several issues need attention"
    elif score >= 40:
        desc = "Poor — significant security gaps"
    else:
        desc = "Critical — immediate remediation needed"

    art = grade_art.get(grade, grade_art["F"]).format(s=score, desc=desc)
    for line in art.splitlines():
        print(f"  {line}")
    _print_divider("═")

    # Issue distribution bar chart
    print(f"\n  Issue Distribution ({total_issues} total across {total_subs} subdomains):\n")
    max_count = max(dist.values()) if dist else 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = dist.get(sev, 0)
        bar = _bar(count, max_count, width=40)
        label = _SEV_LABEL[sev]
        print(f"  {label}  {bar} {count}")

    # Module summary
    print(f"\n  Modules run: {', '.join(scan['summary'].get('modules_run', []))}")
    print()

def _view_rankings(scan, page_size=20):
    """Display paginated subdomain risk rankings."""
    subs = scan["per_subdomain"]
    total = len(subs)
    if not subs:
        print("  No subdomain data.")
        return

    page = 0
    while True:
        start = page * page_size
        end = min(start + page_size, total)
        chunk = subs[start:end]

        print(f"\n  Subdomain Risk Rankings (showing {start+1}-{end} of {total}, sorted worst-first):\n")
        print(f"  {'#':<4} {'Subdomain':<42} {'Grade':>5} {'Score':>6}  {'Risk':<9} Issues")
        _print_divider()
        for i, r in enumerate(chunk, start + 1):
            issue_count = len(r.get("all_issues", []))
            top_sev = r["all_issues"][0]["severity"] if r.get("all_issues") else "-"
            print(f"  {i:<4} {r['subdomain']:<42} {r['letter_grade']:>5} {r['normalized_score']:>5}/100"
                  f"  {r['risk_level']:<9} {issue_count} ({top_sev})")

        print()
        nav = []
        if page > 0:
            nav.append("p) prev")
        if end < total:
            nav.append("n) next")
        nav.append("#) inspect subdomain by rank number")
        nav.append("b) back")
        print(f"  {' | '.join(nav)}")
        choice = input("  > ").strip().lower()

        if choice == "n" and end < total:
            page += 1
        elif choice == "p" and page > 0:
            page -= 1
        elif choice == "b":
            break
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < total:
                _view_subdomain_detail(subs[idx])
            else:
                print(f"  [!] Invalid rank. Enter 1-{total}.")
        else:
            break

def _view_subdomain_detail(sub_risk):
    """Display detailed findings for a single subdomain."""
    sub = sub_risk["subdomain"]
    mods = sub_risk.get("modules", {})

    print(f"\n{'═' * 80}")
    print(f"  {sub}")
    print(f"  Grade: {sub_risk['letter_grade']}  Score: {sub_risk['normalized_score']}/100  "
          f"Risk: {sub_risk['risk_level']}")
    print(f"  Issues: {len(sub_risk.get('all_issues', []))}")
    print(f"{'═' * 80}")

    # Module scores bar chart
    mod_scores = sub_risk.get("module_scores", {})
    if mod_scores:
        max_ms = max(mod_scores.values()) if mod_scores.values() else 1
        print(f"\n  Module Risk Contribution:")
        for mod, score in sorted(mod_scores.items(), key=lambda x: -x[1]):
            bar = _bar(score, max(max_ms, 0.1), width=25)
            print(f"    {mod:<12} {bar} {score:.1f}")

    # Takeover
    tk = mods.get("takeover", {})
    if tk.get("vulnerable"):
        print(f"\n  [TAKEOVER] VULNERABLE")
        print(f"    CNAME: {', '.join(tk.get('cnames', []))}")
        print(f"    Service: {tk.get('service', 'unknown')}")
        print(f"    HTTP confirmed: {'YES' if tk.get('http_confirmed') else 'no'}")
        print(f"    {tk.get('message', '')}")

    # SSL
    ssl_data = mods.get("ssl", {})
    cert = ssl_data.get("cert")
    if cert:
        days = cert.get("days_until_expiry")
        days_str = f"{days}d" if days is not None else "?"
        print(f"\n  [SSL/TLS]")
        print(f"    Subject:  {cert.get('subject', '?')}")
        print(f"    Issuer:   {cert.get('issuer', '?')} ({cert.get('issuer_org', '')})")
        print(f"    Expiry:   {cert.get('not_after', '?')} ({days_str})")
        print(f"    SANs:     {cert.get('san_count', 0)} entries")
        print(f"    Wildcard: {'yes' if cert.get('is_wildcard') else 'no'}")
        print(f"    Self-signed: {'YES' if cert.get('is_self_signed') else 'no'}")
    elif ssl_data.get("reachable") is False and not ssl_data.get("issues"):
        pass  # not reachable on 443, skip
    for i in ssl_data.get("issues", []):
        print(f"    [{_SEV_LABEL[i['severity']]}] {i['message']}")

    # Headers
    hdr = mods.get("headers", {})
    if hdr.get("https_reachable") or hdr.get("http_reachable"):
        print(f"\n  [HEADERS]")
        print(f"    HTTPS: {'yes' if hdr.get('https_reachable') else 'no'}  "
              f"HTTP: {'yes' if hdr.get('http_reachable') else 'no'}  "
              f"HTTP->HTTPS: {'yes' if hdr.get('http_redirects_to_https') else 'no'}")
        # Show present/missing headers as a grid
        check_headers = ["strict-transport-security", "content-security-policy",
                         "x-frame-options", "x-content-type-options",
                         "referrer-policy", "permissions-policy"]
        short_names = ["HSTS", "CSP", "XFO", "XCTO", "Referrer", "Permissions"]
        h = hdr.get("headers", {})
        line = "    "
        for short, full in zip(short_names, check_headers):
            present = full in h
            mark = "✓" if present else "✗"
            line += f"{short}:{mark}  "
        print(line)
        for i in hdr.get("issues", []):
            print(f"    [{_SEV_LABEL[i['severity']]}] {i['message']}")

    # Ports
    ports = mods.get("ports", {})
    if ports.get("open_ports"):
        print(f"\n  [OPEN PORTS] ({ports.get('ip', '?')})")
        for p in ports["open_ports"]:
            sev = _SEV_LABEL.get(p.get("severity", "info"), "    ")
            banner_str = f"  {p['banner'][:60]}" if p.get("banner") else ""
            print(f"    [{sev}] {p['port']}/{p['service']}{banner_str}")

    # Cloud
    cloud = mods.get("cloud", {})
    if cloud.get("cloud_provider") or cloud.get("cdn"):
        print(f"\n  [CLOUD]")
        print(f"    Provider: {cloud.get('cloud_provider') or 'unknown'}  "
              f"Region: {cloud.get('cloud_region') or '?'}  "
              f"Service: {cloud.get('cloud_service') or '?'}")
        print(f"    CDN: {cloud.get('cdn') or 'none detected'}")

    # Tech
    tech = mods.get("tech", {})
    if tech.get("technologies"):
        print(f"\n  [TECHNOLOGY]")
        if tech.get("waf"):
            print(f"    WAF: {tech['waf']}")
        if tech.get("server"):
            print(f"    Server: {tech['server']}")
        cats = {}
        for t in tech["technologies"]:
            cat = t.get("category", "Other")
            if cat not in cats:
                cats[cat] = []
            ver = f" {t['version']}" if t.get("version") else ""
            cats[cat].append(f"{t['name']}{ver}")
        for cat, items in cats.items():
            print(f"    {cat}: {', '.join(items)}")

    # DNS
    dns_data = mods.get("dns", {})
    if dns_data.get("issues") or dns_data.get("caa") or dns_data.get("axfr_vulnerable"):
        print(f"\n  [DNS HEALTH]")
        print(f"    CAA: {'yes' if dns_data.get('caa') else 'none'}  "
              f"DNSSEC: {'DS present' if dns_data.get('dnssec', {}).get('has_ds') else 'none'}  "
              f"AXFR: {'VULNERABLE' if dns_data.get('axfr_vulnerable') else 'safe'}  "
              f"Orphaned: {'yes' if dns_data.get('orphaned') else 'no'}")
        for i in dns_data.get("issues", []):
            print(f"    [{_SEV_LABEL[i['severity']]}] {i['message']}")

    print()
    input("  Press Enter to go back...")

def _view_by_module(scan, module_name):
    """View results filtered to a specific module."""
    titles = {
        "takeover": "Subdomain Takeover",
        "ssl": "SSL/TLS Certificates",
        "headers": "HTTP Security Headers",
        "ports": "Exposed Services",
        "cloud": "Cloud Assets",
        "tech": "Technology Stack",
        "dns": "DNS Zone Health",
    }
    print(f"\n{'─' * 80}")
    print(f"  {titles.get(module_name, module_name)}")
    print(f"{'─' * 80}")

    subs = scan["per_subdomain"]
    shown = 0

    for r in subs:
        mod = r.get("modules", {}).get(module_name, {})
        issues = mod.get("issues", [])

        if module_name == "takeover":
            if not mod.get("vulnerable"):
                continue
            print(f"\n  {r['subdomain']}")
            print(f"    CNAME: {', '.join(mod.get('cnames', []))}")
            print(f"    Service: {mod.get('service', '?')}  "
                  f"HTTP: {'CONFIRMED' if mod.get('http_confirmed') else 'unconfirmed'}")
            print(f"    {mod.get('message', '')}")
            shown += 1

        elif module_name == "ssl":
            cert = mod.get("cert")
            if not cert and not issues:
                continue
            days = cert.get("days_until_expiry", "?") if cert else "?"
            subj = cert.get("subject", "?") if cert else "?"
            iss = cert.get("issuer", "?") if cert else "?"
            self_s = "SELF-SIGNED" if cert and cert.get("is_self_signed") else ""
            print(f"  {r['subdomain']:<40} CN={subj:<25} Issuer={iss:<20} "
                  f"Exp={days}d {self_s}")
            for i in issues:
                print(f"    [{_SEV_LABEL[i['severity']]}] {i['message']}")
            shown += 1

        elif module_name == "headers":
            if not mod.get("https_reachable") and not mod.get("http_reachable"):
                continue
            h = mod.get("headers", {})
            checks = ["strict-transport-security", "content-security-policy",
                       "x-frame-options", "x-content-type-options",
                       "referrer-policy", "permissions-policy"]
            short = ["HSTS", "CSP", "XFO", "XCTO", "Ref", "Perm"]
            marks = " ".join(f"{s}:{'✓' if c in h else '✗'}" for s, c in zip(short, checks))
            issue_count = len(issues)
            print(f"  {r['subdomain']:<40} {marks}  ({issue_count} issues)")
            shown += 1

        elif module_name == "ports":
            if not mod.get("open_ports"):
                continue
            ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in mod["open_ports"])
            ip = mod.get("ip", "?")
            print(f"  {r['subdomain']:<40} [{ip}] {ports_str}")
            for i in issues:
                print(f"    [{_SEV_LABEL[i['severity']]}] {i['message']}")
            shown += 1

        elif module_name == "cloud":
            if not mod.get("cloud_provider") and not mod.get("cdn"):
                continue
            prov = mod.get("cloud_provider", "?")
            region = mod.get("cloud_region", "")
            cdn = mod.get("cdn", "")
            ips = ", ".join(mod.get("ips", [])[:2])
            print(f"  {r['subdomain']:<40} {prov:<12} {region:<15} CDN={cdn or 'none':<12} [{ips}]")
            shown += 1

        elif module_name == "tech":
            techs = mod.get("technologies", [])
            if not techs:
                continue
            waf = mod.get("waf", "")
            names = ", ".join(t["name"] for t in techs)
            print(f"  {r['subdomain']:<40} {names}")
            shown += 1

        elif module_name == "dns":
            if not issues:
                continue
            caa = "CAA:✓" if mod.get("caa") else "CAA:✗"
            dnssec = "DNSSEC:✓" if mod.get("dnssec", {}).get("has_ds") else "DNSSEC:✗"
            axfr = "AXFR:VULN" if mod.get("axfr_vulnerable") else "AXFR:safe"
            print(f"  {r['subdomain']:<40} {caa}  {dnssec}  {axfr}")
            for i in issues:
                print(f"    [{_SEV_LABEL[i['severity']]}] {i['message']}")
            shown += 1

    if shown == 0:
        print(f"\n  No findings for {titles.get(module_name, module_name)}.")
    else:
        print(f"\n  {shown} subdomains with findings.")

    print()
    input("  Press Enter to go back...")

def _view_issues_by_severity(scan, severity):
    """View all issues of a specific severity across all subdomains."""
    print(f"\n  All {severity.upper()} issues:\n")
    count = 0
    for r in scan["per_subdomain"]:
        for i in r.get("all_issues", []):
            if i.get("severity") == severity:
                mod = i.get("module", "?")
                print(f"  {r['subdomain']:<40} [{mod:<8}] {i['message']}")
                count += 1
    if count == 0:
        print(f"  No {severity} issues found.")
    else:
        print(f"\n  {count} total {severity} issues.")
    print()
    input("  Press Enter to go back...")

def _view_search(scan):
    """Search subdomains by name and view their details."""
    query = input("  Search subdomain: ").strip().lower()
    if not query:
        return
    matches = [r for r in scan["per_subdomain"] if query in r["subdomain"].lower()]
    if not matches:
        print(f"  No subdomains matching '{query}'.")
        return
    print(f"\n  {len(matches)} matches:\n")
    for i, r in enumerate(matches, 1):
        issue_count = len(r.get("all_issues", []))
        print(f"  {i}) {r['subdomain']:<45} Grade: {r['letter_grade']}  "
              f"Score: {r['normalized_score']}/100  Issues: {issue_count}")
    print()
    choice = input("  Enter # to inspect, or Enter to go back: ").strip()
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(matches):
            _view_subdomain_detail(matches[idx])

def _view_results(scan):
    """Interactive results browser — main entry point."""
    posture = scan["overall_posture"]
    dist = posture.get("risk_distribution", {})

    while True:
        print(f"\n{'═' * 60}")
        print(f"  RESULTS VIEWER — {scan['domain']}")
        print(f"  Grade: {posture['letter_grade']}  Score: {posture['score']}/100  "
              f"Subdomains: {scan['summary']['total_subdomains']}")
        print(f"  Issues: {dist.get('critical',0)} critical, {dist.get('high',0)} high, "
              f"{dist.get('medium',0)} medium, {dist.get('low',0)} low")
        print(f"{'═' * 60}")
        print()
        print("  Views:")
        print("    1) Security Posture Dashboard")
        print("    2) Subdomain Risk Rankings")
        print("    3) Search subdomain")
        print()
        print("  By Module:")
        print("    4) Subdomain Takeover findings")
        print("    5) SSL/TLS Certificate findings")
        print("    6) HTTP Security Header findings")
        print("    7) Exposed Services findings")
        print("    8) Cloud Asset Inventory")
        print("    9) Technology Stack")
        print("    10) DNS Zone Health findings")
        print()
        print("  By Severity:")
        print("    c) All Critical issues")
        print("    h) All High issues")
        print("    m) All Medium issues")
        print()
        print("    b) Back to main menu")
        choice = input("\n  > ").strip().lower()

        if choice == "1":
            _view_posture(scan)
        elif choice == "2":
            _view_rankings(scan)
        elif choice == "3":
            _view_search(scan)
        elif choice == "4":
            _view_by_module(scan, "takeover")
        elif choice == "5":
            _view_by_module(scan, "ssl")
        elif choice == "6":
            _view_by_module(scan, "headers")
        elif choice == "7":
            _view_by_module(scan, "ports")
        elif choice == "8":
            _view_by_module(scan, "cloud")
        elif choice == "9":
            _view_by_module(scan, "tech")
        elif choice == "10":
            _view_by_module(scan, "dns")
        elif choice == "c":
            _view_issues_by_severity(scan, "critical")
        elif choice == "h":
            _view_issues_by_severity(scan, "high")
        elif choice == "m":
            _view_issues_by_severity(scan, "medium")
        elif choice == "b":
            break
        else:
            print("  [!] Invalid option.")


def interactive_mode():
    domain = input("Enter target domain (e.g. example.com): ").strip()
    if not domain:
        print("[!] No domain provided.")
        return
    debug = input("Enable debug mode? (y/N): ").strip().lower().startswith("y")

    if debug:
        print(f"\n[*] Enumerating subdomains for {domain}...")
        subdomains = enumerate_subdomains(domain, debug)
    else:
        print()
        subdomains = _run_with_starburst(
            "Enumerating subdomains", enumerate_subdomains, domain, debug)
    print(f"[+] Found {len(subdomains)} unique subdomains\n")

    scan_cache = None

    while True:
        print(f"\n=== ScopeScan ===")
        print(f"  Domain: {domain} | {len(subdomains)} subdomains")
        print()
        has_results = " [results ready]" if scan_cache else ""
        print("  1) List subdomains")
        print("  2) Validate subdomains (DNS)")
        print("  3) Full scan (all modules)")
        print("  4) Subdomain Takeover scan")
        print("  5) SSL/TLS Certificate audit")
        print("  6) HTTP Security Headers")
        print("  7) Exposed Service Discovery")
        print("  8) Cloud Asset Inventory")
        print("  9) Web Technology Fingerprint")
        print("  10) DNS Zone Health")
        print(f"  11) View results{has_results}")
        print("  12) Export results")
        print("  q) Quit")
        choice = input("\nChoice: ").strip()

        if choice == "1":
            for sub in subdomains:
                print(f"  {sub}")

        elif choice == "2":
            valid = _run_with_starburst(
                "Validating DNS resolution", validate_subdomains, subdomains)
            print(f"[+] {len(valid)} / {len(subdomains)} subdomains resolve")
            if input("Use only resolved subdomains going forward? (y/N): ").strip().lower().startswith("y"):
                subdomains = sorted(valid)
                print(f"[+] Filtered to {len(subdomains)} subdomains")

        elif choice == "3":
            scan_cache = full_scan(domain, subdomains, debug=debug)
            posture = scan_cache["overall_posture"]
            print(f"\n  Overall Grade: {posture['letter_grade']}  Score: {posture['score']}/100")
            dist = posture.get("risk_distribution", {})
            print(f"  Issues: {dist.get('critical',0)} critical, {dist.get('high',0)} high, "
                  f"{dist.get('medium',0)} medium, {dist.get('low',0)} low")
            print(f"\n  Top 5 riskiest subdomains:")
            for r in scan_cache["per_subdomain"][:5]:
                print(f"    {r['subdomain']:<45} Grade: {r['letter_grade']}  Score: {r['normalized_score']}")

        elif choice == "4":
            print("[*] Running Subdomain Takeover scan...")
            results = scan_takeover_batch(subdomains)
            vuln = [r for r in results if r["vulnerable"]]
            if vuln:
                print(f"\n  {len(vuln)} VULNERABLE subdomains:")
                for r in vuln:
                    print(f"    {r['subdomain']}: {r['message']}")
            else:
                print("  No takeover vulnerabilities found.")

        elif choice == "5":
            print("[*] Running SSL/TLS audit...")
            results = audit_ssl_batch(subdomains)
            for r in results:
                if r["issues"]:
                    print(f"  {r['subdomain']}:")
                    for i in r["issues"]:
                        print(f"    [{i['severity'].upper()}] {i['message']}")

        elif choice == "6":
            print("[*] Running HTTP Security Header scan...")
            results = scan_headers_batch(subdomains)
            for r in results:
                if r["issues"]:
                    print(f"  {r['subdomain']}: {len(r['issues'])} issues")
                    for i in r["issues"][:3]:
                        print(f"    [{i['severity'].upper()}] {i['message']}")

        elif choice == "7":
            print("[*] Running Exposed Service Discovery...")
            results = scan_ports_batch(subdomains)
            for r in results:
                if r["open_ports"]:
                    ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in r["open_ports"])
                    print(f"  {r['subdomain']} ({r['ip']}): {ports_str}")

        elif choice == "8":
            print("[*] Running Cloud Asset Inventory...")
            results = inventory_cloud_batch(subdomains)
            for r in results:
                if r["cloud_provider"] or r["cdn"]:
                    print(f"  {r['subdomain']}: provider={r['cloud_provider'] or 'N/A'}, "
                          f"cdn={r['cdn'] or 'N/A'}")

        elif choice == "9":
            print("[*] Running Web Technology Fingerprint...")
            results = fingerprint_tech_batch(subdomains)
            for r in results:
                if r["technologies"]:
                    techs = ", ".join(t["name"] for t in r["technologies"])
                    print(f"  {r['subdomain']}: {techs}")

        elif choice == "10":
            print("[*] Running DNS Zone Health audit...")
            results = audit_dns_batch(subdomains, domain)
            for r in results:
                if r["issues"]:
                    print(f"  {r['subdomain']}: {len(r['issues'])} issues")
                    for i in r["issues"][:3]:
                        print(f"    [{i['severity'].upper()}] {i['message']}")

        elif choice == "11":
            if not scan_cache:
                print("[!] Run a full scan (option 3) first.")
                continue
            _view_results(scan_cache)

        elif choice == "12":
            if not scan_cache:
                print("[!] Run a full scan (option 3) first.")
                continue
            print("  Export options:")
            print("    c) CSV   j) JSON   h) HTML   a) All   n) Skip")
            exp = input("  Export: ").strip().lower()
            base = domain.replace(".", "_") + "_scopescan"
            if exp in ("c", "a"):
                export_csv(scan_cache, f"{base}.csv")
            if exp in ("j", "a"):
                export_json(scan_cache, f"{base}.json")
            if exp in ("h", "a"):
                export_html(scan_cache, f"{base}.html")

        elif choice == "q":
            break
        else:
            print("[!] Invalid option.")

# ── CLI Mode ─────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(prog="scopescan", description="ScopeScan — Attack Surface Security Scanner")
    p.add_argument("domain", nargs="?", help="Target domain")
    p.add_argument("-o", "--output", help="Output base path")
    p.add_argument("--modules", help="Comma-separated: takeover,ssl,headers,ports,cloud,tech,dns")
    p.add_argument("--subs-file", help="Load subdomains from file")
    p.add_argument("--skip-enum", action="store_true")
    p.add_argument("--workers", type=int, default=15)
    p.add_argument("--debug", action="store_true")
    return p

def cli_mode(args):
    domain = args.domain

    if args.subs_file:
        with open(args.subs_file) as f:
            subdomains = sorted({line.strip() for line in f if line.strip()})
        print(f"[+] Loaded {len(subdomains)} subdomains from {args.subs_file}")
    elif args.skip_enum:
        subdomains = [domain]
    else:
        if args.debug:
            print(f"[*] Enumerating subdomains for {domain}...")
            subdomains = enumerate_subdomains(domain, args.debug)
        else:
            subdomains = _run_with_starburst(
                "Enumerating subdomains", enumerate_subdomains, domain, args.debug)
        print(f"[+] Found {len(subdomains)} subdomains")

    modules = None
    if args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]

    scan = full_scan(domain, subdomains, modules=modules, debug=args.debug, workers=args.workers)

    posture = scan["overall_posture"]
    print(f"\nOverall Grade: {posture['letter_grade']}  Score: {posture['score']}/100")
    dist = posture.get("risk_distribution", {})
    print(f"Issues: {dist.get('critical',0)} critical, {dist.get('high',0)} high, "
          f"{dist.get('medium',0)} medium, {dist.get('low',0)} low")

    print(f"\nTop riskiest subdomains:")
    for r in scan["per_subdomain"][:10]:
        print(f"  {r['subdomain']:<45} Grade: {r['letter_grade']}  Score: {r['normalized_score']}")

    base = args.output or domain.replace(".", "_") + "_scopescan"
    export_csv(scan, base + ".csv")
    export_json(scan, base + ".json")
    export_html(scan, base + ".html")

# ── Entry ────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.domain:
        cli_mode(args)
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
