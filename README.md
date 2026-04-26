<h1 align="center">
  <br>
  ⚡ HackME — Web Vulnerability Scanner
  <br>
</h1>

<h4 align="center">Developed by <b>Meelan Neupane</b></h4>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
</p>

> ⚠️ **For Authorized Penetration Testing ONLY.**
> Use this tool only on systems you own or have explicit written permission to test.

---

## 🔍 Features

- 🕷️ **Smart Crawler** — Burp/ZAP-style spider (BFS, configurable depth)
- 💉 **XSS Scanner** — 40+ payloads (reflected, DOM, template injection)
- 🗄️ **SQL Injection** — Error-based, Time-based blind, Boolean-based blind
- 📁 **Path Traversal / LFI** — Unix, Windows, PHP wrappers, null bytes
- 🔁 **Open Redirect** — Detects unvalidated redirect parameters
- 🛡️ **Header Scanner** — Missing security headers + info disclosure
- 🖥️ **GUI Mode** — Dark hacker-themed Tkinter interface
- 💻 **CLI Mode** — Colored terminal output with full argparse support
- 📊 **Reports** — Auto-saves JSON + HTML reports

---

---

## 🚀 Installation

```bash
# Clone the repo
git clone https://github.com/Meelan1/webSec.git
cd webSec

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### CLI Mode
```bash
# Full scan (default)
python hackme.py -u https://testphp.vulnweb.com

# XSS only
python hackme.py -u https://testphp.vulnweb.com -m xss

# SQL Injection only
python hackme.py -u https://testphp.vulnweb.com -m sqli

# Path Traversal only
python hackme.py -u https://testphp.vulnweb.com -m path

# With proxy (Burp Suite)
python hackme.py -u https://site.com --proxy http://127.0.0.1:8080

# With cookies + custom depth
python hackme.py -u https://site.com --cookies "session=abc" --depth 4

# Save reports manually
python hackme.py -u https://site.com --output report.json --html report.html
```

### GUI Mode
```bash
python hackme.py --gui
```

---

## 🎯 Scan Modes

| Mode   | Description                              |
|--------|------------------------------------------|
| `full` | XSS + SQLi + Path Traversal + extras     |
| `xss`  | Cross-Site Scripting only                |
| `sqli` | SQL Injection only                       |
| `path` | Path Traversal / LFI only               |

---

## 📋 All Flags

| Flag           | Description                          | Default |
|----------------|--------------------------------------|---------|
| `-u / --url`   | Target URL                           | —       |
| `-m / --mode`  | Scan mode: full/xss/sqli/path        | full    |
| `--depth`      | Crawl depth                          | 3       |
| `--max-urls`   | Max URLs to crawl                    | 300     |
| `--proxy`      | HTTP proxy URL                       | —       |
| `--cookies`    | Cookie string                        | —       |
| `--header`     | Custom header (repeatable)           | —       |
| `--output`     | JSON report path                     | auto    |
| `--html`       | HTML report path                     | auto    |
| `--no-report`  | Skip saving reports                  | false   |
| `--gui`        | Launch GUI mode                      | false   |

---

## 🧪 Legal Test Targets

These are safe, legal targets for testing:
- http://testphp.vulnweb.com
- http://testaspnet.vulnweb.com
- https://hackthissite.org
- Your own local DVWA / BWAPP setup

---

## ⚠️ Disclaimer

This tool is intended for **legal security research and authorized
penetration testing only**. The author **Meelan Neupane** is not
responsible for any misuse or damage caused by this tool.
Always get written permission before testing any system.

---

## 👤 Author

**Meelan Neupane**
- GitHub: [@Meelan1](https://github.com/Meelan1)

---

## ⭐ Support

If you find this tool useful, please **star the repository** ⭐
