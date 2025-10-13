# 🕵️‍♂️ GRAB.PY — Advanced Web Reconnaissance Toolkit

> **Automated web reconnaissance, information gathering, and credential brute-forcing tool for ethical security research.**

---

## 📦 Overview

`grab.py` is a powerful, all-in-one web reconnaissance tool designed for **ethical hackers**, **penetration testers**, and **security researchers**. It automates the discovery of:

- Admin panels & login pages  
- Sensitive files (`.env`, `.sql`, `.log`, configs, backups)  
- API endpoints & public services  
- Server information & open ports  
- Email addresses & admin usernames  
- Technology stack (WordPress, React, Laravel, etc.)  
- **Credential brute-forcing** with intelligent username generation  

All findings are saved in structured reports (`report.txt`, `report.json`) and categorized files are automatically downloaded for offline analysis.

> ⚠️ **For educational and authorized testing only. Do not use on systems you do not own or have explicit permission to test.**

---

## 🚀 Features

| Category | Capabilities |
|--------|--------------|
| **Recon** | Crawl websites, extract links, emails, tech stack, server info |
| **Discovery** | Scan for admin panels, APIs, sensitive files, common paths |
| **Port Scanning** | Check 17+ common ports (SSH, FTP, MySQL, etc.) |
| **Brute Force** | Smart credential testing with dynamic usernames (from HTML, emails, wordlists) |
| **File Analysis** | Auto-categorize & download frontend/backend/config files |
| **Reporting** | Save results as JSON, TXT, and organized file directories |
| **Modes** | Single target, batch scan, auto-random domain finder, subdomain enum |

---

## 🛠️ Installation

### Prerequisites
- Python 3.7+
- `pip` package manager

### Setup
```bash
git clone https://github.com/VersaNexusIX/web-reconn.git
cd web-reconn
python grab.py

# Install dependencies (auto-installed on first run, but manual is safer)
pip install requests beautifulsoup4
```

> 💡 **Note**: The script will auto-install `beautifulsoup4` if missing.

---

## ▶️ Usage

### Interactive Mode (Recommended)
```bash
python3 grab.py
```
Follow the on-screen menu to select scanning mode, provide target(s), and optionally load custom wordlists.

### Quick Single Target Scan
```bash
python3 grab.py https://example.com
```

### Modes Explained
| Mode | Description |
|------|-------------|
| **1. Single Target** | Full recon on one URL |
| **2. Auto Random** | Generate & scan random domains (for research) |
| **3. Batch Scan** | Scan multiple URLs from a file (one per line) |
| **4. Subdomain Enum** | Discover common subdomains (www, admin, api, etc.) |
| **5. Brute Force Only** | Test credentials on a specific login page |

---

## 📁 Output Structure

Results are saved under:
```
~/Downloads/web_recon/
└── example_com_20240615_143022/
    ├── report.json          # Machine-readable results
    ├── report.txt           # Human-readable summary
    ├── all_links.txt        # Every discovered URL
    ├── frontend/            # JS, CSS, HTML, images
    ├── backend/             # PHP, Python, logs, SQL dumps
    ├── config/              # .env, .yml, .ini files
    └── api/
        └── endpoints.txt    # Discovered API routes
```

---

## 🔐 Brute Force Intelligence

The tool doesn’t just use default credentials—it **dynamically builds username lists** from:
- HTML comments & meta tags  
- Extracted email prefixes (`john@site.com` → `john`)  
- Custom wordlists (optional)  
- Common defaults (`admin`, `root`, etc.)

It then tests these against login forms with **multiple payload formats** and detects success via:
- Redirects (non-login pages)  
- Session cookies  
- Response length changes  
- Keyword analysis (`dashboard`, `logout`, etc.)

---

## ⚙️ Configuration

Key settings (editable in source):
```python
MAX_PAGES = 150              # Max pages to crawl
MAX_REQUESTS = 10000         # Safety limit
REQUEST_TIMEOUT = 5          # Seconds
DOWNLOAD_ROOT = "~/Downloads/web_recon"
COMMON_PORTS = [21, 22, 80, 443, ...]
DEFAULT_USERNAMES = ["admin", "root", ...]
```

---

## 📜 Example Report Snippet (`report.txt`)
```
WEB RECON REPORT
================================================================================

Target: https://vulnerable-site.com
Timestamp: 2024-06-15T14:30:22.123456
Duration: 42.87s

Server: 192.168.1.100 (Jakarta, Indonesia)

ADMIN PANELS (3)
--------------------------------------------------------------------------------
  - https://vulnerable-site.com/admin
  - https://vulnerable-site.com/wp-admin
  - https://vulnerable-site.com/login.php

FILES (5)
--------------------------------------------------------------------------------
  - https://vulnerable-site.com/.env
  - https://vulnerable-site.com/backup.sql
  - https://vulnerable-site.com/app.log

CREDENTIALS
--------------------------------------------------------------------------------
https://vulnerable-site.com/admin
  - admin:admin123
```

---

## ⚠️ Legal & Ethical Notice

This tool is intended **strictly for authorized security testing**.  
Unauthorized scanning or brute-forcing of systems you do not own is **illegal** in most jurisdictions.

> **You are responsible for your actions.** Use only on:
> - Your own systems  
> - Systems you have **written permission** to test  
> - Public bug bounty programs (with scope adherence)

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository  
2. Create a feature branch (`git checkout -b feature/your-feature`)  
3. Commit your changes (`git commit -am 'Add some feature'`)  
4. Push to the branch (`git push origin feature/your-feature`)  
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.

---

> Made with ❤️ for the security community.  
> **Stay curious. Stay ethical.** 🔒
