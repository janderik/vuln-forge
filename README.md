# VulnForge 🔍

[![CI](https://github.com/vulnforge/vulnforge/actions/workflows/ci.yml/badge.svg)](https://github.com/vulnforge/vulnforge/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-scanner-red.svg)]()

**VulnForge** is a comprehensive, concurrent vulnerability scanner for network services and web applications. It combines port scanning, service fingerprinting, web vulnerability testing, and CVE matching into a single CLI tool with rich output and professional reports.

---

## Features

- **Port Scanner** — TCP connect scan & simulated SYN scan with configurable port ranges and concurrency
- **Service Detection** — Banner grabbing and fingerprinting for HTTP, SSH, FTP, MySQL, PostgreSQL, Redis, and more
- **Web Vulnerability Scanner** — Reflected XSS detection, SQL injection probing, directory enumeration, security header analysis, cookie audit
- **CVE Checker** — Built-in database of ~50 real CVE entries for Apache, Nginx, OpenSSH, MySQL, PostgreSQL, Redis, IIS, and more; optional CIRCL API enrichment
- **Report Generation** — Professional HTML (with severity badges, tables, summary cards) and JSON output
- **Rich CLI** — Color-coded output, progress spinners, severity-based formatting via the `rich` library
- **Concurrent Architecture** — Full async/await with semaphore-limited concurrency

## Architecture

```
vuln-forge/
├── src/
│   ├── cli.py                 # CLI entry point (click + rich)
│   ├── scanners/
│   │   ├── base.py            # Abstract BaseScanner + ScanResult dataclass
│   │   ├── port_scanner.py    # TCP/SYN port scanning
│   │   ├── service_detector.py # Banner grabbing + service fingerprinting
│   │   ├── web_vuln.py        # XSS, SQLi, directory busting, header analysis
│   │   └── cve_checker.py     # CVE matching (local DB + CIRCL API)
│   ├── report/
│   │   └── generator.py       # HTML & JSON report generation
│   └── db/
│       └── cve_cache.py       # SQLite-backed CVE cache with ~50 built-in entries
├── tests/                     # pytest test suite
├── data/payloads/             # XSS payload library
└── Dockerfile                 # Containerized deployment
```

## Installation

```bash
# From source
git clone https://github.com/vulnforge/vulnforge.git
cd vulnforge
pip install -r requirements.txt
pip install -e .

# Using Docker
docker build -t vulnforge .
docker run --rm vulnforge --help
```

## Usage

```
Usage: vulnforge scan [OPTIONS] TARGET

Options:
  -p, --ports TEXT            Port range (e.g. 22,80,443 or 1-1000)
  --scan-type [tcp_connect|syn]
  --timeout FLOAT             Timeout per port in seconds
  --concurrency INTEGER       Max concurrent connections
  --service-detect            Enable service detection
  --web-scan                  Enable web vulnerability scan
  --cve-check                 Enable CVE matching
  --circl-api                 Use CIRCL API for CVE lookups
  -o, --output TEXT           Output file path
  -f, --format [html|json]    Output format
  -v, --verbose               Enable debug logging
  --help                      Show help
```

### Examples

```bash
# Full scan with all modules
vulnforge scan example.com

# Quick port scan
vulnforge scan 192.168.1.1 -p 22,80,443,3306 --service-detect

# Web vulnerability scan only
vulnforge scan https://example.com --web-scan -o report.html

# Scan with CVE matching + CIRCL API
vulnforge scan target.local --cve-check --circl-api

# Look up CVEs for a specific product
vulnforge cves Apache --version 2.4.49

# List available XSS payloads
vulnforge list-payloads

# JSON output
vulnforge scan example.com -f json -o scan.json
```

## CVE Database

VulnForge ships with a built-in SQLite-backed CVE database containing ~50 entries for:

| Product    | Sample CVEs                                    |
|------------|------------------------------------------------|
| Apache     | CVE-2023-25690, CVE-2022-26377, CVE-2024-24795 |
| Nginx      | CVE-2023-44487, CVE-2021-23017, CVE-2024-24989 |
| OpenSSH    | CVE-2024-6387 (regreSSHion), CVE-2023-38408    |
| MySQL      | CVE-2023-21971, CVE-2023-22053, CVE-2023-22102 |
| PostgreSQL | CVE-2023-2454, CVE-2023-2455, CVE-2024-0985    |
| Redis      | CVE-2022-0543, CVE-2023-41056, CVE-2023-45145  |
| IIS        | CVE-2023-38171, CVE-2023-36418                 |
| and more   | SMB, RDP, VNC, MongoDB, WinRM, FTP, SMTP       |

## Testing

```bash
pytest tests/ -v
pytest tests/ -v --coverage --cov=src
```

## License

MIT License — see [LICENSE](LICENSE).
