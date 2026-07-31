# 🔍 Advanced Network Scanner (netscan)

[![Python 3.9+](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

> A professional-grade network scanner built on Python and **nmap** — engineered for
> cybersecurity internships and real-world security assessments.

`netscan` discovers hosts, fingerprints operating systems, identifies services and
versions, grabs service banners, and exports professional reports (CSV / JSON / HTML) —
all with multi-threaded performance and a clean terminal experience.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🖥️ **Host discovery** | Scan single IPs, ranges, CIDR subnets, or comma-separated lists |
| 🔌 **Port scanning** | Full `1-65535` or custom ranges/lists, TCP service detection |
| 🧬 **Service fingerprinting** | Product + version detection via nmap `-sV` |
| 💻 **OS detection** | Remote OS fingerprinting via nmap `-O` |
| 📡 **Banner grabbing** | Raw TCP banner capture with service-specific probes (HTTP, SSH, SMTP, FTP, Redis…) |
| ⚡ **Multi-threading** | Concurrent host/port scanning with `ThreadPoolExecutor` |
| 📊 **Rich progress bars** | Live terminal feedback with the `rich` library |
| 📁 **Report exports** | CSV, JSON, and styled **HTML** reports |
| 🎨 **Colored output** | Beautiful terminal UI via Colorama + Rich |
| 🧵 **Structured logging** | Console + rotating JSON file logs for auditing |
| 📦 **Packaged** | Installable via `pip`, runs as `python -m netscan` |
| 🐳 **Docker ready** | Multi-stage container with nmap pre-installed |
| ✅ **Tested & linted** | 48 pytest tests, Ruff lint, Black format, pre-commit CI |

---

## 📋 Requirements

- **Python 3.9+**
- **nmap** installed on the system

### Installing nmap

| OS | Command |
|----|---------|
| **macOS** | `brew install nmap` |
| **Ubuntu/Debian** | `sudo apt install nmap` |
| **Fedora/RHEL** | `sudo dnf install nmap` |
| **Windows** | Download from [nmap.org](https://nmap.org/download.html) |

---

## 🚀 Installation

### From source

```bash
# Clone the repository
git clone https://github.com/prateek7876/network-scanner.git
cd network-scanner

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install the package and dependencies
pip install -e .

# Optional: dev tooling (pytest, ruff, black, pre-commit)
pip install -r requirements-dev.txt
pre-commit install
```

### With Docker

```bash
docker build -t netscan .
docker run --rm -it netscan -t scanme.nmap.org -p 80,443
```

---

## 💻 Usage

### Quick start

```bash
# Basic scan — single target, default ports 1-1024
python -m netscan -t 192.168.1.1

# Scan an IP range
python -m netscan -t 192.168.1.1-50

# Scan a CIDR subnet
python -m netscan -t 192.168.1.0/24

# Multi-target scan (threaded)
python -m netscan -t 192.168.1.1,192.168.1.2,192.168.1.3 --threads 20
```

### Scan profiles

| Profile | nmap arguments | Use case |
|---------|---------------|----------|
| `--quick` | `-sV -T4` | Service/version detection (default) |
| `--full` | `-sV -sC -O -T4` | Default scripts + OS detection |
| `--stealth` | `-sS -T2` | Stealth SYN scan, slow & quiet |
| `--os-detection` | `-O -T4` | OS fingerprinting only |

```bash
python -m netscan -t 192.168.1.1 --full
python -m netscan -t 192.168.1.1 --stealth
python -m netscan -t 192.168.1.1 --os-detection
```

### Exports

```bash
python -m netscan -t scanme.nmap.org --csv --json --html
python -m netscan -t 192.168.1.1 -o my_scan --csv        # custom filename
```

### Banner grabbing

```bash
python -m netscan -t 192.168.1.1 --banner-grab
```

---

## ⚙️ Command-Line Reference

| Argument | Description | Default |
|----------|-------------|---------|
| `-t, --target` | Target IP, CIDR range, or hostname *(required)* | — |
| `-p, --ports` | Port range or comma-separated list | `1-1024` |
| `--quick` | Service version detection (default profile) | — |
| `--full` | Service + script + OS detection | — |
| `--stealth` | Stealth SYN scan (slower, less detectable) | — |
| `--os-detection` | OS fingerprinting only | — |
| `--banner-grab` | Enable TCP banner grabbing on open ports | off |
| `--csv` | Export results to CSV | off |
| `--json` | Export results to JSON | off |
| `--html` | Export results to HTML report | off |
| `-o, --output` | Output filename base (without extension) | timestamped |
| `--threads` | Concurrent worker threads | `10` |
| `-v, --verbose` | Verbose/debug logging | off |
| `--version` | Show version and exit | — |

---

## 🏗️ Architecture

```
network-scanner/
├── src/netscan/                # Installable package
│   ├── __init__.py             # Public API & version
│   ├── __main__.py             # python -m netscan entry
│   ├── cli.py                  # Argument parsing, main() entry point
│   ├── scanner.py              # Core scanning engine + scan profiles
│   ├── detector.py             # OS & service fingerprinting
│   ├── banner.py               # TCP banner grabbing (probes + threading)
│   ├── reporter.py             # CSV / JSON / HTML exports + terminal table
│   ├── logger.py               # Structured logging (rotating JSON files)
│   ├── models.py               # PortResult, ScanTarget, ScanReport
│   └── exceptions.py           # NetscanError exception hierarchy
├── tests/                      # 48 pytest tests with mocked nmap
├── .github/workflows/ci.yml    # GitHub Actions CI (lint + test, 3.9–3.12)
├── .pre-commit-config.yaml     # Ruff, Black, mypy, pre-commit hooks
├── Dockerfile                  # Multi-stage build with nmap
├── pyproject.toml              # Packaging + tool configuration
├── requirements.txt            # Runtime dependencies
├── requirements-dev.txt        # Dev/test dependencies
└── Makefile                    # install / lint / test / docker shortcuts
```

### Data flow

```
CLI (argparse)
   │
   ▼
NetworkScanner (scanner.py) ── nmap ──► host discovery + port/service/OS data
   │
   ├──► detector.py     → OS & service fingerprint enrichment
   ├──► banner.py       → threaded TCP banner capture on open ports
   │
   ▼
ScanReport (models.py)  ──► reporter.py ──► CSV / JSON / HTML + terminal table
```

### Error handling

All failures map to a typed exception hierarchy — never a silent crash:

```
NetscanError
├── NmapNotFoundError      # nmap binary missing from PATH
├── InvalidTargetError     # malformed IP / hostname
├── ScanError              # scan execution failure
└── ExportError            # report export failure
```

---

## 🔒 Responsible Use

This tool is intended for:

- ✅ Authorized security testing of systems you own or have permission to test
- ✅ Educational purposes in cybersecurity training and certification prep
- ✅ Network administration, inventory, and troubleshooting

> ⚠️ **Always obtain explicit written authorization before scanning any network or
> system. Unauthorized scanning may be illegal and is punishable under computer-misuse
> legislation in most jurisdictions.**

---

## 🧪 Development

```bash
# Install dev dependencies
make install-dev

# Run tests with coverage
make test
make test-cov          # HTML coverage report

# Lint & format
make lint
make format

# Pre-commit
make pre-commit
make pre-commit-run

# Docker
make docker-build
make docker-run TARGET="-t scanme.nmap.org -p 80,443"

# Cleanup
make clean
```

The CI pipeline (`.github/workflows/ci.yml`) runs **Ruff lint + Black format check +
pytest (with coverage)** across Python 3.9 – 3.12 on every push and pull request.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with ⚡ by <a href="https://github.com/prateek7876">Prateek Raghuvanshi</a> for cybersecurity education
</p>
