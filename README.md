# Advanced Network Scanner

A professional-grade network scanner built with Python and nmap. This tool is designed for cybersecurity professionals and penetration testers to discover open ports, running services, and version information on target hosts.

## Features

- [x] Scan single IP addresses
- [x] Scan IP ranges and CIDR notation subnets
- [x] Open port detection
- [x] Service and version detection
- [x] Multiple scan types (quick, full, stealth)
- [x] CSV and JSON report export
- [x] Colored terminal output
- [x] Comprehensive logging
- [x] Error handling and input validation
- [x] Virtual environment support

## Requirements

- Python 3.8+
- nmap installed on the system

### Install nmap

| OS | Command |
|----|---------|
| **macOS** | `brew install nmap` |
| **Ubuntu/Debian** | `sudo apt install nmap` |
| **Fedora/RHEL** | `sudo dnf install nmap` |
| **Windows** | Download from [nmap.org](https://nmap.org/download.html) |

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Activate virtual environment (if not already)
source venv/bin/activate

# Basic scan - single IP with default ports 1-1024
python main.py -t 192.168.1.1

# Scan IP range
python main.py -t 192.168.1.1-50

# Scan CIDR notation subnet
python main.py -t 192.168.1.0/24

# Scan specific port range
python main.py -t 192.168.1.1 -p 1-65535

# Export results to CSV
python main.py -t 192.168.1.1 --csv

# Export results to JSON
python main.py -t 192.168.1.1 --json

# Full scan with OS detection
python main.py -t 192.168.1.1 -s full

# Stealth scan (slower, less detectable)
python main.py -t 192.168.1.1 -s stealth
```

## Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `-t, --target` | Target IP, range, or CIDR notation **(required)** |
| `-p, --ports` | Port range to scan (default: 1-1024) |
| `-s, --scan-type` | Scan type: `quick`, `full`, or `stealth` |
| `--csv` | Export results to CSV file |
| `--json` | Export results to JSON file |
| `--output` | Custom output filename (without extension) |
| `-v, --verbose` | Enable verbose logging |

## Output

### Terminal Output
The terminal displays a colored, formatted table showing:
- Target IP and hostname
- Protocol type (TCP/UDP)
- Port number and state
- Service name and version

### Reports
- **CSV**: Structured table with columns (IP, Hostname, Port, Service, Version)
- **JSON**: Machine-readable format for integration with other tools

### Logs
All scan activity is logged to `logs/` directory with timestamps for auditing and debugging.

## Project Structure

```
network-scanner/
├── __init__.py          # Package initialization
├── main.py              # CLI entry point
├── scanner.py           # Core scanning logic
├── logger.py            # Logging configuration
├── requirements.txt     # Python dependencies
├── README.md            # Documentation
├── .gitignore           # Git ignore rules
├── logs/                # Scan logs (auto-created)
├── venv/                # Virtual environment (not tracked)
└── scan_results.csv|json  # Exported reports
```

## Use Cases

- **Security Auditing**: Identify open ports and services on internal networks
- **Penetration Testing**: Discover attack surface of target systems
- **Network Inventory**: Map devices and services on a network
- **Vulnerability Assessment**: Version detection helps identify outdated services

## Responsible Use

This tool is intended for:
- Authorized security testing of systems you own or have permission to test
- Educational purposes in cybersecurity training
- Network administration and troubleshooting

**Always obtain proper authorization before scanning any network or system.**

## License

This project is for educational and professional use.
