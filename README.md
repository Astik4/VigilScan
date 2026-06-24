# VigilScan: Risk-Scoring Port Scanner

A portfolio-grade Python CLI tool that scans network ports, identifies services (via banner grabbing and HTTP header parsing), queries the NVD (National Vulnerability Database) for known CVEs, and calculates an aggregated risk score for the target host. 

This tool is designed to move beyond simple "open port listing" by providing contextual vulnerability analysis and exportable reports in console, JSON, and static HTML formats.

---

## Features

- **Multithreaded TCP Connect Scan**: High-performance concurrent scanning across custom ports, ranges, or presets (top 100/1000 ports).
- **Service & Version Detection**: Grabs greeting banners (SSH, FTP, SMTP, Telnet) and queries HTTP/HTTPS headers to extract service names and version numbers.
- **NVD API Integration**: Performs keyword searches on the NVD API v2.0 to cross-reference software versions with known vulnerabilities.
- **SQLite Caching**: Caches vulnerability lookups locally (`cve_cache.db`) with configurable expiration (default: 7 days) to speed up repeat scans and respect NVD API rate limits.
- **Quantitative Risk Scoring**: Computes a host-level risk score (0.0 to 10.0) using a custom formula that balances principal severity, compounding vulnerability density, and attack surface exposure.
- **Rich CLI Console Output**: Displays progress bars, real-time logging, colored tables, and an interactive host risk meter.
- **Multiple Exporters**: Generates detailed machine-readable JSON files and clean, responsive, offline HTML dashboards.

---

## Setup & Installation

### 1. Prerequisites
- Python 3.8 or higher.
- A free **NVD API Key** is highly recommended. You can request one [here](https://nvd.nist.gov/developers/request-an-api-key) to avoid strict rate-limiting.

### 2. Installation
Clone or download the project files and install the dependencies:

```bash
# Install required dependencies
pip install -r requirements.txt
```

---

## Usage Guide

The tool is invoked via `vigilscan.py`. Run `python vigilscan.py --help` to view all parameters.

```bash
usage: vigilscan.py [-h] [-p PORTS] [-sT] [-sS] [-Pn] [--open]
                    [--packet-trace] [-sV] [-sn] [-F] [-v] [-O] [-A]
                    [-T {1,2,3,4,5}] [-th THREADS] [-to TIMEOUT]
                    [-oA OUTPUT_ALL] [-oJ JSON] [-oH HTML]
                    target

Risk-Scoring Port Scanner - A security audit tool that scans ports, detects services, matches NVD CVEs, and scores host risk.

positional arguments:
  target                Target hostname or IP address to scan (e.g., '127.0.0.1', 'scanme.nmap.org')

options:
  -h, --help            show this help message and exit
  -p PORTS              Ports to scan (default: 'top1000', or 'top100' if -F is specified). Options:
                          - 'top100': scans 100 most common TCP ports
                          - 'top1000': scans 1000 common TCP ports (well-known 1-1024 + selected high)
                          - Nmap-style: list (e.g. '22,80,443'), ranges ('1-1024', '80-', '-80'), or '-' for all ports
  -sT                   TCP Connect Scan (default behavior)
  -sS                   Stealth SYN Scan (requires root/admin privileges)
  -Pn                   Skip host discovery - assume all target hosts are online
  --open                Only display open and confirmed ports in reports
  --packet-trace        Enable diagnostic packet/socket trace output
  -sV                   Enable service version detection and NVD vulnerability audit
  -sn                   Ping scan - Host discovery only (skip port scan)
  -F                    Fast scan - scan the top 100 ports instead of top 1000
  -v, --verbose         Verbose mode - specify multiple times for more verbosity:
                          -v:   Print open ports as they are discovered
                          -vv:  Print open/closed ports and enable connection packet tracing
                          -vvv: Print open/closed/filtered ports, trace connections, and log detailed NVD API endpoints/caching details
  -O                    OS detection - guess target OS based on TTL and version banners
  -A                    Aggressive scan template - enable OS detection (-O), service version detection (-sV),
                        web app fingerprinter (script scan), and automatically set verbosity to level 1 (or higher)
  -T {1,2,3,4,5}        Timing template (1-5) for automatic performance tuning (default: 4)
                          - 1: Sneaky (1 thread, 5.0s timeout)
                          - 2: Polite (5 threads, 3.0s timeout)
                          - 3: Normal (30 threads, 1.5s timeout)
                          - 4: Aggressive (100 threads, 1.0s timeout)
                          - 5: Insane (200 threads, 0.5s timeout)
  -th, --threads THREADS
                        Number of concurrent scanning threads (Overrides -T)
  -to, --timeout TIMEOUT
                        Timeout in seconds for port connections (Overrides -T)
  -oA OUTPUT_ALL        Export reports in ALL formats (JSON & HTML) using the specified prefix
  -oJ JSON              Export report in JSON format to the specified filepath
  -oH HTML              Export report in HTML format to the specified filepath
```

### Command Examples

#### 1. Basic Scan (Top 100 Ports)
Scans the top 100 most common ports of localhost and outputs results directly to the console:
```bash
python vigilscan.py 127.0.0.1 -F
```

#### 2. Specific Port Range with Insane Speed (-T5)
Scans ports 1 through 1024 with timing template 5 (200 threads, 0.5s timeout):
```bash
python vigilscan.py 192.168.1.1 -p 1-1024 -T 5
```

#### 3. Custom Nmap-style Port Ranges
Scan a specific range or all ports:
```bash
# Scan ports from 80 to 65535
python vigilscan.py 192.168.1.1 -p 80-

# Scan all ports (1 to 65535)
python vigilscan.py 192.168.1.1 -p -
```

#### 4. Environment-based NVD API Scan
If you have an NVD API Key, you can add it to a `.env` file in the project directory:
```env
NVD_API_KEY=YOUR_NVD_API_KEY
```
Then run the scanner normally. It will automatically load the key and query NVD with higher rate limits:
```bash
python vigilscan.py scanme.nmap.org -p top1000 -oA scanme_report
```
*(If no API key is set in environment or `.env`, the scanner automatically limits request speed or transitions to a fast offline cache-only fallback mode if it detects consecutive outages).*

---

## Host Risk Scoring Model

The overall host risk score $R$ (ranging from $0.0$ to $10.0$) is calculated using the following formula:

$$R = \min\left(10.0, S_{max} + 0.1 \times \sum_{i \neq max} S_i + \min(1.0, 0.05 \times N_{open\_clean})\right)$$

### Key Components:
1. **Baseline Severity ($S_{max}$)**: The highest CVSS score found among all services on the target. If the most vulnerable port has a CVSS score of 8.5, this sets the host's baseline risk.
2. **Compounding Vulnerability Factor ($0.1 \times \sum S_i$)**: A target with multiple vulnerable services is easier to breach than one with a single vulnerability. We sum the maximum CVSS score of each other vulnerable port and multiply by 10% to represent this compounding threat.
3. **Attack Surface Penalty ($0.05 \times N_{open\_clean}$)**: Every open port is an entry point. Even if no known CVEs are found (due to missing banners or unvulnerable software), open ports increase risk. We add 0.05 per clean open port (capped at 1.0) to represent this exposure.

*For example, a host with a high-severity vulnerability (CVSS 8.0) and two medium-severity vulnerabilities (CVSS 6.0 and 5.0) on other ports, alongside 2 clean open ports, receives a score of: `min(10.0, 8.0 + 0.1*(6.0 + 5.0) + (0.05 * 2)) = min(10.0, 8.0 + 1.1 + 0.1) = 9.2 (Critical)`.*

---

## Ethical Disclosure & Responsible Use

> [!WARNING]
> This port scanner is a powerful network auditing tool. You must **only** run scans against systems and networks that you own or have explicit, written authorization to test. 
> Unauthorized port scanning can disrupt network services, trigger intrusion detection alerts, and may be illegal under local cybersecurity laws (such as the US Computer Fraud and Abuse Act or the UK Computer Misuse Act).
> The authors and developers of this tool assume no liability for misuse or damage caused by this utility.

---

## Automated Testing

To verify the core NVD API client logic, rate limits, backoff retry handling, and SQLite caching without relying on live network connectivity to NIST servers, you can run the mock server test:

```bash
python test_nvd_mock.py
```

This script:
1. Spawns a local HTTP server in a background thread.
2. Intercepts the client's queries.
3. Simulates a `503 Service Unavailable` error on the first query to verify that the NVDClient triggers its exponential backoff and retry loop.
4. Returns a mock vulnerability response on the retry.
5. Performs a second query to confirm that the SQLite cache handles the result locally without hitting the server again.

