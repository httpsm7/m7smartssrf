# m7smartssrf 🔭
**Smart SSRF Discovery & Exploitation Framework**
By: Sharlix | Milkyway Intelligence | httpsm7

> ⚠️ **For authorized penetration testing and bug bounty use only.**
> Do not use on systems without explicit written permission.

---

## Features

| Module | Description |
|--------|-------------|
| Input Engine | Bulk URLs, Burp requests, normalization, deduplication |
| Param Extractor | Extract existing params from URLs |
| Param Bruteforce | 30+ SSRF-prone hidden params with priority scoring |
| Payload Engine | Internal, cloud metadata, encoded, obfuscated payloads |
| Protocol Fuzzer | 25+ protocols (gopher, ftp, dict, ldap, smb, file...) |
| Header Injector | X-Forwarded-Host, X-Original-URL, X-Host and 20+ headers |
| OOB Engine | Interactsh integration (no API key required) |
| Response Analyzer | Status/size diff, keyword match, time-based detection |
| Exploit Engine | AWS/GCP/Azure metadata chaining, localhost service enum |
| Bypass Engine | IP encoding, hex, octal, case variation, URL confusion |
| Redirect Chain | Follow 30x chains to detect internal redirect SSRF |
| Report Generator | JSON + CSV + TXT structured reports |
| Session Manager | Resume interrupted scans |
| Request Cache | Skip duplicate requests automatically |

---

## Install

```bash
git clone https://github.com/httpsm7/m7smartssrf
cd m7smartssrf
chmod +x install.sh
./install.sh
```

---

## Usage

```bash
# Basic scan
m7smartssrf scan urls.txt

# Fast mode with OOB detection
m7smartssrf scan urls.txt --oob --threads 50

# Deep mode with all bypasses
m7smartssrf scan urls.txt --mode deep --bypass all

# Stealth mode with proxy
m7smartssrf scan urls.txt --mode stealth --proxy http://127.0.0.1:8080

# Authenticated scanning
m7smartssrf scan urls.txt --cookies "session=abc123" --auth "Bearer token123"

# Custom payloads
m7smartssrf scan urls.txt --payloads payloads/ssrf_payloads.txt

# Resume interrupted scan
m7smartssrf scan urls.txt --resume logs/scan.session --save-session

# Use config file
m7smartssrf scan urls.txt --config config/config.yaml

# Header injection only
m7smartssrf scan urls.txt --headers-only

# Specific protocols only
m7smartssrf scan urls.txt --protocols gopher,ftp,dict

# Replay a request
m7smartssrf scan urls.txt --replay 42
```

---

## Scan Modes

| Mode | Threads | Payloads | Protocols | Use Case |
|------|---------|----------|-----------|----------|
| fast | 30 | Core only | No | Quick recon |
| deep | 10 | All | Yes | Full assessment |
| stealth | 5 | Core+obf | No | WAF bypass |

---

## Output

Reports saved to `reports/` directory:
- `report.json` - Full structured JSON
- `report.txt` - Human-readable text
- `report.csv` - Spreadsheet-ready CSV

---

## Project Structure

```
m7smartssrf/
├── m7smartssrf.py          # Main CLI entry
├── install.sh              # One-click installer
├── config/
│   └── config.yaml         # Default config
├── core/
│   ├── banner.py           # ASCII banner
│   ├── config.py           # Config loader
│   └── scanner.py          # Main orchestrator
├── engines/
│   ├── input_engine.py     # URL loading/normalization
│   ├── param_extractor.py  # Param extraction
│   ├── param_bruteforce.py # Hidden param fuzzing
│   ├── payload_engine.py   # Payload generation
│   ├── protocol_fuzzer.py  # Protocol fuzzing
│   ├── header_injector.py  # Header injection
│   ├── request_engine.py   # Async HTTP engine
│   ├── response_analyzer.py# Response analysis
│   ├── oob_engine.py       # OOB/Interactsh
│   ├── exploit_engine.py   # Exploitation chains
│   ├── bypass_engine.py    # Filter bypass
│   ├── redirect_chain.py   # Redirect following
│   └── replay.py           # Request replay
├── modules/
│   └── report_generator.py # Report output
├── utils/
│   ├── logger.py           # Colored logging
│   ├── cache.py            # Request dedup cache
│   └── session.py          # Resume sessions
└── payloads/
    └── ssrf_payloads.txt   # Custom payload list
```

---

## Legal

This tool is for **authorized security testing only**.
The author (Sharlix / Milkyway Intelligence) is not responsible for misuse.
