# Intel

A modular, Python-based endpoint security toolkit for home lab and internal network monitoring. Intel inspects running services, flags risky network exposure, and cross-references installed software against known CVEs — with built-in notification support so findings can reach sysadmins automatically.

> **Status:** Active development. Currently includes the Network Auditor and CVE Lookup modules. See [Roadmap](#roadmap) for what's next.

---

## Why Intel

Most endpoint security tooling is either expensive commercial EDR software or scattered one-off scripts. Intel aims for something in between: a single, readable Python codebase that a home lab or small team can run, understand, and extend — without a SaaS subscription or a black box.

---

## Features

### Network Auditor (`network.py`)
- **Port & Service Mapper** — enumerates every listening port and active connection, maps each to its owning process, and flags anything outside a configurable allowlist
- **High-risk port detection** — flags known attacker-favored ports (Telnet, SMB, Metasploit defaults, common C2 ports) regardless of which process owns them
- **Connection Anomaly Detector** — observes traffic over a configurable window and flags:
  - Abnormally high upload ratios (potential data exfiltration)
  - Beaconing patterns — regular, low-jitter connection intervals typical of C2 check-ins
- Cross-platform handling for macOS permission quirks (graceful fallback when `sudo` isn't used)

### CVE Lookup (`cve.py`)
- **Software inventory** — enumerates installed packages via Homebrew (macOS), `dpkg`/`rpm` (Linux), with support for manually tracked software
- **CVE matching** — queries the [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) for known vulnerabilities, with automatic fallback to [OSV](https://osv.dev/) (Google's Open Source Vulnerabilities database) if NVD is unavailable
- **New CVE detection** — caches previously seen CVE IDs locally and only alerts on genuinely new findings, so notifications don't repeat on every scan
- **Multi-channel notifications** — Email (SMTP), Slack, and Discord webhooks, all individually toggleable, plus persistent log file output

---

## Project Structure

```
intel/
├── network.py             # Port & service auditor, connection anomaly detector
├── cve.py                 # Software inventory, CVE lookup, notification system
├── main.py                # (planned) Unified entry point tying all modules together
├── .env                    # Your secrets — never committed (see .gitignore)
├── .env.example             # Template showing required environment variables
├── .gitignore
├── requirements.txt
├── data/
│   └── cve_cache.json     # Local cache of previously seen CVE IDs (auto-generated)
└── output/
    └── reports/
        └── cve.log         # Persistent CVE scan log (auto-generated)
```

---

## Installation

### Requirements
- Python 3.9+
- macOS or Linux

### Setup

```bash
git clone https://github.com/<your-username>/intel.git
cd intel

pip install -r requirements.txt
```

### Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in whichever values apply to you. All fields are optional — Intel runs fine with none of them set, but the CVE module performs better with an NVD API key, and notification channels require their respective credentials.

```env
# NVD API — free key at https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# Email (SMTP) — use an App Password for Gmail, not your account password
EMAIL_SENDER=
EMAIL_PASSWORD=
EMAIL_RECIPIENTS=

# Slack — Incoming Webhook URL
SLACK_WEBHOOK_URL=

# Discord — Webhook URL
DISCORD_WEBHOOK_URL=
```

After filling in a channel's credentials, flip its corresponding `_ENABLED` flag to `True` near the top of `cve.py`. This two-step design means a webhook sitting in `.env` won't start firing notifications until you intentionally enable it.

---

## Usage

### Network Auditor

```bash
# Scan ports and flag anything outside the allowlist
python network.py --mode ports

# Show all connections, including clean ones
python network.py --mode ports --all-ports

# Run anomaly detection over a 60-second window (default)
python network.py --mode anomaly

# Custom observation window
python network.py --mode anomaly --duration 120

# Run both, output as JSON (for piping into other tools)
python network.py --mode all --json
```

> **Note (macOS):** Full connection visibility requires elevated privileges. Run with `sudo python network.py --mode ports` for complete results; without it, Intel falls back to per-process enumeration and may miss some connections.

### CVE Lookup

```bash
# Full system inventory scan
python cve.py

# Query a single package
python cve.py --software openssl 3.1.4

# Output as JSON
python cve.py --software nginx 1.18.0 --json

# Clear the local cache (treats all CVEs as new on next run — useful for testing notifications)
python cve.py --clear-cache
```

---

## Configuration Reference

Most tunable values live as named constants near the top of each module, with inline `NOTE:` comments explaining intent and safe ranges. Key ones to review before your first run:

| File | Setting | Purpose |
|---|---|---|
| `network.py` | `ALLOWED_PORTS` | Known-good port → process mappings for your environment |
| `network.py` | `HIGH_RISK_PORTS` | Ports flagged regardless of owning process |
| `network.py` | `EPHEMERAL_PORT_RANGE` | OS-assigned dynamic ports excluded from flagging |
| `network.py` | `UPLOAD_RATIO_THRESHOLD` | Outbound traffic ratio that triggers an exfiltration flag |
| `network.py` | `BEACON_INTERVAL_TOLERANCE` | Jitter tolerance for beaconing detection |
| `cve.py` | `MIN_CVSS_SCORE` | Minimum severity score to include in results |
| `cve.py` | `MANUAL_SOFTWARE` | Software not tracked by a package manager |

---

## Data Sources

- **NVD (National Vulnerability Database)** — primary CVE source. [API docs](https://nvd.nist.gov/developers/vulnerabilities)
- **OSV (Open Source Vulnerabilities)** — automatic fallback when NVD is unavailable. [API docs](https://google.github.io/osv.dev/api/)

---

## Roadmap

- [ ] `main.py` — unified CLI entry point tying all modules together
- [ ] Process Monitor — flag processes running from unusual locations
- [ ] File Integrity Monitor — baseline and diff critical directories
- [ ] Persistence/startup checker — autorun and scheduled task auditing
- [ ] Severity scoring engine across all modules
- [ ] Chatbot integration layer for natural-language scan summaries

---

## Disclaimer

Intel is built for personal home lab and internal monitoring use. It is not a substitute for commercial-grade EDR/SIEM tooling in production or enterprise environments. Review and tune all thresholds and allowlists for your specific environment before relying on its output.

---

## License

This project is licensed under the [MIT License](LICENSE) — see the `LICENSE` file for full terms.
