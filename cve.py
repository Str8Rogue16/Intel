"""
cve.py - Intel Project
=======================
Module: CVE Lookup by Software Version + New CVE Notification System

Sub-modules:
    - SoftwareInventory:  Enumerates installed software versions from the OS.
    - CVELookup:          Queries NVD API for known CVEs per software/version.
    - CVENotifier:        Compares results against a local cache and fires
                          notifications for any newly discovered CVEs via
                          Email, Slack, Discord, and/or log file.

Dependencies:
    pip install psutil rich requests

API Reference:
    NVD API v2: https://nvd.nist.gov/developers/vulnerabilities
    Rate limits: 5 req/30s (no key) | 50 req/30s (with API key)
    Get a free API key: https://nvd.nist.gov/developers/request-an-api-key

Author: Intel Project
Platform: macOS / Linux

Changelog:
    v1.0 - Initial scaffold with NVD API v2 integration
         - Software inventory via OS package managers and psutil
         - CVE severity filtering (all severities supported)
         - Notification channels: Email, Slack, Discord, log file
         - Local JSON cache to detect and alert on NEW CVEs only
         - On-demand trigger mode
"""

import json
import logging
import os
import platform
import smtplib
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Load environment variables from .env file in project root.
# NOTE: .env must never be committed to version control — see .gitignore.
load_dotenv()

console = Console()

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
# NOTE: All secrets (API keys, passwords, webhook URLs) load from the .env
# file via os.getenv() — never hardcode credentials directly here.
# Non-secret settings (toggles, thresholds, paths) remain plain constants
# since they aren't sensitive and are easier to manage as code.
# After filling in .env values, set the matching _ENABLED flag to True below.

# --- NVD API ---
# Get a free key at https://nvd.nist.gov/developers/request-an-api-key
# Without a key: 5 requests per 30 seconds.
# With a key:   50 requests per 30 seconds.
# .env key: NVD_API_KEY=your-key-here
NVD_API_KEY: Optional[str] = os.getenv("NVD_API_KEY")
NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- Severity Filter ---
# All CVEs are returned regardless of severity. Adjust MIN_CVSS_SCORE to
# filter notifications only. Set to 0.0 to notify on all severities.
# CVSS scale: 0.0 None | 0.1-3.9 Low | 4.0-6.9 Medium | 7.0-8.9 High | 9.0-10.0 Critical
MIN_CVSS_SCORE: float = 0.0

# --- Cache ---
# Local JSON file storing previously seen CVE IDs per software package.
# Used to detect NEW CVEs and avoid duplicate notifications.
# NOTE: Adjust path as needed for your project structure.
CACHE_FILE: Path = Path("data/cve_cache.json")

# --- Log File ---
# Set to None to disable file logging.
LOG_FILE: Optional[Path] = Path("output/reports/cve.log")

# --- Email (SMTP) ---
# NOTE: For Gmail, use an App Password, not your account password.
# https://support.google.com/accounts/answer/185833
# .env keys: EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECIPIENTS (comma-separated)
EMAIL_ENABLED: bool = False
EMAIL_SMTP_HOST: str = "smtp.gmail.com"
EMAIL_SMTP_PORT: int = 587
EMAIL_SENDER: str = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD: str = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECIPIENTS: list[str] = [
    addr.strip() for addr in os.getenv("EMAIL_RECIPIENTS", "").split(",") if addr.strip()
]

# --- Slack ---
# Create an Incoming Webhook in your Slack workspace:
# https://api.slack.com/messaging/webhooks
# .env key: SLACK_WEBHOOK_URL
SLACK_ENABLED: bool = False
SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")

# --- Discord ---
# Create a Webhook in your Discord channel:
# Server Settings → Integrations → Webhooks → New Webhook → Copy URL
# .env key: DISCORD_WEBHOOK_URL
DISCORD_ENABLED: bool = False
DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")


# ---------------------------------------------------------------------------
# LOGGING SETUP
# ---------------------------------------------------------------------------

def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("intel.cve")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    # Console handler (rich handles its own output separately)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler
    if LOG_FILE:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(LOG_FILE)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger

logger = _setup_logger()


# ---------------------------------------------------------------------------
# DATA STRUCTURES
# ---------------------------------------------------------------------------

@dataclass
class SoftwareEntry:
    """Represents a single installed software package and its version."""
    name: str
    version: str
    source: str     # "brew" | "dpkg" | "rpm" | "python" | "manual"


@dataclass
class CVEEntry:
    """Represents a single CVE result from the NVD API."""
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_severity: Optional[str]   # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    published: str
    last_modified: str
    url: str
    software_name: str
    software_version: str
    is_new: bool = False           # True if not seen in previous scan cache


@dataclass
class CVEScanResult:
    """Aggregated result of a full CVE scan run."""
    scanned_at: str
    software_scanned: list[SoftwareEntry]
    cves_found: list[CVEEntry]
    new_cves: list[CVEEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SUB-MODULE A: SOFTWARE INVENTORY
# ---------------------------------------------------------------------------

class SoftwareInventory:
    """
    Enumerates installed software from the OS using available package managers.

    Supported sources:
        - macOS: Homebrew (brew list --versions)
        - Linux: dpkg (Debian/Ubuntu), rpm (RHEL/CentOS/Fedora)
        - Cross-platform: Python packages via pip (optional)
        - Manual: Hardcoded entries in MANUAL_SOFTWARE below

    NOTE: Add entries to MANUAL_SOFTWARE for software not managed by a
    package manager (e.g. custom builds, downloaded binaries).
    """

    # NOTE: Add software here that your package manager won't catch.
    # Format: ("software_name", "version")
    MANUAL_SOFTWARE: list[tuple[str, str]] = [
        # ("nginx", "1.25.3"),
        # ("openssl", "3.1.4"),
    ]

    def collect(self) -> list[SoftwareEntry]:
        """Collect software inventory from all available sources."""
        entries: list[SoftwareEntry] = []
        system = platform.system()

        if system == "Darwin":
            entries.extend(self._from_brew())
        elif system == "Linux":
            entries.extend(self._from_dpkg())
            entries.extend(self._from_rpm())

        # NOTE: Uncomment the line below to include Python packages.
        # Be aware this can generate a large number of NVD API calls.
        # entries.extend(self._from_pip())

        for name, version in self.MANUAL_SOFTWARE:
            entries.append(SoftwareEntry(name=name, version=version, source="manual"))

        console.print(f"[dim]Software inventory: {len(entries)} packages found.[/dim]")
        return entries

    def _from_brew(self) -> list[SoftwareEntry]:
        """Enumerate Homebrew packages on macOS."""
        entries = []
        try:
            result = subprocess.run(
                ["brew", "list", "--versions"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[-1]  # Use last version if multiple listed
                    entries.append(SoftwareEntry(name=name, version=version, source="brew"))
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Homebrew inventory failed: {e}")
        return entries

    def _from_dpkg(self) -> list[SoftwareEntry]:
        """Enumerate installed packages on Debian/Ubuntu via dpkg."""
        entries = []
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    entries.append(SoftwareEntry(
                        name=parts[0], version=parts[1], source="dpkg"
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"dpkg inventory failed: {e}")
        return entries

    def _from_rpm(self) -> list[SoftwareEntry]:
        """Enumerate installed packages on RHEL/CentOS/Fedora via rpm."""
        entries = []
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    entries.append(SoftwareEntry(
                        name=parts[0], version=parts[1], source="rpm"
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"rpm inventory failed: {e}")
        return entries

    def _from_pip(self) -> list[SoftwareEntry]:
        """Enumerate installed Python packages via pip."""
        entries = []
        try:
            result = subprocess.run(
                ["pip", "list", "--format=freeze"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().splitlines():
                if "==" in line:
                    name, version = line.split("==", 1)
                    entries.append(SoftwareEntry(
                        name=name.strip(), version=version.strip(), source="python"
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"pip inventory failed: {e}")
        return entries


# ---------------------------------------------------------------------------
# SUB-MODULE B: CVE LOOKUP
# ---------------------------------------------------------------------------

class CVELookup:
    """
    Queries the NVD API v2 for CVEs matching a software name and version.
    Automatically falls back to OSV (Open Source Vulnerabilities) if NVD is unavailable.

    Primary:  NVD API v2 — https://nvd.nist.gov/developers/vulnerabilities
    Fallback: OSV (Open Source Vulnerabilities) — https://api.osv.dev/v1/query
              Run by Google. Better version matching. No API key. No rate limit.

    Rate limits (NVD):
        No key:  5 requests / 30s  (REQUEST_DELAY = 6.1s)
        With key: 50 requests / 30s (REQUEST_DELAY = 0.7s)

    Usage:
        lookup = CVELookup()
        cves = lookup.query(SoftwareEntry(name="openssl", version="3.1.4", source="brew"))
    """

    # NVD rate limit delay — see note above
    REQUEST_DELAY: float = 6.1 if not NVD_API_KEY else 0.7
    MAX_RETRIES: int = 3
    RESULTS_PER_PAGE: int = 20  # NOTE: Max 2000 per NVD docs, 20 is safe for home lab


    def __init__(self):
        self._headers = {}
        if NVD_API_KEY:
            self._headers["apiKey"] = NVD_API_KEY

    def query(self, software: SoftwareEntry) -> list[CVEEntry]:
        """
        Query NVD for CVEs. Falls back to OSV automatically when unavailable.
        Returns a list of CVEEntry objects filtered by MIN_CVSS_SCORE.
        """
        cves = self._query_nvd(software)
        if cves is None:
            # NVD unavailable — try OSV
            console.print(
                f"[yellow]  ↳ NVD unavailable. Falling back to OSV for "
                f"{software.name}...[/yellow]"
            )
            cves = self._query_osv(software)

        return cves if cves is not None else []

    def _query_nvd(self, software: SoftwareEntry) -> Optional[list[CVEEntry]]:
        """
        Query NVD API v2. Returns list of CVEEntry on success, None when
        NVD is unavailable (5xx, timeout, or connection error) to trigger
        fallback. Retries on 429 rate limit only.
        """
        params = {
            "keywordSearch": f"{software.name} {software.version}".strip(),
            "resultsPerPage": self.RESULTS_PER_PAGE,
        }

        for attempt in range(self.MAX_RETRIES):
            try:
                time.sleep(self.REQUEST_DELAY)
                response = requests.get(
                    NVD_BASE_URL,
                    headers=self._headers,
                    params=params,
                    timeout=8,  # Short timeout — fail fast and fall back to OSV
                )

                if response.status_code == 429:
                    wait = 30 * (attempt + 1)
                    console.print(f"[yellow]NVD rate limit hit. Waiting {wait}s...[/yellow]")
                    time.sleep(wait)
                    continue

                if response.status_code >= 500:
                    logger.warning(
                        f"NVD returned {response.status_code} for "
                        f"{software.name} {software.version}. Will try OSV."
                    )
                    return None

                response.raise_for_status()
                return self._parse_nvd_response(response.json(), software)

            except (requests.ConnectionError, requests.Timeout):
                # Timeout or connection failure — go straight to fallback,
                # do not retry. NVD is clearly unavailable right now.
                logger.warning(
                    f"NVD unreachable for {software.name} "
                    f"(attempt {attempt + 1}). Will try OSV."
                )
                return None

            except requests.RequestException as e:
                logger.error(
                    f"NVD API error for {software.name} {software.version}: {e}"
                )
                if attempt == self.MAX_RETRIES - 1:
                    return None

        return None

    def _query_osv(self, software: SoftwareEntry) -> Optional[list[CVEEntry]]:
        """
        Query OSV (Open Source Vulnerabilities) as a fallback when NVD is down.

        OSV is run by Google and offers better version matching than other sources.
        No API key required. No rate limit for reasonable use.
        API docs: https://google.github.io/osv.dev/api/

        Endpoint: POST https://api.osv.dev/v1/query
        Payload:  { "version": "x.y.z", "package": { "name": "pkg", "ecosystem": "..." } }

        NOTE: OSV uses ecosystem identifiers (PyPI, npm, Go, etc.). For system
        packages without a known ecosystem, we query by version + name only
        which searches across all ecosystems. Results are best-effort for
        packages outside OSV's indexed ecosystems (e.g. raw C libraries).
        """
        OSV_URL = "https://api.osv.dev/v1/query"

        # Map common package sources to OSV ecosystem identifiers
        # NOTE: Extend this map as you add more package sources to Intel.
        ECOSYSTEM_MAP: dict[str, str] = {
            "python": "PyPI",
            "brew":   "",     # Homebrew not an OSV ecosystem — query without ecosystem
            "dpkg":   "",     # Debian packages — query without ecosystem
            "rpm":    "",     # RPM packages — query without ecosystem
            "manual": "",
        }

        ecosystem = ECOSYSTEM_MAP.get(software.source, "")

        payload: dict = {"version": software.version}
        if ecosystem:
            payload["package"] = {"name": software.name, "ecosystem": ecosystem}
        else:
            # No ecosystem — OSV will search across all
            payload["package"] = {"name": software.name}

        try:
            response = requests.post(
                OSV_URL,
                json=payload,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (Intel Security Tool)"}
            )

            if response.status_code == 404 or response.status_code == 400:
                # Package not found in OSV — not an error, just no data
                return []

            if response.status_code >= 500:
                logger.warning(f"OSV returned {response.status_code} for {software.name}.")
                return []

            response.raise_for_status()
            return self._parse_osv_response(response.json(), software)

        except (requests.ConnectionError, requests.Timeout) as e:
            logger.error(f"OSV fallback also failed for {software.name}: {e}")
            return []
        except requests.RequestException as e:
            logger.error(f"OSV error for {software.name}: {e}")
            return []

    def _parse_nvd_response(
        self, data: dict, software: SoftwareEntry
    ) -> list[CVEEntry]:
        """Parse NVD API v2 JSON response into CVEEntry objects."""
        entries = []

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "UNKNOWN")

            # Extract English description
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available."
            )

            # Extract CVSS score — prefer v3.1, fall back to v3.0, then v2
            cvss_score = None
            cvss_severity = None
            metrics = cve_data.get("metrics", {})

            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                    break

            if cvss_score is not None and cvss_score < MIN_CVSS_SCORE:
                continue

            entries.append(CVEEntry(
                cve_id=cve_id,
                description=description[:300] + "..." if len(description) > 300 else description,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                published=cve_data.get("published", ""),
                last_modified=cve_data.get("lastModified", ""),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                software_name=software.name,
                software_version=software.version,
            ))

        return entries

    def _parse_osv_response(
        self, data: dict, software: SoftwareEntry
    ) -> list[CVEEntry]:
        """
        Parse OSV API v1 query response into CVEEntry objects.

        OSV response structure:
        {
          "vulns": [
            {
              "id": "GHSA-xxxx" or "CVE-xxxx",
              "summary": "...",
              "details": "...",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}],
              "published": "2024-01-01T00:00:00Z",
              "modified":  "2024-01-02T00:00:00Z",
              "aliases":   ["CVE-2024-XXXX"],  # canonical CVE ID if OSV ID is GHSA
            }
          ]
        }

        NOTE: OSV IDs may be GHSA (GitHub Advisory) format. We prefer the
        CVE alias when available for consistency with NVD results.
        CVSS score is extracted from the severity vector string via cvss library
        if present, otherwise left as None.
        """
        entries = []
        vulns = data.get("vulns", [])

        for item in vulns[:self.RESULTS_PER_PAGE]:
            # Prefer CVE ID from aliases over OSV/GHSA native ID
            osv_id = item.get("id", "UNKNOWN")
            aliases = item.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)

            description = item.get("summary") or item.get("details", "No description available.")
            published = item.get("published", "")
            last_modified = item.get("modified", "")

            # Extract CVSS score from severity vector string if present.
            # OSV severity format: [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}]
            # NOTE: Full CVSS vector parsing requires the `cvss` library.
            # We extract the base score from the vector string directly to
            # avoid adding a dependency. Install `pip install cvss` for full
            # vector parsing if needed in future.
            cvss_score = None
            cvss_severity = None
            for sev in item.get("severity", []):
                score_str = sev.get("score", "")
                # CVSS v3 vectors encode base score in the string after parsing;
                # OSV also provides database_specific.severity in some records
                pass

            # Fallback: check database_specific block (GitHub advisories include this)
            db_specific = item.get("database_specific", {})
            raw_severity = db_specific.get("severity", "")  # "HIGH", "CRITICAL", etc.
            if raw_severity:
                cvss_severity = raw_severity.upper()
                # Map severity label to approximate midpoint score for filtering
                severity_score_map = {
                    "CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0
                }
                cvss_score = severity_score_map.get(cvss_severity)

            if cvss_score is not None and cvss_score < MIN_CVSS_SCORE:
                continue

            # Build NVD detail URL if we have a CVE ID, else link to OSV
            if cve_id.startswith("CVE-"):
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            else:
                url = f"https://osv.dev/vulnerability/{osv_id}"

            entries.append(CVEEntry(
                cve_id=cve_id,
                description=description[:300] + "..." if len(description) > 300 else description,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                published=published,
                last_modified=last_modified,
                url=url,
                software_name=software.name,
                software_version=software.version,
            ))

        return entries

    def scan_all(
        self, software_list: list[SoftwareEntry], errors: list[str]
    ) -> list[CVEEntry]:
        """
        Run CVE queries for all software in the inventory.
        Logs progress and collects errors without stopping the full scan.
        """
        all_cves: list[CVEEntry] = []
        total = len(software_list)

        for i, software in enumerate(software_list, 1):
            console.print(
                f"[dim]Querying: [{i}/{total}] {software.name} {software.version}[/dim]"
            )
            try:
                cves = self.query(software)
                all_cves.extend(cves)
                if cves:
                    console.print(
                        f"[cyan]  → {len(cves)} CVE(s) found for "
                        f"{software.name} {software.version}[/cyan]"
                    )
            except Exception as e:
                msg = f"Unexpected error querying {software.name}: {e}"
                logger.error(msg)
                errors.append(msg)

        return all_cves



# ---------------------------------------------------------------------------
# SUB-MODULE C: CVE CACHE
# ---------------------------------------------------------------------------

class CVECache:
    """
    Persists previously seen CVE IDs to a local JSON file.
    Used to identify NEW CVEs that weren't present in the last scan.

    Cache format:
    {
        "software_name==version": ["CVE-2024-XXXX", "CVE-2024-YYYY"],
        ...
    }

    NOTE: Cache is stored at CACHE_FILE (configurable at top of file).
    Delete the cache file to treat all CVEs as new on next run.
    """

    def __init__(self):
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, list[str]] = self._load()

    def _load(self) -> dict[str, list[str]]:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Cache load failed, starting fresh: {e}")
        return {}

    def _save(self) -> None:
        with open(CACHE_FILE, "w") as f:
            json.dump(self._cache, f, indent=2)

    def _key(self, cve: CVEEntry) -> str:
        return f"{cve.software_name}=={cve.software_version}"

    def mark_new(self, cves: list[CVEEntry]) -> list[CVEEntry]:
        """
        Compare CVEs against cache. Mark and return only NEW entries.
        Updates the cache with all current CVE IDs after comparison.
        """
        new_cves: list[CVEEntry] = []

        for cve in cves:
            key = self._key(cve)
            seen_ids = self._cache.get(key, [])
            if cve.cve_id not in seen_ids:
                cve.is_new = True
                new_cves.append(cve)

        # Update cache with all current CVE IDs
        for cve in cves:
            key = self._key(cve)
            if key not in self._cache:
                self._cache[key] = []
            if cve.cve_id not in self._cache[key]:
                self._cache[key].append(cve.cve_id)

        self._save()
        return new_cves


# ---------------------------------------------------------------------------
# SUB-MODULE D: NOTIFIER
# ---------------------------------------------------------------------------

class CVENotifier:
    """
    Sends notifications for newly discovered CVEs via configured channels.

    Channels (configure at top of file):
        - Email (SMTP)
        - Slack (Incoming Webhook)
        - Discord (Webhook)
        - Log file (always active if LOG_FILE is set)

    Usage:
        notifier = CVENotifier()
        notifier.notify(new_cves)
    """

    def notify(self, new_cves: list[CVEEntry]) -> None:
        """Dispatch notifications to all enabled channels."""
        if not new_cves:
            console.print("[green]✓ No new CVEs to notify.[/green]")
            return

        console.print(
            f"[bold yellow]⚠ {len(new_cves)} new CVE(s) detected — dispatching notifications...[/bold yellow]"
        )

        # Log file is always attempted if configured
        self._notify_log(new_cves)

        if EMAIL_ENABLED and EMAIL_SENDER and EMAIL_RECIPIENTS:
            self._notify_email(new_cves)
        elif EMAIL_ENABLED:
            logger.warning("Email enabled but EMAIL_SENDER or EMAIL_RECIPIENTS not configured.")

        if SLACK_ENABLED and SLACK_WEBHOOK_URL:
            self._notify_slack(new_cves)
        elif SLACK_ENABLED:
            logger.warning("Slack enabled but SLACK_WEBHOOK_URL not configured.")

        if DISCORD_ENABLED and DISCORD_WEBHOOK_URL:
            self._notify_discord(new_cves)
        elif DISCORD_ENABLED:
            logger.warning("Discord enabled but DISCORD_WEBHOOK_URL not configured.")

    def _format_summary(self, new_cves: list[CVEEntry]) -> str:
        """Build a plain-text summary of new CVEs for notifications."""
        lines = [
            f"Intel Security Alert — {len(new_cves)} New CVE(s) Detected",
            f"Scanned at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "-" * 60,
        ]
        for cve in new_cves:
            score = f"CVSS {cve.cvss_score} ({cve.cvss_severity})" if cve.cvss_score else "No CVSS score"
            lines.append(
                f"\n{cve.cve_id} | {cve.software_name} {cve.software_version} | {score}"
            )
            lines.append(f"  {cve.description}")
            lines.append(f"  Details: {cve.url}")
        return "\n".join(lines)

    def _notify_log(self, new_cves: list[CVEEntry]) -> None:
        """Write new CVEs to the log file."""
        for cve in new_cves:
            score = f"CVSS {cve.cvss_score}" if cve.cvss_score else "no score"
            logger.info(
                f"NEW CVE: {cve.cve_id} | {cve.software_name} {cve.software_version} "
                f"| {score} | {cve.url}"
            )

    def _notify_email(self, new_cves: list[CVEEntry]) -> None:
        """Send new CVE alert via SMTP email."""
        try:
            subject = f"[Intel] {len(new_cves)} New CVE(s) Detected"
            body = self._format_summary(new_cves)

            msg = MIMEMultipart()
            msg["From"] = EMAIL_SENDER
            msg["To"] = ", ".join(EMAIL_RECIPIENTS)
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT) as server:
                server.starttls()
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENTS, msg.as_string())

            console.print(f"[green]✓ Email alert sent to {EMAIL_RECIPIENTS}[/green]")
            logger.info(f"Email alert sent to {EMAIL_RECIPIENTS}")

        except smtplib.SMTPException as e:
            console.print(f"[red]✗ Email failed: {e}[/red]")
            logger.error(f"Email notification failed: {e}")

    def _notify_slack(self, new_cves: list[CVEEntry]) -> None:
        """Post new CVE alert to Slack via Incoming Webhook."""
        try:
            # Build Slack blocks for clean formatting
            # NOTE: Extend blocks here for richer Slack formatting if needed.
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"⚠ Intel: {len(new_cves)} New CVE(s) Detected"
                    }
                },
                {"type": "divider"},
            ]

            for cve in new_cves:
                score = f"CVSS {cve.cvss_score} ({cve.cvss_severity})" if cve.cvss_score else "No score"
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*<{cve.url}|{cve.cve_id}>* | "
                            f"`{cve.software_name} {cve.software_version}` | {score}\n"
                            f"{cve.description}"
                        )
                    }
                })
                blocks.append({"type": "divider"})

            payload = {"blocks": blocks}
            response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
            console.print("[green]✓ Slack alert sent.[/green]")
            logger.info("Slack notification sent.")

        except requests.RequestException as e:
            console.print(f"[red]✗ Slack failed: {e}[/red]")
            logger.error(f"Slack notification failed: {e}")

    def _notify_discord(self, new_cves: list[CVEEntry]) -> None:
        """Post new CVE alert to Discord via Webhook."""
        try:
            # Discord webhook payload uses embeds for formatted output.
            # NOTE: Discord has a 2000 char limit per message and 25 embed limit.
            # If you scan many packages, this may need pagination.
            embeds = []
            for cve in new_cves[:25]:  # Discord max 25 embeds per message
                score = f"CVSS {cve.cvss_score} ({cve.cvss_severity})" if cve.cvss_score else "No score"
                color = self._discord_color(cve.cvss_score)
                embeds.append({
                    "title": cve.cve_id,
                    "url": cve.url,
                    "description": cve.description,
                    "color": color,
                    "fields": [
                        {"name": "Software", "value": f"{cve.software_name} {cve.software_version}", "inline": True},
                        {"name": "Severity", "value": score, "inline": True},
                        {"name": "Published", "value": cve.published[:10], "inline": True},
                    ]
                })

            payload = {
                "content": f"⚠ **Intel Security Alert** — {len(new_cves)} new CVE(s) detected",
                "embeds": embeds,
            }
            response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
            console.print("[green]✓ Discord alert sent.[/green]")
            logger.info("Discord notification sent.")

        except requests.RequestException as e:
            console.print(f"[red]✗ Discord failed: {e}[/red]")
            logger.error(f"Discord notification failed: {e}")

    @staticmethod
    def _discord_color(cvss_score: Optional[float]) -> int:
        """Map CVSS score to Discord embed color (decimal RGB)."""
        if cvss_score is None:
            return 0x95a5a6   # Grey
        if cvss_score >= 9.0:
            return 0xe74c3c   # Red — Critical
        if cvss_score >= 7.0:
            return 0xe67e22   # Orange — High
        if cvss_score >= 4.0:
            return 0xf1c40f   # Yellow — Medium
        return 0x2ecc71       # Green — Low


# ---------------------------------------------------------------------------
# ORCHESTRATOR
# ---------------------------------------------------------------------------

class CVEScanner:
    """
    Top-level orchestrator that ties together inventory, lookup, cache, and
    notification into a single scan run.

    Usage:
        scanner = CVEScanner()
        result = scanner.run()
        scanner.display(result)

    NOTE: Integration point for main.py — call scanner.run() and pass
    result.new_cves to your chatbot context for natural language summarization.
    """

    def __init__(self):
        self.inventory = SoftwareInventory()
        self.lookup = CVELookup()
        self.cache = CVECache()
        self.notifier = CVENotifier()

    def run(self) -> CVEScanResult:
        """Execute a full CVE scan: inventory → lookup → cache diff → notify."""
        scanned_at = datetime.now().isoformat()
        errors: list[str] = []

        console.rule("[bold]CVE Scan — Software Inventory[/bold]")
        software_list = self.inventory.collect()

        if not software_list:
            console.print("[yellow]No software found in inventory. Check MANUAL_SOFTWARE or package manager access.[/yellow]")

        console.rule("[bold]CVE Scan — NVD Lookup[/bold]")
        all_cves = self.lookup.scan_all(software_list, errors)

        console.rule("[bold]CVE Scan — New CVE Detection[/bold]")
        new_cves = self.cache.mark_new(all_cves)

        if new_cves:
            console.print(f"[bold red]⚠ {len(new_cves)} new CVE(s) since last scan.[/bold red]")
        else:
            console.print("[green]✓ No new CVEs since last scan.[/green]")

        self.notifier.notify(new_cves)

        result = CVEScanResult(
            scanned_at=scanned_at,
            software_scanned=software_list,
            cves_found=all_cves,
            new_cves=new_cves,
            errors=errors,
        )
        return result

    def display(self, result: CVEScanResult) -> None:
        """Render full scan results to terminal."""
        console.rule("[bold]CVE Scan Results[/bold]")

        if not result.cves_found:
            console.print("[green]✓ No CVEs found for scanned software.[/green]")
            return

        table = Table(
            title=f"CVEs Found ({len(result.cves_found)} total | "
                  f"[red]{len(result.new_cves)} new[/red])",
            show_lines=True,
        )
        table.add_column("CVE ID", style="cyan")
        table.add_column("Software")
        table.add_column("CVSS")
        table.add_column("Severity")
        table.add_column("New?")
        table.add_column("Description")

        for cve in result.cves_found:
            severity_color = {
                "CRITICAL": "bold red",
                "HIGH":     "red",
                "MEDIUM":   "yellow",
                "LOW":      "green",
            }.get(cve.cvss_severity or "", "white")

            table.add_row(
                cve.cve_id,
                f"{cve.software_name} {cve.software_version}",
                str(cve.cvss_score) if cve.cvss_score else "-",
                f"[{severity_color}]{cve.cvss_severity or 'N/A'}[/{severity_color}]",
                "[bold red]YES[/bold red]" if cve.is_new else "no",
                cve.description[:80] + "..." if len(cve.description) > 80 else cve.description,
            )

        console.print(table)

        if result.errors:
            console.print(f"\n[yellow]Errors during scan ({len(result.errors)}):[/yellow]")
            for err in result.errors:
                console.print(f"  [dim]{err}[/dim]")

    def to_dict(self, result: CVEScanResult) -> dict:
        """
        Serialize scan results for JSON export or chatbot ingestion.

        NOTE: Integration point for main.py and your chatbot.
        Pass result["new_cves"] as context for natural language summarization.
        """
        return {
            "scanned_at": result.scanned_at,
            "software_count": len(result.software_scanned),
            "cves_found": len(result.cves_found),
            "new_cves_count": len(result.new_cves),
            "new_cves": [
                {
                    "cve_id": c.cve_id,
                    "software": f"{c.software_name} {c.software_version}",
                    "cvss_score": c.cvss_score,
                    "cvss_severity": c.cvss_severity,
                    "description": c.description,
                    "url": c.url,
                    "published": c.published,
                }
                for c in result.new_cves
            ],
            "all_cves": [
                {
                    "cve_id": c.cve_id,
                    "software": f"{c.software_name} {c.software_version}",
                    "cvss_score": c.cvss_score,
                    "cvss_severity": c.cvss_severity,
                    "description": c.description,
                    "url": c.url,
                    "is_new": c.is_new,
                }
                for c in result.cves_found
            ],
            "errors": result.errors,
        }


# ---------------------------------------------------------------------------
# STANDALONE RUNNER
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json as jsonlib

    parser = argparse.ArgumentParser(description="Intel - CVE Module")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (for chatbot/pipeline integration)",
    )
    parser.add_argument(
        "--software",
        nargs=2,
        metavar=("NAME", "VERSION"),
        help="Query a single software package instead of full inventory scan. "
             "Example: --software openssl 3.1.4",
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Delete the local CVE cache before running (treat all CVEs as new)",
    )
    args = parser.parse_args()

    if args.clear_cache and CACHE_FILE.exists():
        CACHE_FILE.unlink()
        console.print("[yellow]Cache cleared. All CVEs will be treated as new.[/yellow]")

    scanner = CVEScanner()

    if args.software:
        # Single software query mode
        name, version = args.software
        console.rule(f"[bold]CVE Lookup: {name} {version}[/bold]")
        entry = SoftwareEntry(name=name, version=version, source="manual")
        errors: list[str] = []
        cves = scanner.lookup.scan_all([entry], errors)
        new_cves = scanner.cache.mark_new(cves)
        scanner.notifier.notify(new_cves)

        result = CVEScanResult(
            scanned_at=datetime.now().isoformat(),
            software_scanned=[entry],
            cves_found=cves,
            new_cves=new_cves,
            errors=errors,
        )
    else:
        # Full inventory scan mode
        result = scanner.run()

    if args.json:
        print(jsonlib.dumps(scanner.to_dict(result), indent=2))
    else:
        scanner.display(result)
