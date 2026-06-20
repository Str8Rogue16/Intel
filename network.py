"""
network.py - Intel Project
===========================
Module: Open Port & Service Auditor + Connection Anomaly Detector

Sub-modules:
    - PortMapper:      Enumerates listening ports, maps to owning processes,
                       and flags entries outside a configurable allowlist.
    - AnomalyDetector: Baselines per-connection traffic and flags:
                        * Abnormal upload ratios (potential exfiltration)
                        * Beaconing patterns (regular intervals to same remote IP)

Dependencies:
    pip install psutil rich requests
    (requests is used only for fetching known-vendor IP ranges — see
    KNOWN_VENDOR_CIDRS section. Import is local to that function so the
    rest of network.py has no hard dependency on it.)

Author: Intel Project
Platform: macOS / Linux (psutil handles cross-platform differences)

Changelog:
    v1.1 - Fixed duplicate entries from dual-stack (IPv4/IPv6) sockets
         - Added ephemeral port skipping to reduce false positive noise
         - Fixed raddr.ip AttributeError in AnomalyDetector._collect_snapshot
         - Added macOS system services (kdc, postgres) to default ALLOWED_PORTS
    v1.2 - Fixed AttributeError on conn.pid in macOS sudo-less fallback path
         - Added presence-ratio filter to beaconing detection (excludes
           continuously-open connections like browser tabs, sync clients)
         - Retuned beaconing defaults after real-world testing showed false
           positives on nearly every long-lived connection at 60s/5s window:
           window raised to 300s/15s, CV tolerance tightened to 0.08,
           min samples raised to 8, presence ratio cap lowered to 0.75
         - Downgraded BEACONING severity from HIGH to MEDIUM to reflect that
           this is a coarse polling heuristic, not a confirmed-malicious signal
    v1.3 - Added KNOWN_VENDOR_CIDRS allowlist to suppress beaconing flags from
           confirmed legitimate cloud infrastructure (Microsoft, Google).
           Identified via WHOIS during real-world testing — see config block
           comment for sourcing notes and update guidance.
"""

import ipaddress
import json
import time
import statistics
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil
from rich.console import Console
from rich.table import Table

console = Console()

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
# NOTE: Modify ALLOWED_PORTS to match your environment's known-good services.
# Format: { port: "expected_process_name" }
# Set value to None to allow any process on that port.

ALLOWED_PORTS: dict[int, Optional[str]] = {
    22:   "sshd",         # SSH
    80:   "nginx",        # HTTP  -- modify to match your web server
    443:  "nginx",        # HTTPS -- modify to match your web server
    53:   None,           # DNS   -- any process allowed
    3389: "TermService",  # RDP   -- flag if unexpected in your lab
    # macOS system services
    88:   "kdc",          # Kerberos KDC -- built-in macOS auth service
    5432: "postgres",     # PostgreSQL   -- remove if not running locally
}

# Ephemeral/dynamic port range — assigned by OS, not persistent listeners.
# NOTE: Ports in this range are skipped during flagging to reduce noise from
# short-lived IPC sockets (VS Code plugins, Python scripts, etc.).
# macOS default: 49152–65535 | Linux default: 32768–60999
# Adjust if your OS uses a different range.
EPHEMERAL_PORT_RANGE: range = range(49152, 65536)

# Ports considered high-risk regardless of process.
# NOTE: 445 (SMB) is intentionally kept here. If you use macOS File Sharing,
# either add it to ALLOWED_PORTS or disable File Sharing in System Settings.
HIGH_RISK_PORTS: set[int] = {
    23,    # Telnet
    445,   # SMB -- disable macOS File Sharing if this fires unexpectedly
    1080,  # SOCKS proxy
    4444,  # Metasploit default
    5555,  # Android ADB / common C2
    6666,  # Common C2
    8888,  # Common C2 / alt HTTP
    9001,  # Tor relay default
    31337, # Elite/Back Orifice legacy
}

# Anomaly detection thresholds.
# NOTE: Tune these based on your lab's normal traffic patterns.
UPLOAD_RATIO_THRESHOLD: float = 0.85    # Flag if >85% of traffic is outbound

# Beaconing detection — these defaults were retuned after real-world testing
# showed the original 60s/5s window flagged nearly every long-lived connection
# (browsers, Slack, iCloud, push notification services all re-poll every few
# seconds as normal behavior, which looks identical to fixed-interval C2
# beaconing at coarse resolution). A longer window with fewer, sparser samples
# gives the CV calculation more room to separate "structurally fixed interval"
# from "happens to be active most of the time."
BEACON_INTERVAL_TOLERANCE: float = 0.08   # Tightened from 0.15 — stricter regularity required
BEACON_MIN_SAMPLES: int = 8               # Raised from 5 — needs sustained pattern, not a few polls
# Connections present in >= this fraction of total polls are treated as
# continuously-open (browser tabs, sync clients, IDE servers) and excluded
# from beaconing detection. Lower this to catch slower beacon intervals;
# raise it if legitimate long-lived connections are still being excluded.
BEACON_PRESENCE_RATIO_MAX: float = 0.75   # Lowered from 0.9 — excludes "mostly present" too
SAMPLE_INTERVAL_SECONDS: int = 15         # Raised from 5 — reduces normal-chatter noise
SAMPLE_DURATION_SECONDS: int = 300        # Raised from 60 — 5 min window, ~20 samples per IP

# NOTE ON LIMITATIONS: Even with these tighter defaults, this is a coarse,
# poll-based heuristic, not a real intrusion detection signal. Actual C2
# beacon intervals are often deliberately randomized (jitter) specifically to
# evade interval-regularity detection like this. A BEACONING flag here means
# "worth a manual look," not "confirmed malicious." For production-grade
# beacon detection, dedicated tools (Zeek, RITA, Suricata) analyze raw packet
# timing at a level psutil's polling approach cannot reach.

# --- Known Cloud Vendor Suppression List ---
# Background services from major cloud providers (push notifications, sync
# clients, telemetry) check in on fixed timers as normal behavior, which
# triggers BEACONING false positives at the same rate as real C2 traffic.
# IPs/ranges matched here are excluded from beaconing detection entirely
# rather than relying on jitter alone to tell them apart.
#
# IMPORTANT — WHY THIS FETCHES INSTEAD OF HARDCODING:
# An earlier version of this filter hand-picked a handful of CIDR blocks from
# memory. Real-world testing immediately found a gap: 4.249.131.160 (confirmed
# Microsoft via WHOIS) wasn't covered by any guessed range. Cloud providers'
# real IP space is enormous and changes regularly — Microsoft's own official
# download is sometimes out of date even on Microsoft's side. Hand-picking
# ranges from memory was never going to keep pace, so this now pulls from the
# vendors' own published, machine-readable sources instead:
#   Microsoft (Azure Service Tags): https://www.microsoft.com/en-us/download/details.aspx?id=56519
#   Google:                          https://www.gstatic.com/ipranges/goog.json
# Results are cached locally (VENDOR_RANGE_CACHE) since these files are large
# and don't change minute-to-minute. Delete the cache file to force a refresh.
VENDOR_RANGE_CACHE: Path = Path("data/vendor_ip_ranges.json")
VENDOR_RANGE_CACHE_MAX_AGE_DAYS: int = 30  # Re-fetch if cache is older than this

# Google's range file has a stable, predictable URL.
GOOGLE_IP_RANGES_URL: str = "https://www.gstatic.com/ipranges/goog.json"

# NOTE: Microsoft's Azure Service Tags JSON is published behind a download
# page with a versioned filename that changes on every release (e.g.
# ServiceTags_Public_20260615.json), so it can't be fetched from a single
# stable URL the way Google's can. Options to keep this current:
#   1. Manually check https://www.microsoft.com/en-us/download/details.aspx?id=56519
#      periodically, download the current JSON, and place it at the path below.
#   2. Use a community-maintained mirror such as:
#      https://github.com/femueller/cloud-ip-ranges (microsoft-azure-ip-ranges.json)
#      — NOT an official Microsoft source; verify before trusting in production.
# Until a file exists at this path, Microsoft ranges are simply skipped (the
# filter degrades gracefully rather than failing).
MICROSOFT_RANGES_LOCAL_PATH: Optional[Path] = Path("data/microsoft-azure-ip-ranges.json")

_vendor_networks_cache: Optional[list] = None  # populated lazily by _load_vendor_networks()


def _load_vendor_networks() -> list:
    """
    Load known-vendor IP networks from cache, fetching fresh data if the
    cache is missing or stale. Returns a list of ipaddress network objects.

    NOTE: Network/connectivity failures here are non-fatal — the filter
    simply returns whatever was loaded (possibly empty), and beaconing
    detection proceeds without vendor suppression rather than crashing.
    """
    global _vendor_networks_cache
    if _vendor_networks_cache is not None:
        return _vendor_networks_cache

    networks: list = []
    cidrs: list[str] = []

    # Try loading from local cache first.
    cache_is_fresh = False
    if VENDOR_RANGE_CACHE.exists():
        age_days = (time.time() - VENDOR_RANGE_CACHE.stat().st_mtime) / 86400
        cache_is_fresh = age_days < VENDOR_RANGE_CACHE_MAX_AGE_DAYS
        if cache_is_fresh:
            try:
                with open(VENDOR_RANGE_CACHE) as f:
                    cidrs = json.load(f)
            except (json.JSONDecodeError, OSError):
                cache_is_fresh = False  # Corrupt cache — re-fetch below

    if not cache_is_fresh:
        cidrs = _fetch_vendor_ranges()
        if cidrs:
            try:
                VENDOR_RANGE_CACHE.parent.mkdir(parents=True, exist_ok=True)
                with open(VENDOR_RANGE_CACHE, "w") as f:
                    json.dump(cidrs, f)
            except OSError:
                pass  # Cache write failure is non-fatal

    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr))
        except ValueError:
            continue  # Skip malformed entries rather than crashing

    _vendor_networks_cache = networks
    return networks


def _fetch_vendor_ranges() -> list[str]:
    """
    Fetch current vendor IP ranges from official/community sources.
    Returns a flat list of CIDR strings. Failures are logged and skipped
    per-source rather than aborting the whole fetch.
    """
    import requests  # Local import — network.py has no other hard dependency on requests

    all_cidrs: list[str] = []

    # --- Google ---
    try:
        resp = requests.get(GOOGLE_IP_RANGES_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        for prefix in data.get("prefixes", []):
            cidr = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
            if cidr:
                all_cidrs.append(cidr)
        console.print(f"[dim]Fetched {len(all_cidrs)} Google IP ranges.[/dim]")
    except requests.RequestException as e:
        logger_module_print(f"[yellow]Could not fetch Google IP ranges: {e}[/yellow]")

    # --- Microsoft (local file only — see MICROSOFT_RANGES_LOCAL_PATH note) ---
    if MICROSOFT_RANGES_LOCAL_PATH and MICROSOFT_RANGES_LOCAL_PATH.exists():
        try:
            with open(MICROSOFT_RANGES_LOCAL_PATH) as f:
                ms_data = json.load(f)
            ms_count = 0
            for value in ms_data.get("values", []):
                props = value.get("properties", {})
                for cidr in props.get("addressPrefixes", []):
                    all_cidrs.append(cidr)
                    ms_count += 1
            console.print(f"[dim]Loaded {ms_count} Microsoft IP ranges from local file.[/dim]")
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger_module_print(f"[yellow]Could not parse Microsoft ranges file: {e}[/yellow]")
    else:
        console.print(
            "[dim]No local Microsoft IP ranges file found — Microsoft IPs won't be "
            "suppressed in beaconing detection. See MICROSOFT_RANGES_LOCAL_PATH "
            "comment for how to add one.[/dim]"
        )

    return all_cidrs


def logger_module_print(message: str) -> None:
    """Small helper so this module doesn't need a hard logging dependency."""
    console.print(message)


def _is_known_vendor_ip(ip_str: str) -> bool:
    """
    Check whether an IP falls within a known cloud vendor's CIDR range.
    Returns False (not suppressed) for malformed IPs or when no vendor
    ranges are loaded, since this is a best-effort filter, not a critical path.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for network_obj in _load_vendor_networks():
        if ip_obj in network_obj:
            return True

    return False


# ---------------------------------------------------------------------------
# DATA STRUCTURES
# ---------------------------------------------------------------------------

@dataclass
class PortEntry:
    """Represents a single listening or established connection."""
    local_address: str
    local_port: int
    remote_address: Optional[str]
    remote_port: Optional[int]
    status: str
    pid: Optional[int]
    process_name: Optional[str]
    process_path: Optional[str]
    flagged: bool = False
    flag_reason: str = ""


@dataclass
class ConnectionSnapshot:
    """A single traffic sample for a connection, used in anomaly detection."""
    timestamp: float
    remote_ip: str
    bytes_sent: int
    bytes_recv: int


@dataclass
class AnomalyResult:
    """Result from anomaly detection analysis."""
    remote_ip: str
    finding_type: str   # "HIGH_UPLOAD_RATIO" | "BEACONING"
    detail: str
    severity: str       # "LOW" | "MEDIUM" | "HIGH"
    snapshots: list[ConnectionSnapshot] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _ip(addr) -> str:
    """
    Safely extract IP string from a psutil address object or plain string.
    psutil returns named tuples from net_connections() but plain strings
    from per-process fallback on macOS. Handle both formats.
    """
    if not addr:
        return ""
    return addr.ip if hasattr(addr, "ip") else str(addr)


def _port(addr) -> Optional[int]:
    """Safely extract port int from a psutil address object or plain string."""
    if not addr:
        return None
    return addr.port if hasattr(addr, "port") else None


# ---------------------------------------------------------------------------
# SUB-MODULE A: PORT MAPPER
# ---------------------------------------------------------------------------

class PortMapper:
    """
    Enumerates all listening ports and active connections.
    Maps each entry to the owning process and checks against the allowlist
    and high-risk port list.

    Usage:
        mapper = PortMapper()
        results = mapper.scan()
        mapper.display(results)
    """

    def scan(self) -> list[PortEntry]:
        """
        Perform a full port scan of the local system.
        Returns a deduplicated list of PortEntry objects, flagged entries included.

        NOTE: On macOS, psutil.net_connections(kind="all") requires root/sudo
        to inspect all PIDs. Without elevated privileges, falls back to
        per-process enumeration and skips connections it cannot access.
        Run with `sudo python network.py --mode ports` for complete results.
        """
        entries: list[PortEntry] = []

        # Build a pid -> process info map once to avoid repeated lookups.
        process_map: dict[int, psutil.Process] = {}
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                process_map[proc.pid] = proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # macOS requires elevated privileges for net_connections(kind="all").
        # Fall back to per-process enumeration if system-wide call is denied.
        connections = []
        try:
            connections = psutil.net_connections(kind="all")
        except psutil.AccessDenied:
            console.print(
                "[yellow]⚠ Warning: Insufficient privileges for full connection scan.[/yellow]\n"
                "[dim]  Falling back to per-process enumeration. Some connections may be missing.\n"
                "  Run with sudo for complete results.[/dim]\n"
            )
            # NOTE: proc.net_connections() returns pconn objects WITHOUT a
            # .pid attribute (unlike the system-wide call, which includes it
            # on every connection). Since we already know which proc each
            # connection came from here, we tag it manually so downstream
            # code can treat both code paths identically.
            for proc in process_map.values():
                try:
                    for conn in proc.net_connections(kind="all"):
                        conn_with_pid = conn._replace(pid=proc.pid) if hasattr(conn, "_replace") else conn
                        connections.append(conn_with_pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        for conn in connections:
            local_addr = _ip(conn.laddr)
            local_port = _port(conn.laddr) or 0
            remote_addr = _ip(conn.raddr) or None
            remote_port = _port(conn.raddr)

            # Resolve process info from the pre-built map.
            # NOTE: getattr() used defensively in case a future psutil version
            # or platform returns a connection object without a pid field.
            pid = getattr(conn, "pid", None)
            proc_name = None
            proc_path = None
            if pid and pid in process_map:
                try:
                    proc_name = process_map[pid].info.get("name")
                    proc_path = process_map[pid].info.get("exe")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            entry = PortEntry(
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                status=conn.status,
                pid=pid,
                process_name=proc_name,
                process_path=proc_path,
            )

            self._apply_flags(entry)
            entries.append(entry)

        # Deduplicate on (pid, local_port, status) to collapse dual-stack
        # IPv4/IPv6 duplicates that appear when a service binds to both.
        seen: set[tuple] = set()
        deduped: list[PortEntry] = []
        for e in entries:
            key = (e.pid, e.local_port, e.status)
            if key not in seen:
                seen.add(key)
                deduped.append(e)

        return deduped

    def _apply_flags(self, entry: PortEntry) -> None:
        """
        Apply flagging logic to a PortEntry in-place.

        Flag conditions (checked in priority order):
            1. Port is in EPHEMERAL_PORT_RANGE  -> skip (no flag)
            2. Port is in HIGH_RISK_PORTS       -> HIGH_RISK_PORT
            3. Port is in ALLOWED_PORTS but process doesn't match -> PROCESS_MISMATCH
            4. Port is LISTENING and not in ALLOWED_PORTS -> UNLISTED_LISTENER
        """
        port = entry.local_port

        # Condition 1: Skip ephemeral ports — OS-assigned, not persistent listeners.
        if port in EPHEMERAL_PORT_RANGE:
            return

        # Condition 2: High-risk port regardless of process.
        if port in HIGH_RISK_PORTS:
            entry.flagged = True
            entry.flag_reason = f"HIGH_RISK_PORT: port {port} is on the high-risk list"
            return

        # Condition 3: Port is allowed but owned by unexpected process.
        if port in ALLOWED_PORTS:
            expected_proc = ALLOWED_PORTS[port]
            if expected_proc is not None and entry.process_name != expected_proc:
                entry.flagged = True
                entry.flag_reason = (
                    f"PROCESS_MISMATCH: expected '{expected_proc}' on port {port}, "
                    f"found '{entry.process_name}'"
                )
            return

        # Condition 4: Unlisted listener on a non-ephemeral port.
        if entry.status == "LISTEN":
            entry.flagged = True
            entry.flag_reason = f"UNLISTED_LISTENER: port {port} is not in the allowlist"

    def display(self, entries: list[PortEntry]) -> None:
        """Render scan results to the terminal using rich tables."""
        flagged = [e for e in entries if e.flagged]
        clean = [e for e in entries if not e.flagged]

        if flagged:
            flag_table = Table(
                title=f"[bold red]⚠ Flagged Entries ({len(flagged)})[/bold red]",
                show_lines=True,
            )
            flag_table.add_column("Port", style="red")
            flag_table.add_column("Status")
            flag_table.add_column("Process")
            flag_table.add_column("PID")
            flag_table.add_column("Remote")
            flag_table.add_column("Reason", style="yellow")

            for e in flagged:
                remote = f"{e.remote_address}:{e.remote_port}" if e.remote_address else "-"
                flag_table.add_row(
                    str(e.local_port),
                    e.status or "-",
                    e.process_name or "unknown",
                    str(e.pid) if e.pid else "-",
                    remote,
                    e.flag_reason,
                )
            console.print(flag_table)
        else:
            console.print("[bold green]✓ No flagged port entries.[/bold green]")

        console.print(f"\n[dim]Clean connections: {len(clean)} (not displayed by default)[/dim]")
        # NOTE: To display clean entries, call display_all(entries).

    def display_all(self, entries: list[PortEntry]) -> None:
        """Render ALL connections including clean ones. Useful for full audits."""
        table = Table(title="All Connections", show_lines=True)
        table.add_column("Port")
        table.add_column("Status")
        table.add_column("Process")
        table.add_column("PID")
        table.add_column("Remote")
        table.add_column("Flag")

        for e in entries:
            flag_col = f"[red]{e.flag_reason}[/red]" if e.flagged else "[green]OK[/green]"
            remote = f"{e.remote_address}:{e.remote_port}" if e.remote_address else "-"
            table.add_row(
                str(e.local_port),
                e.status or "-",
                e.process_name or "unknown",
                str(e.pid) if e.pid else "-",
                remote,
                flag_col,
            )
        console.print(table)

    def to_dict(self, entries: list[PortEntry]) -> list[dict]:
        """
        Serialize results to a list of dicts for JSON export or chatbot ingestion.

        NOTE: Integration point for your chatbot module.
        Feed this output as context for natural language summarization.
        """
        return [
            {
                "local_port": e.local_port,
                "local_address": e.local_address,
                "remote_address": e.remote_address,
                "remote_port": e.remote_port,
                "status": e.status,
                "pid": e.pid,
                "process_name": e.process_name,
                "process_path": e.process_path,
                "flagged": e.flagged,
                "flag_reason": e.flag_reason,
            }
            for e in entries
        ]


# ---------------------------------------------------------------------------
# SUB-MODULE B: CONNECTION ANOMALY DETECTOR
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Observes active network connections over a configurable time window
    and flags:
        - High upload ratio connections (potential data exfiltration)
        - Beaconing patterns (periodic connections to the same remote IP)

    Usage:
        detector = AnomalyDetector()
        results = detector.run()
        detector.display(results)
    """

    def run(
        self,
        duration: int = SAMPLE_DURATION_SECONDS,
        interval: int = SAMPLE_INTERVAL_SECONDS,
    ) -> list[AnomalyResult]:
        """
        Collect traffic snapshots over `duration` seconds, sampling every
        `interval` seconds. Returns a list of AnomalyResult objects.
        """
        console.print(
            f"[bold cyan]AnomalyDetector:[/bold cyan] Observing for {duration}s "
            f"(sampling every {interval}s)..."
        )

        # remote_ip -> list of ConnectionSnapshot
        history: dict[str, list[ConnectionSnapshot]] = defaultdict(list)

        total_polls = 0
        start = time.time()
        while time.time() - start < duration:
            self._collect_snapshot(history)
            total_polls += 1
            time.sleep(interval)

        return self._analyze(history, total_polls)

    def _collect_snapshot(
        self, history: dict[str, list[ConnectionSnapshot]]
    ) -> None:
        """
        Take a single traffic sample.

        IMPORTANT — KNOWN LIMITATION (read before trusting beaconing alerts):
        psutil only exposes SYSTEM-WIDE byte counters via net_io_counters(),
        not per-connection byte counts, without root-level packet inspection
        (which would require something like pcap/eBPF, well beyond psutil).

        Because of this, bytes_sent/bytes_recv on each ConnectionSnapshot are
        SYSTEM-WIDE totals at the time of the poll, not bytes for that specific
        remote IP. The HIGH_UPLOAD_RATIO check inherits this same limitation —
        it reflects your whole machine's traffic shape, not a single
        connection's. Treat upload-ratio flags as "the machine as a whole is
        upload-heavy right now," not "this specific IP is exfiltrating data."

        Beaconing detection, however, is now corrected to NOT depend on byte
        counters at all. A snapshot is only recorded for a remote IP when that
        connection is actually observed to exist in this poll. The interval
        between snapshots is the real time between sightings, not the fixed
        polling loop timer. An IP that's continuously connected for the whole
        observation window will look "present every poll," which still isn't
        true beaconing — see the min-gap filter in _check_beaconing for how
        that case is excluded.

        For genuine per-connection traffic accounting, this would need to be
        rebuilt on raw packet capture (e.g. scapy or pyshark) rather than psutil.
        """
        try:
            timestamp = time.time()
            counters = psutil.net_io_counters(pernic=False)

            # Track which remote IPs are observed THIS poll, to support a
            # "currently connected" check in beaconing analysis later.
            seen_this_poll: set[str] = set()

            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr:
                    continue

                remote_ip = _ip(conn.raddr)
                if not remote_ip:
                    continue

                seen_this_poll.add(remote_ip)

                snapshot = ConnectionSnapshot(
                    timestamp=timestamp,
                    remote_ip=remote_ip,
                    # NOTE: system-wide totals — see docstring above.
                    bytes_sent=counters.bytes_sent,
                    bytes_recv=counters.bytes_recv,
                )
                history[remote_ip].append(snapshot)

        except (psutil.AccessDenied, PermissionError):
            console.print("[yellow]Warning: Insufficient permissions for some connections.[/yellow]")

    def _analyze(
        self, history: dict[str, list[ConnectionSnapshot]], total_polls: int
    ) -> list[AnomalyResult]:
        """Run all anomaly checks against collected history."""
        results: list[AnomalyResult] = []

        for remote_ip, snapshots in history.items():
            if len(snapshots) < 2:
                continue

            upload_result = self._check_upload_ratio(remote_ip, snapshots)
            if upload_result:
                results.append(upload_result)

            beacon_result = self._check_beaconing(remote_ip, snapshots, total_polls)
            if beacon_result:
                results.append(beacon_result)

        return results

    def _check_upload_ratio(
        self, remote_ip: str, snapshots: list[ConnectionSnapshot]
    ) -> Optional[AnomalyResult]:
        """
        Flag connections where outbound traffic exceeds UPLOAD_RATIO_THRESHOLD
        of total traffic. Indicative of data exfiltration.

        CAVEAT: bytes_sent/recv are SYSTEM-WIDE counters (see _collect_snapshot
        docstring), not specific to this remote IP. This effectively answers
        "was my machine upload-heavy while this IP was connected?" rather than
        "did this IP receive a lot of uploaded data?" Treat results as a
        machine-wide signal, not conclusive evidence against a single host.
        Genuine per-connection byte accounting requires packet capture
        (e.g. scapy/pyshark), which is a larger undertaking than psutil supports.
        """
        first, last = snapshots[0], snapshots[-1]
        delta_sent = last.bytes_sent - first.bytes_sent
        delta_recv = last.bytes_recv - first.bytes_recv
        total = delta_sent + delta_recv

        if total == 0:
            return None

        ratio = delta_sent / total
        if ratio >= UPLOAD_RATIO_THRESHOLD:
            return AnomalyResult(
                remote_ip=remote_ip,
                finding_type="HIGH_UPLOAD_RATIO",
                detail=(
                    f"Upload ratio: {ratio:.1%} "
                    f"(sent={delta_sent}B, recv={delta_recv}B) "
                    f"[system-wide total, not IP-specific]"
                ),
                severity="HIGH",
                snapshots=snapshots,
            )
        return None

    def _check_beaconing(
        self,
        remote_ip: str,
        snapshots: list[ConnectionSnapshot],
        total_polls: int,
    ) -> Optional[AnomalyResult]:
        """
        Flag connections that appear at suspiciously regular intervals.
        Beaconing is a hallmark of C2 (Command & Control) implants that
        check in with a remote server on a fixed timer.

        Method: compute intervals between snapshots, check coefficient of
        variation (CV = stdev/mean). Low CV = highly regular = suspicious.

        FALSE-POSITIVE FILTER: a connection that's simply held open for the
        entire observation window (browser tab, IDE language server, Spotify,
        iCloud sync) will ALSO show up every poll with near-zero jitter — this
        looks identical to beaconing under interval-regularity alone. True
        beaconing is a pattern of repeated short connect/disconnect cycles at
        a fixed cadence, not one continuously-held socket.

        Since psutil can't distinguish "still the same open socket" from
        "reconnected," we approximate the distinction with a presence ratio:
        if this IP was seen in nearly every single poll across the whole
        observation window (>= BEACON_PRESENCE_RATIO_MAX), it's treated as a
        long-lived connection and excluded — not flagged as beaconing.
        This trades some detection sensitivity for far fewer false positives,
        which is the right tradeoff for a home lab tool. Tune
        BEACON_PRESENCE_RATIO_MAX if you want it stricter or looser.

        KNOWN-VENDOR FILTER: IPs in KNOWN_VENDOR_CIDRS (Microsoft, Google,
        etc.) are excluded before any interval math runs. Real-world testing
        showed these vendors' background services (push notifications, sync,
        telemetry) check in on fixed timers as standard behavior, which is
        indistinguishable from beaconing by CV alone. See KNOWN_VENDOR_CIDRS
        comment block for sourcing and update guidance.
        """
        if _is_known_vendor_ip(remote_ip):
            return None

        if len(snapshots) < BEACON_MIN_SAMPLES:
            return None

        # Presence-ratio filter — exclude continuously-open connections.
        presence_ratio = len(snapshots) / total_polls if total_polls > 0 else 0
        if presence_ratio >= BEACON_PRESENCE_RATIO_MAX:
            return None

        timestamps = [s.timestamp for s in snapshots]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        if not intervals:
            return None

        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return None

        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = stdev / mean_interval  # Coefficient of variation

        if cv <= BEACON_INTERVAL_TOLERANCE:
            return AnomalyResult(
                remote_ip=remote_ip,
                finding_type="BEACONING",
                detail=(
                    f"Regular interval detected: mean={mean_interval:.1f}s, "
                    f"stdev={stdev:.2f}s, CV={cv:.3f} (threshold={BEACON_INTERVAL_TOLERANCE}) "
                    f"[heuristic — worth a manual look, not confirmed malicious]"
                ),
                severity="MEDIUM",
                snapshots=snapshots,
            )
        return None

    def display(self, results: list[AnomalyResult]) -> None:
        """Render anomaly results to terminal."""
        if not results:
            console.print("[bold green]✓ No anomalies detected.[/bold green]")
            return

        table = Table(
            title=f"[bold red]⚠ Anomalies Detected ({len(results)})[/bold red]",
            show_lines=True,
        )
        table.add_column("Remote IP", style="red")
        table.add_column("Type", style="yellow")
        table.add_column("Severity", style="bold")
        table.add_column("Detail")

        for r in results:
            severity_color = "red" if r.severity == "HIGH" else "yellow"
            table.add_row(
                r.remote_ip,
                r.finding_type,
                f"[{severity_color}]{r.severity}[/{severity_color}]",
                r.detail,
            )
        console.print(table)

    def to_dict(self, results: list[AnomalyResult]) -> list[dict]:
        """
        Serialize anomaly results for JSON export or chatbot ingestion.

        NOTE: Integration point for your chatbot — pass this list as context
        for the model to summarize and explain findings in plain language.
        """
        return [
            {
                "remote_ip": r.remote_ip,
                "finding_type": r.finding_type,
                "severity": r.severity,
                "detail": r.detail,
                "sample_count": len(r.snapshots),
                "first_seen": datetime.fromtimestamp(r.snapshots[0].timestamp).isoformat()
                if r.snapshots else None,
                "last_seen": datetime.fromtimestamp(r.snapshots[-1].timestamp).isoformat()
                if r.snapshots else None,
            }
            for r in results
        ]


# ---------------------------------------------------------------------------
# STANDALONE RUNNER (for direct testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Intel - Network Module")
    parser.add_argument(
        "--mode",
        choices=["ports", "anomaly", "all"],
        default="all",
        help="Which sub-module to run",
    )
    parser.add_argument(
        "--all-ports",
        action="store_true",
        help="Display all connections, not just flagged ones",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (for chatbot/pipeline integration)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=SAMPLE_DURATION_SECONDS,
        help=f"Anomaly detection observation window in seconds (default: {SAMPLE_DURATION_SECONDS})",
    )
    args = parser.parse_args()

    output = {}

    if args.mode in ("ports", "all"):
        console.rule("[bold]Port & Service Scan[/bold]")
        mapper = PortMapper()
        port_results = mapper.scan()
        if args.json:
            output["ports"] = mapper.to_dict(port_results)
        elif args.all_ports:
            mapper.display_all(port_results)
        else:
            mapper.display(port_results)

    if args.mode in ("anomaly", "all"):
        console.rule("[bold]Anomaly Detection[/bold]")
        detector = AnomalyDetector()
        anomaly_results = detector.run(duration=args.duration)
        if args.json:
            output["anomalies"] = detector.to_dict(anomaly_results)
        else:
            detector.display(anomaly_results)

    if args.json:
        print(json.dumps(output, indent=2))
