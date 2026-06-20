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
    pip install psutil rich

Author: Intel Project
Platform: macOS / Linux (psutil handles cross-platform differences)

Changelog:
    v1.1 - Fixed duplicate entries from dual-stack (IPv4/IPv6) sockets
         - Added ephemeral port skipping to reduce false positive noise
         - Fixed raddr.ip AttributeError in AnomalyDetector._collect_snapshot
         - Added macOS system services (kdc, postgres) to default ALLOWED_PORTS
"""

import time
import statistics
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
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
BEACON_INTERVAL_TOLERANCE: float = 0.15 # 15% jitter tolerance for beaconing
BEACON_MIN_SAMPLES: int = 5             # Minimum samples to consider a beacon pattern
SAMPLE_INTERVAL_SECONDS: int = 5        # How often AnomalyDetector polls (seconds)
SAMPLE_DURATION_SECONDS: int = 60       # Total observation window per run


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
            for proc in process_map.values():
                try:
                    connections.extend(proc.net_connections(kind="all"))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        for conn in connections:
            local_addr = _ip(conn.laddr)
            local_port = _port(conn.laddr) or 0
            remote_addr = _ip(conn.raddr) or None
            remote_port = _port(conn.raddr)

            # Resolve process info from the pre-built map.
            pid = conn.pid
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

        start = time.time()
        while time.time() - start < duration:
            self._collect_snapshot(history)
            time.sleep(interval)

        return self._analyze(history)

    def _collect_snapshot(
        self, history: dict[str, list[ConnectionSnapshot]]
    ) -> None:
        """
        Take a single traffic sample. Records bytes_sent/recv per remote IP.

        NOTE: psutil.net_io_counters() gives system-wide totals, not per-connection.
        This uses system-wide counters keyed by remote IP as a practical
        approximation for home lab use. For per-process accuracy, extend this
        with proc.connections() + proc.io_counters() loops (requires root).
        """
        try:
            counters = psutil.net_io_counters(pernic=False)
            timestamp = time.time()

            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr:
                    continue

                # Use shared _ip() helper to handle both named tuple and
                # plain string formats returned by different psutil code paths.
                remote_ip = _ip(conn.raddr)
                if not remote_ip:
                    continue

                snapshot = ConnectionSnapshot(
                    timestamp=timestamp,
                    remote_ip=remote_ip,
                    bytes_sent=counters.bytes_sent,
                    bytes_recv=counters.bytes_recv,
                )
                history[remote_ip].append(snapshot)

        except (psutil.AccessDenied, PermissionError):
            console.print("[yellow]Warning: Insufficient permissions for some connections.[/yellow]")

    def _analyze(
        self, history: dict[str, list[ConnectionSnapshot]]
    ) -> list[AnomalyResult]:
        """Run all anomaly checks against collected history."""
        results: list[AnomalyResult] = []

        for remote_ip, snapshots in history.items():
            if len(snapshots) < 2:
                continue

            upload_result = self._check_upload_ratio(remote_ip, snapshots)
            if upload_result:
                results.append(upload_result)

            beacon_result = self._check_beaconing(remote_ip, snapshots)
            if beacon_result:
                results.append(beacon_result)

        return results

    def _check_upload_ratio(
        self, remote_ip: str, snapshots: list[ConnectionSnapshot]
    ) -> Optional[AnomalyResult]:
        """
        Flag connections where outbound traffic exceeds UPLOAD_RATIO_THRESHOLD
        of total traffic. Indicative of data exfiltration.
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
                    f"(sent={delta_sent}B, recv={delta_recv}B)"
                ),
                severity="HIGH",
                snapshots=snapshots,
            )
        return None

    def _check_beaconing(
        self, remote_ip: str, snapshots: list[ConnectionSnapshot]
    ) -> Optional[AnomalyResult]:
        """
        Flag connections that appear at suspiciously regular intervals.
        Beaconing is a hallmark of C2 (Command & Control) implants that
        check in with a remote server on a fixed timer.

        Method: compute intervals between snapshots, check coefficient of
        variation (CV = stdev/mean). Low CV = highly regular = suspicious.
        """
        if len(snapshots) < BEACON_MIN_SAMPLES:
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
                    f"stdev={stdev:.2f}s, CV={cv:.3f} (threshold={BEACON_INTERVAL_TOLERANCE})"
                ),
                severity="HIGH",
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
