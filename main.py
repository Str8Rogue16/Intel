"""
main.py - Intel Project
========================
Unified entry point tying together the Network Auditor and CVE Lookup modules.

Responsibilities:
    - Single CLI for running any combination of scans (network, anomaly, cve, all)
    - Aggregates results from network.py and cve.py into one combined report
    - Cross-module correlation: feeds discovered services from the port scan
      directly into the CVE lookup, so you don't have to manually identify
      software versions yourself
    - Writes a single timestamped JSON report per run to output/reports/
    - Returns a non-zero exit code when findings exist, so this can be wired
      into cron/systemd timers or other monitoring later

Usage:
    python main.py --scan network          # Port mapper only
    python main.py --scan anomaly          # Anomaly detector only
    python main.py --scan cve              # CVE inventory scan only
    python main.py --scan all              # Everything (default)
    python main.py --scan all --json       # Print combined JSON to stdout
    python main.py --scan all --no-report  # Skip writing report file

Dependencies:
    pip install -r requirements.txt

Author: Intel Project
Platform: macOS / Linux

Changelog:
    v1.0 - Initial scaffold tying network.py and cve.py together
         - Added combined JSON report output
         - Added exit-code signaling for future scheduling/monitoring use
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

import network
import cve

console = Console()

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
# NOTE: Adjust as your project structure evolves.
REPORT_DIR: Path = Path("output/reports")


# ---------------------------------------------------------------------------
# CORRELATION — NETWORK FINDINGS -> CVE LOOKUP
# ---------------------------------------------------------------------------

def correlate_network_to_cve(
    port_entries: list,
) -> list:
    """
    Build a software inventory from processes discovered by the port scan,
    so the CVE module can check those specific services instead of (or in
    addition to) a full system package inventory.

    NOTE: This is best-effort. Process names from psutil (e.g. "nginx",
    "postgres") often don't include version numbers directly — only the
    package manager inventory in SoftwareInventory reliably has versions.
    This function currently maps flagged processes to placeholder entries
    so they're visible in the combined report; replace the "unknown" version
    with real version detection logic if you extend this (e.g. parsing
    `process_path` and running `<binary> --version`).
    """
    correlated: list = []
    seen_names: set[str] = set()

    for entry in port_entries:
        if not entry.flagged or not entry.process_name:
            continue
        name = entry.process_name.lower()
        if name in seen_names:
            continue
        seen_names.add(name)
        # NOTE: version is unknown from the port scan alone — see docstring.
        correlated.append(
            cve.SoftwareEntry(name=name, version="unknown", source="network-scan")
        )

    return correlated


# ---------------------------------------------------------------------------
# ORCHESTRATOR
# ---------------------------------------------------------------------------

class IntelRunner:
    """
    Top-level orchestrator for the Intel project. Ties network.py and cve.py
    together into a single run with combined reporting.

    Usage:
        runner = IntelRunner()
        results = runner.run(modes=["network", "anomaly", "cve"])
        runner.save_report(results)
    """

    def __init__(self):
        self.port_mapper = network.PortMapper()
        self.anomaly_detector = network.AnomalyDetector()
        self.cve_scanner = cve.CVEScanner()

    def run(
        self,
        modes: list[str],
        anomaly_duration: int = network.SAMPLE_DURATION_SECONDS,
        correlate: bool = True,
    ) -> dict:
        """
        Run the requested scan modes and return a combined results dict.

        modes: any combination of "network", "anomaly", "cve"
        correlate: if True and both "network" and "cve" are in modes,
                   feed flagged services from the port scan into CVE lookup
        """
        results: dict = {
            "scanned_at": datetime.now().isoformat(),
            "modes_run": modes,
        }

        port_entries = None

        if "network" in modes:
            console.rule("[bold cyan]Intel — Network Port Scan[/bold cyan]")
            port_entries = self.port_mapper.scan()
            self.port_mapper.display(port_entries)
            results["network"] = self.port_mapper.to_dict(port_entries)

        if "anomaly" in modes:
            console.rule("[bold cyan]Intel — Connection Anomaly Detection[/bold cyan]")
            anomaly_results = self.anomaly_detector.run(duration=anomaly_duration)
            self.anomaly_detector.display(anomaly_results)
            results["anomaly"] = self.anomaly_detector.to_dict(anomaly_results)

        if "cve" in modes:
            console.rule("[bold cyan]Intel — CVE Lookup[/bold cyan]")

            if correlate and port_entries is not None:
                # Cross-module correlation: check flagged services from the
                # port scan in addition to the full package inventory.
                correlated = correlate_network_to_cve(port_entries)
                if correlated:
                    console.print(
                        f"[dim]Correlating {len(correlated)} flagged service(s) "
                        f"from network scan into CVE lookup...[/dim]"
                    )
                    errors: list[str] = []
                    correlated_cves = self.cve_scanner.lookup.scan_all(correlated, errors)
                    new_correlated = self.cve_scanner.cache.mark_new(correlated_cves)
                    self.cve_scanner.notifier.notify(new_correlated)
                    results["cve_correlated"] = {
                        "services_checked": len(correlated),
                        "cves_found": len(correlated_cves),
                        "new_cves": len(new_correlated),
                    }

            cve_result = self.cve_scanner.run()
            self.cve_scanner.display(cve_result)
            results["cve"] = self.cve_scanner.to_dict(cve_result)

        return results

    def save_report(self, results: dict) -> Path:
        """
        Write the combined results dict to a timestamped JSON file under
        REPORT_DIR. Returns the path written.
        """
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = REPORT_DIR / f"intel_report_{timestamp}.json"

        with open(report_path, "w") as f:
            json.dump(results, f, indent=2)

        return report_path

    def summarize(self, results: dict) -> dict:
        """
        Build a short summary of findings across all modules.
        Used for the final console panel and to determine exit code.

        NOTE: This is also a good integration point for your chatbot —
        pass this summary dict as context for a natural language readout.
        """
        summary = {
            "flagged_ports": 0,
            "anomalies": 0,
            "new_cves": 0,
        }

        if "network" in results:
            summary["flagged_ports"] = sum(
                1 for e in results["network"] if e.get("flagged")
            )

        if "anomaly" in results:
            summary["anomalies"] = len(results["anomaly"])

        if "cve" in results:
            summary["new_cves"] = results["cve"].get("new_cves_count", 0)

        return summary

    def display_summary(self, summary: dict) -> None:
        """Render a final summary panel to the terminal."""
        lines = [
            f"Flagged ports:     {summary['flagged_ports']}",
            f"Traffic anomalies: {summary['anomalies']}",
            f"New CVEs found:    {summary['new_cves']}",
        ]

        total_findings = sum(summary.values())
        style = "bold red" if total_findings > 0 else "bold green"
        title = "⚠ Findings Detected" if total_findings > 0 else "✓ All Clear"

        console.print(Panel("\n".join(lines), title=title, border_style=style))


# ---------------------------------------------------------------------------
# STANDALONE RUNNER
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Intel - Unified Security Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--scan",
        choices=["network", "anomaly", "cve", "all"],
        default="all",
        help="Which scan(s) to run",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=network.SAMPLE_DURATION_SECONDS,
        help="Anomaly detection observation window in seconds",
    )
    parser.add_argument(
        "--no-correlate",
        action="store_true",
        help="Disable feeding network scan findings into the CVE lookup",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print combined results as JSON to stdout",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip writing the JSON report file to output/reports/",
    )
    args = parser.parse_args()

    modes = ["network", "anomaly", "cve"] if args.scan == "all" else [args.scan]

    runner = IntelRunner()
    results = runner.run(
        modes=modes,
        anomaly_duration=args.duration,
        correlate=not args.no_correlate,
    )

    summary = runner.summarize(results)

    if not args.json:
        runner.display_summary(summary)

    if not args.no_report:
        report_path = runner.save_report(results)
        if not args.json:
            console.print(f"\n[dim]Report saved to {report_path}[/dim]")

    if args.json:
        print(json.dumps(results, indent=2))

    # Exit code signaling: non-zero if findings exist. Useful for cron/
    # systemd timers or CI pipelines that want to alert on scan failures.
    total_findings = sum(summary.values())
    return 1 if total_findings > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
