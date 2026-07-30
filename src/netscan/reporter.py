"""Report generation — terminal display, CSV, JSON, and HTML exports."""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from colorama import Fore, Style

from netscan.exceptions import ExportError
from netscan.models import ScanReport

logger = logging.getLogger("netscan.reporter")


def display_report(report: ScanReport) -> None:
    """Print a colourised report of scan results to the terminal.

    Args:
        report: The scan results to display.
    """
    if not report.targets:
        print(f"\n{Fore.RED}[!] No hosts found in scan results{Style.RESET_ALL}")
        return

    print(f"\n{'=' * 68}")
    print(f"{Fore.CYAN}{'SCAN RESULTS':^68}{Style.RESET_ALL}")
    print(f"{'=' * 68}")
    print(f"  Scan type: {report.scan_type}")
    print(f"  Time:      {report.scan_time}")
    if report.duration_seconds:
        print(f"  Duration:  {report.duration_seconds:.1f}s")
    print(f"{'=' * 68}\n")

    for target in report.targets:
        print(f"{Fore.GREEN}Host: {target.ip}{Style.RESET_ALL}  ({target.hostname})")
        print(f"      State: {target.state}")

        if target.os_info:
            os_name = target.os_info.get("name", "unknown")
            os_acc = target.os_info.get("accuracy", "")
            print(f"      OS:    {os_name} (accuracy: {os_acc}%)")

        if not target.ports:
            print("      No open ports found\n")
            continue

        for port in target.ports:
            if port.state == "open":
                colour = Fore.GREEN
            elif port.state == "filtered":
                colour = Fore.YELLOW
            else:
                colour = Fore.RED

            version = port.version or port.product or ""
            print(
                f"      {colour}{port.port:>5}/{port.protocol:<3}  "
                f"{port.state:<10}  "
                f"{port.service:<18}  "
                f"{version}{Style.RESET_ALL}"
            )

            if port.banner:
                banner_short = port.banner[:80].replace("\n", " ")
                print(f"             Banner: {banner_short}")

        print()

    print(f"{'=' * 68}")
    print(f"  {report.total_hosts} host(s), {report.total_open_ports} open port(s)")
    print(f"{'=' * 68}\n")


def export_csv(report: ScanReport, path: str | Path) -> None:
    """Export scan results to a CSV file.

    Args:
        report: The scan results.
        path: Output file path.

    Raises:
        ExportError: If the file cannot be written.
    """
    try:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "IP", "Hostname", "State", "Protocol", "Port",
                "Port State", "Service", "Version", "Product", "Banner",
            ])
            for target in report.targets:
                for port in target.ports:
                    writer.writerow([
                        target.ip,
                        target.hostname,
                        target.state,
                        port.protocol,
                        port.port,
                        port.state,
                        port.service,
                        port.version,
                        port.product,
                        port.banner or "",
                    ])
        logger.info("CSV report saved: %s", path)
    except OSError as exc:
        raise ExportError("CSV", str(exc))


def export_json(report: ScanReport, path: str | Path) -> None:
    """Export scan results to a JSON file.

    Args:
        report: The scan results.
        path: Output file path.

    Raises:
        ExportError: If the file cannot be written.
    """
    try:
        with open(path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info("JSON report saved: %s", path)
    except OSError as exc:
        raise ExportError("JSON", str(exc))


def export_html(report: ScanReport, path: str | Path) -> None:
    """Export scan results to an HTML report file.

    Args:
        report: The scan results.
        path: Output file path.

    Raises:
        ExportError: If the file cannot be written.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    rows_html = ""
    for target in report.targets:
        rows_html += _host_section_html(target)
        for port in target.ports:
            rows_html += _port_row_html(port, target)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Scan Report — netscan</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
          background:#f5f7fa; color:#1a1a2e; padding:2rem; }}
  .container {{ max-width:1200px; margin:0 auto; }}
  h1 {{ font-size:1.8rem; margin-bottom:.5rem; color:#16213e; }}
  .meta {{ color:#555; margin-bottom:2rem; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
          border-radius:8px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.08);
          margin-bottom:2rem; }}
  th {{ background:#16213e; color:#fff; padding:12px 16px;
        text-align:left; font-weight:600; }}
  td {{ padding:10px 16px; border-bottom:1px solid #eef; }}
  tr:hover td {{ background:#f0f4ff; }}
  .host-header td {{ background:#e8edf5; font-weight:700; }}
  .state-open {{ color:#1b7a1b; }}
  .state-filtered {{ color:#b8860b; }}
  .state-closed {{ color:#a00; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px;
             font-size:.75rem; font-weight:600; }}
  .badge-open {{ background:#d4edda; color:#155724; }}
  .badge-filtered {{ background:#fff3cd; color:#856404; }}
  .badge-closed {{ background:#f8d7da; color:#721c24; }}
  footer {{ text-align:center; color:#888; margin-top:2rem; font-size:.85rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>🔍 Network Scan Report</h1>
  <div class="meta">
    <p><strong>Scan type:</strong> {report.scan_type}</p>
    <p><strong>Time:</strong> {report.scan_time}</p>
    <p><strong>Generated:</strong> {timestamp}</p>
    <p><strong>Duration:</strong> {report.duration_seconds:.1f}s</p>
    <p><strong>Hosts:</strong> {report.total_hosts} &middot;
       <strong>Open ports:</strong> {report.total_open_ports}</p>
  </div>
  <table>
    <thead>
      <tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th>
          <th>Service</th><th>Version</th><th>Banner</th></tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
  <footer>Generated by netscan v2.0.0</footer>
</div>
</body>
</html>"""

    try:
        Path(path).write_text(html)
        logger.info("HTML report saved: %s", path)
    except OSError as exc:
        raise ExportError("HTML", str(exc))


def _host_section_html(target: Any) -> str:
    """Build an HTML row showing host info."""
    cols = (
        f'<td colspan="7" class="host-header">'
        f'📡 {target.ip} ({target.hostname}) — {target.state}'
        f'</td>'
    )
    return f"<tr>{cols}</tr>"


def _port_row_html(port: Any, target: Any) -> str:
    """Build an HTML row for a single port."""
    state_class = f"state-{port.state}"
    badge = f'<span class="badge badge-{port.state}">{port.state}</span>'
    banner = (port.banner[:80] if port.banner else "")
    return (
        f"<tr>"
        f"<td></td>"
        f"<td><strong>{port.port}</strong></td>"
        f"<td>{port.protocol}</td>"
        f'<td class="{state_class}">{badge}</td>'
        f"<td>{port.service}</td>"
        f"<td>{port.version or port.product or '—'}</td>"
        f"<td>{banner}</td>"
        f"</tr>"
    )
