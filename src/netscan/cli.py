"""Command-line interface for the netscan package."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from colorama import Fore, Style, init

from netscan.exceptions import NetscanError
from netscan.scanner import NetworkScanner

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {Fore.WHITE}  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗{Fore.CYAN} ║
║   {Fore.WHITE}  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║{Fore.CYAN} ║
║   {Fore.WHITE}  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║{Fore.CYAN} ║
║   {Fore.WHITE}  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║{Fore.CYAN} ║
║   {Fore.WHITE}  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║{Fore.CYAN} ║
║   {Fore.WHITE}  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.CYAN} ║
║                                                              ║
║   {Fore.YELLOW}Advanced Network Scanner v2.0.0{Fore.CYAN}                           ║
║   {Fore.WHITE}Professional Port Scanning & Service Detection{Fore.CYAN}              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="Advanced Network Scanner — port detection, "
                    "service fingerprinting, and banner grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m netscan -t 192.168.1.1\n"
            "  python -m netscan -t 192.168.1.0/24 -p 22,80,443 --full\n"
            "  python -m netscan -t scanme.nmap.org --csv --json\n"
            "  python -m netscan -t 10.0.0.1 -p 1-65535 --threads 20\n"
        ),
    )

    # Target
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP, CIDR range, or hostname",
    )

    # Ports
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port range or comma-separated list (default: 1-1024)",
    )

    # Scan type
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan: service version detection (default)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Full scan: service + script + OS detection",
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help="Stealth SYN scan (slower, less detectable)",
    )
    parser.add_argument(
        "--os-detection",
        action="store_true",
        help="OS fingerprinting only",
    )

    # Export
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Export results to CSV",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Export results to JSON",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Export results to HTML report",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output filename base (without extension)",
    )

    # Banner grabbing
    parser.add_argument(
        "--banner-grab",
        action="store_true",
        help="Enable TCP banner grabbing on open ports",
    )

    # Threading
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )

    # Verbosity
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )

    # Version
    parser.add_argument(
        "--version",
        action="version",
        version="netscan 2.0.0",
    )

    return parser


def _resolve_scan_type(args: argparse.Namespace) -> str:
    """Determine the scan-type string from flags."""
    if args.full:
        return "full"
    if args.stealth:
        return "stealth"
    if args.os_detection:
        return "os-detection"
    return "quick"


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CLI.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code (0 for success).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    print(BANNER)

    # Logging
    log_level = "DEBUG" if args.verbose else "INFO"
    from netscan.logger import setup_logging
    setup_logging(level=log_level)

    logger = __import__("logging").getLogger("netscan.cli")
    logger.debug("CLI arguments: %s", args)

    scan_type = _resolve_scan_type(args)
    output_base = args.output or f"netscan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    print(f"{Fore.YELLOW}[*] Target:     {args.target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Ports:      {args.ports}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Scan type:  {scan_type}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Threads:    {args.threads}{Style.RESET_ALL}")
    print()

    try:
        scanner = NetworkScanner()

        # Support comma-separated list of targets
        target_list = [t.strip() for t in args.target.split(",") if t.strip()]
        if len(target_list) > 1:
            report = scanner.scan_targets(
                targets=target_list,
                ports=args.ports,
                scan_type=scan_type,
                max_workers=args.threads,
            )
        else:
            report = scanner.scan_target(
                target=target_list[0],
                ports=args.ports,
                scan_type=scan_type,
                show_progress=True,
            )
    except NetscanError as exc:
        logger.error(str(exc))
        print(f"{Fore.RED}[!] {exc}{Style.RESET_ALL}")
        return 1

    # Display results
    from netscan.reporter import display_report
    display_report(report)

    # Banner grabbing
    if args.banner_grab:
        print(f"\n{Fore.CYAN}[*] Starting banner grabbing...{Style.RESET_ALL}")
        try:
            from netscan.banner import grab_banners
            report = grab_banners(report, max_workers=args.threads)
        except NetscanError as exc:
            logger.warning("Banner grabbing skipped: %s", exc)

    # Export
    if args.csv:
        from netscan.reporter import export_csv
        path = f"{output_base}.csv"
        try:
            export_csv(report, path)
            print(f"{Fore.GREEN}[+] CSV report: {path}{Style.RESET_ALL}")
        except NetscanError as exc:
            logger.error("CSV export failed: %s", exc)

    if args.json:
        from netscan.reporter import export_json
        path = f"{output_base}.json"
        try:
            export_json(report, path)
            print(f"{Fore.GREEN}[+] JSON report: {path}{Style.RESET_ALL}")
        except NetscanError as exc:
            logger.error("JSON export failed: %s", exc)

    if args.html:
        from netscan.reporter import export_html
        path = f"{output_base}.html"
        try:
            export_html(report, path)
            print(f"{Fore.GREEN}[+] HTML report: {path}{Style.RESET_ALL}")
        except NetscanError as exc:
            logger.error("HTML export failed: %s", exc)

    print(f"\n{Fore.GREEN}[✓] Scan complete — {report.total_hosts} host(s), "
          f"{report.total_open_ports} open port(s){Style.RESET_ALL}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
