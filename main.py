"""
Network Scanner - CLI Interface
================================
Main entry point for the network scanner tool.
Provides command-line interface for scanning targets.
"""

import argparse
import sys
from datetime import datetime

from colorama import Fore, Style, init

from logger import setup_logger
from scanner import NetworkScanner

# Initialize colorama
init(autoreset=True)

# Initialize logger
logger = setup_logger()


def print_banner():
    """Display the tool banner."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {Fore.WHITE}  ███╗   ██╗███████╗████████╗██╗    ██╗                  {Fore.CYAN} ║
║   {Fore.WHITE}  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║                  {Fore.CYAN} ║
║   {Fore.WHITE}  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║                  {Fore.CYAN} ║
║   {Fore.WHITE}  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║                  {Fore.CYAN} ║
║   {Fore.WHITE}  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝                  {Fore.CYAN} ║
║   {Fore.WHITE}  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝                   {Fore.CYAN} ║
║                                                              ║
║   {Fore.YELLOW}Advanced Network Scanner v1.0{Fore.CYAN}                            ║
║   {Fore.WHITE}Professional Port Scanning Tool{Fore.CYAN}                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Advanced Network Scanner - Scan networks for open ports and services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t 192.168.1.1
  python main.py -t 192.168.1.1-50
  python main.py -t 192.168.1.0/24 -p 1-65535
  python main.py -t scanme.nmap.org -p 80,443,22
        """,
    )

    # Target specification
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address, range, or CIDR notation",
    )

    # Port specification
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port range to scan (default: 1-1024)",
    )

    # Export options
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Export results to CSV file",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Export results to JSON file",
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Output filename (without extension)",
    )

    # Scan type
    parser.add_argument(
        "-s", "--scan-type",
        choices=["quick", "full", "stealth"],
        default="quick",
        help="Scan type (default: quick)",
    )

    # Verbose mode
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    return parser.parse_args()


def get_scan_arguments(scan_type):
    """
    Get nmap arguments based on scan type.

    Args:
        scan_type: Type of scan to perform

    Returns:
        str: Nmap arguments string
    """
    scan_types = {
        "quick": "-sV -T4",
        "full": "-sV -sC -O -T4",
        "stealth": "-sS -T2",
    }
    return scan_types.get(scan_type, "-sV")


def main():
    """Main function to run the network scanner."""
    # Print banner
    print_banner()

    # Parse arguments
    args = parse_arguments()

    # Display scan info
    print(f"{Fore.YELLOW}[*] Target: {args.target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Ports: {args.ports}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Scan Type: {args.scan_type}{Style.RESET_ALL}")
    print()

    # Initialize scanner
    scanner = NetworkScanner()

    # Perform scan
    scan_args = get_scan_arguments(args.scan_type)
    logger.info(f"Scan type: {args.scan_type} | Arguments: {scan_args}")

    results = scanner.scan_target(
        args.target,
        ports=args.ports,
        scan_type=scan_args,
    )

    if not results:
        print(f"\n{Fore.RED}[!] Scan failed. Check logs for details.{Style.RESET_ALL}")
        sys.exit(1)

    # Display results
    scanner.display_results(results)

    # Export results
    if args.csv or args.json:
        output_base = args.output or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if args.csv:
            csv_file = f"{output_base}.csv"
            scanner.export_csv(results, csv_file)
            print(f"{Fore.GREEN}[+] CSV report saved: {csv_file}{Style.RESET_ALL}")

        if args.json:
            json_file = f"{output_base}.json"
            scanner.export_json(results, json_file)
            print(f"{Fore.GREEN}[+] JSON report saved: {json_file}{Style.RESET_ALL}")

    logger.info("Scan completed successfully")
    print(f"\n{Fore.GREEN}[✓] Scan completed successfully{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
