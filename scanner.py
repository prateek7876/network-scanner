"""
Network Scanner Module
=====================
Core scanning functionality using python-nmap.
Provides port scanning, service detection, and result export.
"""

import csv
import json
import os
from datetime import datetime

import nmap
from colorama import Fore, Style, init

from logger import setup_logger

# Initialize colorama
init(autoreset=True)

# Initialize logger
logger = setup_logger()


class NetworkScanner:
    """Advanced Network Scanner using nmap."""

    def __init__(self):
        """Initialize the nmap scanner."""
        try:
            self.scanner = nmap.PortScanner()
            logger.info("Nmap scanner initialized successfully")
        except nmap.PortScannerError:
            logger.error("nmap is not installed or not in PATH")
            raise SystemExit("Error: Please install nmap first")

    def validate_target(self, target):
        """
        Validate if target is a valid IP, hostname, or range.

        Args:
            target: IP address, hostname, or range

        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Basic validation
            if not target or not target.strip():
                return False

            # Try to scan to validate
            self.scanner.scan(target, arguments="-sn")
            return True

        except Exception as e:
            logger.error(f"Invalid target: {target} - {e}")
            return False

    def scan_target(self, target, ports="1-1024", scan_type="-sV"):
        """
        Perform a scan on the target.

        Args:
            target: IP address or range
            ports: Port range to scan (default: 1-1024)
            scan_type: Nmap scan type (default: service version detection)

        Returns:
            dict: Scan results
        """
        logger.info(f"Starting scan on {target}")
        logger.info(f"Port range: {ports}")

        try:
            # Build arguments
            arguments = f"{scan_type} -p {ports} --open"

            # Perform scan
            self.scanner.scan(target, ports, arguments)

            logger.info(f"Scan completed for {target}")
            return self.get_results()

        except nmap.PortScannerError as e:
            logger.error(f"Nmap error: {e}")
            return None
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return None

    def get_results(self):
        """
        Parse scan results into structured format.

        Returns:
            dict: Parsed results with host information
        """
        results = {
            "scan_time": datetime.now().isoformat(),
            "hosts": [],
        }

        for host in self.scanner.all_hosts():
            host_info = {
                "ip": host,
                "hostname": self.scanner[host].hostname(),
                "state": self.scanner[host].state(),
                "protocols": [],
            }

            for proto in self.scanner[host].all_protocols():
                protocol_info = {
                    "name": proto,
                    "ports": [],
                }

                ports = self.scanner[host][proto].keys()
                for port in sorted(ports):
                    port_info = self.scanner[host][proto][port]
                    protocol_info["ports"].append(
                        {
                            "port": port,
                            "state": port_info["state"],
                            "service": port_info["name"],
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                            "extra": port_info.get("extrainfo", ""),
                        }
                    )

                host_info["protocols"].append(protocol_info)

            results["hosts"].append(host_info)

        logger.info(f"Found {len(results['hosts'])} host(s)")
        return results

    def export_csv(self, results, filename="scan_results.csv"):
        """
        Export scan results to CSV file.

        Args:
            results: Scan results dictionary
            filename: Output filename
        """
        try:
            with open(filename, "w", newline="") as csvfile:
                fieldnames = [
                    "IP",
                    "Hostname",
                    "State",
                    "Protocol",
                    "Port",
                    "Port State",
                    "Service",
                    "Version",
                    "Product",
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for host in results.get("hosts", []):
                    for proto in host.get("protocols", []):
                        for port in proto.get("ports", []):
                            writer.writerow(
                                {
                                    "IP": host["ip"],
                                    "Hostname": host["hostname"],
                                    "State": host["state"],
                                    "Protocol": proto["name"],
                                    "Port": port["port"],
                                    "Port State": port["state"],
                                    "Service": port["service"],
                                    "Version": port["version"],
                                    "Product": port["product"],
                                }
                            )

            logger.info(f"Results exported to {filename}")
            return True

        except Exception as e:
            logger.error(f"CSV export error: {e}")
            return False

    def export_json(self, results, filename="scan_results.json"):
        """
        Export scan results to JSON file.

        Args:
            results: Scan results dictionary
            filename: Output filename
        """
        try:
            with open(filename, "w") as jsonfile:
                json.dump(results, jsonfile, indent=4)

            logger.info(f"Results exported to {filename}")
            return True

        except Exception as e:
            logger.error(f"JSON export error: {e}")
            return False

    def display_results(self, results):
        """
        Display scan results with colored output.

        Args:
            results: Scan results dictionary
        """
        if not results or not results.get("hosts"):
            print(f"\n{Fore.RED}[!] No results to display{Style.RESET_ALL}")
            return

        print(f"\n{'=' * 60}")
        print(f"{Fore.CYAN}{'NETWORK SCAN RESULTS':^60}{Style.RESET_ALL}")
        print(f"{'=' * 60}")
        print(f"{Fore.YELLOW}Scan Time: {results['scan_time']}{Style.RESET_ALL}")
        print(f"{'=' * 60}\n")

        for host in results.get("hosts", []):
            # Host header
            print(f"{Fore.GREEN}{'─' * 60}{Style.RESET_ALL}")
            print(
                f"{Fore.GREEN}Host: {host['ip']}{Style.RESET_ALL}"
                f" ({host['hostname']})"
            )
            print(f"State: {host['state']}")

            for proto in host.get("protocols", []):
                print(f"\n  {Fore.CYAN}Protocol: {proto['name'].upper()}{Style.RESET_ALL}")

                for port in proto.get("ports", []):
                    # Color based on state
                    if port["state"] == "open":
                        color = Fore.GREEN
                    elif port["state"] == "filtered":
                        color = Fore.YELLOW
                    else:
                        color = Fore.RED

                    version = port["version"] or port["product"] or "unknown"
                    print(
                        f"    {color}{port['port']}/{proto['name']}"
                        f"  {port['state']:<10}  "
                        f"{port['service']:<15}  {version}{Style.RESET_ALL}"
                    )

        print(f"\n{'=' * 60}")
        print(
            f"{Fore.CYAN}Total Hosts Scanned: {len(results.get('hosts', []))}"
            f"{Style.RESET_ALL}"
        )
        print(f"{'=' * 60}\n")
