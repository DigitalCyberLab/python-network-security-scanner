
#!/usr/bin/env python3

"""
Python Network Security Scanner

Project: Python Network Security Scanner
Purpose: Identify open TCP ports on authorized network devices.

Features:
- IP address input and validation
- Host availability detection
- Common TCP port scanning
- Custom TCP port scanning
- Common service identification
- Security reporting
- Export results to TXT and CSV

Authorized testing only.
"""

import socket
import ipaddress
import datetime
import csv
import os


# Common TCP ports and their associated services

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP"
}


def validate_ip_address(target_ip):
    """Validate the target IP address."""

    try:
        ipaddress.ip_address(target_ip)
        return True

    except ValueError:
        return False



def check_host_availability(target_ip):
    """Check host availability using multiple common TCP ports."""

    availability_ports = [22, 80, 443, 53, 3389]

    for port in availability_ports:

        try:
            with socket.create_connection((target_ip, port), timeout=2):
                print(f"[INFO] Host {target_ip} is reachable.")
                print(f"[INFO] Availability confirmed using TCP port {port}.")
                return True

        except (socket.timeout, ConnectionRefusedError, OSError):
            continue

    print(f"[WARNING] Host {target_ip} did not respond on the tested TCP ports.")
    return False



def scan_ports(target_ip):
    """Scan common TCP ports on the target host."""

    print("\n[INFO] Starting common TCP port scan...")
    print("-" * 45)

    open_ports = []

    for port, service in COMMON_PORTS.items():

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scanner:
                scanner.settimeout(1)

                result = scanner.connect_ex((target_ip, port))

                if result == 0:
                    print(f"[OPEN] Port {port:<5} Service: {service}")
                    open_ports.append((port, service))

        except socket.error as error:
            print(f"[ERROR] Port {port}: {error}")

    print("-" * 45)
    print(f"[INFO] Scan completed. Open ports found: {len(open_ports)}")

    return open_ports


def scan_custom_ports(target_ip, ports):
    """Scan user-selected TCP ports on the target host."""

    print("\n[INFO] Starting custom TCP port scan...")
    print("-" * 45)

    open_ports = []

    for port in ports:

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scanner:
                scanner.settimeout(1)

                result = scanner.connect_ex((target_ip, port))

                if result == 0:
                    service = COMMON_PORTS.get(port, "Unknown Service")
                    print(f"[OPEN] Port {port:<5} Service: {service}")
                    open_ports.append((port, service))

        except socket.error as error:
            print(f"[ERROR] Port {port}: {error}")

    print("-" * 45)
    print(f"[INFO] Custom scan completed. Open ports found: {len(open_ports)}")

    return open_ports


def save_txt_report(target_ip, scan_method, open_ports):
    """Save scan results to a TXT report."""

    report_folder = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "Reports"
    )

    os.makedirs(report_folder, exist_ok=True)

    scan_time = datetime.datetime.now()
    timestamp = scan_time.strftime("%Y%m%d_%H%M%S")
    date_time = scan_time.strftime("%Y-%m-%d %H:%M:%S")

    filename = f"scan_report_{timestamp}.txt"
    filepath = os.path.join(report_folder, filename)

    with open(filepath, "w", encoding="utf-8") as report:

        report.write("=" * 55 + "\n")
        report.write("       PYTHON NETWORK SECURITY SCAN REPORT\n")
        report.write("=" * 55 + "\n\n")

        report.write(f"Target IP Address: {target_ip}\n")
        report.write(f"Scan Date and Time: {date_time}\n")
        report.write(f"Scanning Method: {scan_method}\n\n")

        report.write("OPEN TCP PORTS\n")
        report.write("-" * 45 + "\n")

        if open_ports:
            for port, service in open_ports:
                report.write(f"Port: {port} | Service: {service}\n")
        else:
            report.write("No open TCP ports found.\n")

        report.write("\n")
        report.write(f"Total Open Ports: {len(open_ports)}\n")
        report.write("=" * 55 + "\n")

    print(f"\n[INFO] TXT report saved: {filepath}")


def save_csv_report(target_ip, scan_method, open_ports):
    """Save scan results to a CSV report."""

    report_folder = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "Reports"
    )

    os.makedirs(report_folder, exist_ok=True)

    scan_time = datetime.datetime.now()
    timestamp = scan_time.strftime("%Y%m%d_%H%M%S")
    date_time = scan_time.strftime("%Y-%m-%d %H:%M:%S")

    filename = f"scan_report_{timestamp}.csv"
    filepath = os.path.join(report_folder, filename)

    with open(filepath, "w", newline="", encoding="utf-8") as report:

        writer = csv.writer(report)

        writer.writerow([
            "Target IP",
            "Scan Date and Time",
            "Scanning Method",
            "Open Port",
            "Service",
            "Total Open Ports"
        ])

        if open_ports:
            for port, service in open_ports:
                writer.writerow([
                    target_ip,
                    date_time,
                    scan_method,
                    port,
                    service,
                    len(open_ports)
                ])
        else:
            writer.writerow([
                target_ip,
                date_time,
                scan_method,
                "",
                "No open ports found",
                0
            ])

    print(f"[INFO] CSV report saved: {filepath}")


def main():
    """Main program entry point."""

    print("=" * 55)
    print("          PYTHON NETWORK SECURITY SCANNER")
    print("=" * 55)

    target_ip = input("\nEnter the IP address to scan: ").strip()

    if not validate_ip_address(target_ip):
        print("\n[ERROR] Invalid IP address.")
        return

    print(f"\n[INFO] Target IP address: {target_ip}")
    print("[INFO] IP address validation successful.")

    if not check_host_availability(target_ip):
        print("\n[WARNING] Host availability check failed.")
        print("[INFO] Scanning will not continue.")
        return

    print("\nSelect scanning option:")
    print("1. Scan common TCP ports")
    print("2. Scan custom TCP ports")

    choice = input("\nEnter your choice (1 or 2): ").strip()

    if choice == "1":

        open_ports = scan_ports(target_ip)
        scan_method = "Common TCP Port Scan"

    elif choice == "2":

        port_input = input(
            "\nEnter TCP ports separated by commas (example: 22,80,443): "
        ).strip()

        try:
            ports = sorted(set(
                int(port.strip()) for port in port_input.split(",")
            ))

            if not ports or any(port < 1 or port > 65535 for port in ports):
                print("\n[ERROR] Enter valid TCP ports between 1 and 65535.")
                return

        except ValueError:
            print("\n[ERROR] Invalid port input. Use numbers separated by commas.")
            return

        open_ports = scan_custom_ports(target_ip, ports)
        scan_method = "Custom TCP Port Scan"

    else:

        print("\n[ERROR] Invalid menu selection.")
        return

    # Generate scan reports

    print("\n[INFO] Generating scan reports...")

    save_txt_report(target_ip, scan_method, open_ports)
    save_csv_report(target_ip, scan_method, open_ports)

    print("\n[INFO] Scan and reporting process completed.")


if __name__ == "__main__":
    main()
