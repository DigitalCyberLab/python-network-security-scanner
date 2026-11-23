# Python Network Security Scanner

## 1. Project Overview

The Python Network Security Scanner is a cybersecurity project designed to identify open TCP ports on authorized network devices.

The scanner uses Python's socket programming capabilities to check host availability, scan common TCP ports, perform custom port scans, and identify services associated with detected open ports.

The project also includes automated reporting capabilities that export scan results into TXT and CSV files for documentation and analysis.

## 2. Project Objectives

- Develop a network scanning tool using Python.
- Validate target IP addresses before scanning.
- Check host availability using multiple common TCP ports.
- Identify open TCP ports on authorized network devices.
- Perform common and user-selected TCP port scans.
- Identify common services associated with open ports.
- Generate automated TXT and CSV scan reports.
- Implement input validation and error handling.

## 3. Tools and Technologies

- Programming Language: Python 3.14
- Operating System: macOS
- Target System: Ubuntu Server Linux
- Virtualization Platform: Oracle VirtualBox
- Network Protocol: TCP
- Python Libraries: socket, ipaddress, datetime, csv, os

## 4. Project Features

### IP Address Validation
Validates the target IP address before beginning a scan.

### Host Availability Detection
Checks multiple common TCP ports to determine whether the target host accepts connections.

### Common TCP Port Scanning
Scans a predefined list of common TCP ports and identifies open services.

### Custom TCP Port Scanning
Allows users to enter specific TCP ports for targeted scanning.

### Service Identification
Associates detected open ports with commonly recognized network services.

### Automated Reporting
Automatically generates TXT and CSV reports containing the target IP address, scan date and time, scanning method, detected open ports, identified services, and total open ports.

### Input Validation and Error Handling
Rejects invalid IP addresses, menu selections, invalid port numbers, and empty port entries. Duplicate port entries are removed before scanning.

## 5. Testing and Verification

The following functionality was tested:

| Test | Result |
|---|---|
| Invalid IP address rejection | Passed |
| Invalid menu selection rejection | Passed |
| Invalid TCP port rejection | Passed |
| Empty custom port input rejection | Passed |
| Duplicate port removal | Passed |
| Host availability detection | Passed |
| Common TCP port scanning | Passed |
| Custom TCP port scanning | Passed |
| TXT report generation | Passed |
| CSV report generation | Passed |

## 6. Test Environment

- Administrator Workstation: MacBook Air
- Target Server: Ubuntu Server Virtual Machine
- Target IP Address: xxx.xxx.x.xxx
- Detected Open Port: TCP 22 (SSH)

## 7. Project Structure

```text
Python_Network_Security_Scanner/
│
├── network_scanner.py
├── README.md
│
└── Reports/
    ├── scan_report_YYYYMMDD_HHMMSS.txt
    └── scan_report_YYYYMMDD_HHMMSS.csv
```

## 8. Running the Scanner

Run the following command from the project directory:

```bash
python3 network_scanner.py
```

Alternatively, specify the Python executable:

```bash
/Users/admin/.local/bin/python3.14 network_scanner.py
```

Enter the target IP address and select either common TCP port scanning or custom TCP port scanning.

## 9. Security and Authorization

This tool is intended for educational purposes and authorized network security testing only.

Only scan systems and networks for which permission has been granted.
