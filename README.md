Network Security Scanner

Overview

The Network Security Scanner is a Python-based tool designed to help identify open ports and potential vulnerabilities on a specified IP address or a list of IPs. It leverages multi-threading for efficient scanning and logs the results for further analysis.

Features

Single IP Scanning: Quickly scan a single IP for open ports within a specified range.

Batch Scanning: Scan multiple IP addresses from a file.

Multi-threaded Port Scanning: Uses multi-threading for faster scanning of ports.

Vulnerability Detection: Matches open ports with known vulnerabilities from a predefined dictionary.

Result Logging: Logs the scan results, including open ports and detected vulnerabilities, to timestamped files.

Requirements

Python 3.7+

No external dependencies are required.

Installation

Clone the repository:

git clone https://github.com/your-repository/network-scanner.git
cd network-scanner

Ensure Python is installed on your system.

Usage

Single IP Scanning

Scan a single IP address with a specified port range:

python scanner.py 192.168.1.1 --start-port 20 --end-port 100

Batch Scanning from a File

Scan multiple IP addresses listed in a file:

python scanner.py --ip-file ip_list.txt --start-port 20 --end-port 100

The ip_list.txt file should contain one IP address per line.

Command-Line Arguments

Argument

Description

Default Value

ip

Single IP address to scan

None

--ip-file

File containing a list of IPs to scan

None

--start-port

Start of the port range

1

--end-port

End of the port range

1024

Results

The results of each scan are saved in a log file named scan_<IP>_<timestamp>.txt. Each log includes:

Open Ports: A list of all detected open ports.

Vulnerabilities Found: Descriptions of vulnerabilities related to the open ports.

Example Log File

Scan results for 192.168.1.1 at 20250106_120000

Open ports:
 - Port 22
 - Port 80

Vulnerabilities found:
 - Port 22: Potential SSH brute-force vulnerability
 - Port 80: Open HTTP port; check for outdated web server

Contribution

Contributions are welcome! To contribute:

Fork the repository.

Create a feature branch.

Submit a pull request.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Support

If you encounter any issues or have questions, please open an issue in this repository.

Acknowledgments

This project is inspired by the need for lightweight and fast network security tools for system administrators and developers.

