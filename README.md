import socket
from datetime import datetime
import argparse
import re

# Vulnerability dictionary with common ports and descriptions
vulnerabilities = {
    22: "Potential SSH brute-force vulnerability",
    80: "Open HTTP port; check for outdated web server",
    443: "Open HTTPS port; verify SSL/TLS version",
    3306: "Open MySQL port; check for default credentials",
    3389: "Remote Desktop Protocol (RDP) open; high-risk exposure",
}

def validate_ip(ip):
    """Validate the IP address format."""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return True
    else:
        raise ValueError("Invalid IP address format.")

def scan_ports(ip, port_range=(1, 1024)):
    """Scan the specified IP for open ports in the given range."""
    open_ports = []
    print(f"Scanning {ip} for open ports...")
    for port in range(port_range[0], port_range[1] + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Faster scanning with short timeout
            if s.connect_ex((ip, port)) == 0:  # If port is open
                print(f"Port {port} is open")
                open_ports.append(port)
    return open_ports

def check_vulnerabilities(open_ports):
    """Check for known vulnerabilities on open ports."""
    vulnerabilities_found = {}
    for port in open_ports:
        if port in vulnerabilities:
            vulnerabilities_found[port] = vulnerabilities[port]
    return vulnerabilities_found

def log_results(ip, open_ports, vulnerabilities_found):
    """Log the results of the scan to a file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"scan_{ip}_{timestamp}.txt"
    
    with open(log_filename, 'w') as log_file:
        log_file.write(f"Scan results for {ip} at {timestamp}\n")
        log_file.write("Open ports:\n")
        for port in open_ports:
            log_file.write(f" - Port {port}\n")
        log_file.write("Vulnerabilities found:\n")
        for port, vuln in vulnerabilities_found.items():
            log_file.write(f" - Port {port}: {vuln}\n")

    print(f"Results logged to {log_filename}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Security Scanner")
    parser.add_argument("ip", type=str, help="IP address to scan")
    parser.add_argument("--start-port", type=int, default=1, help="Start of port range")
    parser.add_argument("--end-port", type=int, default=1024, help="End of port range")
    args = parser.parse_args()

    # Validate IP and scan
    if validate_ip(args.ip):
        open_ports = scan_ports(args.ip, (args.start_port, args.end_port))
        vulnerabilities_found = check_vulnerabilities(open_ports)
        log_results(args.ip, open_ports, vulnerabilities_found)

if __name__ == "__main__":
    main()
