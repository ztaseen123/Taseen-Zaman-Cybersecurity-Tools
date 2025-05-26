#!/usr/bin/env python3

import socket
import sys
from datetime import datetime


def get_target_host():
    """Get and validate target host from user input."""
    while True:
        remote_server = input("Enter a remote host to scan: ").strip()
        if remote_server:
            return remote_server
        print("Invalid input, please try again")


def resolve_hostname(hostname):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"Error: Hostname '{hostname}' could not be resolved")
        sys.exit(1)


def scan_port(host_ip, port, timeout=0.5):
    """Scan a single port on the target host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host_ip, port))
            return result == 0
    except socket.error:
        return False


def main():
    """Main function to run the port scanner."""
    print("=" * 60)
    print("           Python Port Scanner")
    print("=" * 60)
    
    # Get target host
    remote_server = get_target_host()
    
    # Resolve hostname to IP
    remote_server_ip = resolve_hostname(remote_server)
    
    # Print scanning information
    print("-" * 60)
    print(f"Scanning target: {remote_server} ({remote_server_ip})")
    print(f"Port range: 1-1023")
    start_time = datetime.now()
    print(f"Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    open_ports = []
    scanned_ports = 0
    
    try:
        # Scan ports 1-1023
        for port in range(1, 1024):
            scanned_ports += 1
            
            # Show progress every 100 ports
            if scanned_ports % 100 == 0:
                print(f"Scanned {scanned_ports}/1023 ports...")
            
            if scan_port(remote_server_ip, port):
                print(f"Port {port}: OPEN")
                open_ports.append(port)
    
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print("Scan interrupted by user")
        print(f"Scanned {scanned_ports}/1023 ports before interruption")
    
    except Exception as e:
        print(f"\nError during scanning: {e}")
        sys.exit(1)
    
    # Calculate and display results
    end_time = datetime.now()
    total_time = end_time - start_time
    
    print("-" * 60)
    print("SCAN RESULTS")
    print("-" * 60)
    print(f"Host: {remote_server} ({remote_server_ip})")
    print(f"Ports scanned: {scanned_ports}")
    print(f"Open ports found: {len(open_ports)}")
    
    if open_ports:
        print(f"Open ports: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found in the scanned range")
    
    print(f"Scan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total scan time: {total_time}")
    print("-" * 60)


if __name__ == "__main__":
    main()
