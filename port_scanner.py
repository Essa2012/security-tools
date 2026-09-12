#!/usr/bin/env python3
import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
}

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            return (port, SERVICES.get(port, 'unknown'))
    except:
        pass
    return None

def scan(host, start_port, end_port):
    print(f"\n{'='*60}")
    print(f"  Port Scanner")
    print(f"  Target: {host}")
    print(f"  Ports:  {start_port}-{end_port}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = [ex.submit(scan_port, host, p) for p in range(start_port, end_port + 1)]
        for future in futures:
            result = future.result()
            if result:
                port, service = result
                open_ports.append(port)
                print(f"  [+] Port {port:5d} OPEN  →  {service}")
    
    print(f"\n{'='*60}")
    print(f"  Found {len(open_ports)} open ports")
    print(f"{'='*60}\n")
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 port_scanner.py <host> <start> <end>")
        sys.exit(1)
    scan(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
