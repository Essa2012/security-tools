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
    6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached',
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

def scan(host, start, end):
    print(f"\n{'='*60}")
    print(f"  Port Scanner v2")
    print(f"  Target: {host}")
    print(f"  Ports:  {start}-{end}")
    print(f"{'='*60}\n")
    
    found = []
    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = [ex.submit(scan_port, host, p) for p in range(start, end + 1)]
        for future in futures:
            result = future.result()
            if result:
                port, service = result
                found.append(port)
                print(f"  [+] Port {port:5d} OPEN  →  {service}")
    
    print(f"\n  Found {len(found)} open ports\n")
    return found

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 port_scanner_v2.py <host> <start> <end>")
        sys.exit(1)
    scan(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
