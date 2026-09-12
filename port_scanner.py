#!/usr/bin/env python3
import socket
import sys

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            return True
    except:
        pass
    return False

def scan(host, start, end):
    print(f"Scanning {host} ports {start}-{end}...")
    found = []
    for p in range(start, end + 1):
        if scan_port(host, p):
            print(f"[+] Port {p} OPEN")
            found.append(p)
    print(f"Found {len(found)} open ports")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 port_scanner.py <host> <start> <end>")
        sys.exit(1)
    scan(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
