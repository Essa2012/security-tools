#!/usr/bin/env python3
import requests
import sys

def analyze(url):
    print(f"\n{'='*60}")
    print(f"  HTTP Header Analyzer v1")
    print(f"  URL: {url}")
    print(f"{'='*60}\n")
    try:
        r = requests.get(url, timeout=5)
        print(f"[+] Status: {r.status_code}")
        print(f"[+] Server: {r.headers.get('Server', 'N/A')}")
        print(f"\n[*] Headers:")
        for h, v in r.headers.items():
            print(f"    {h}: {v}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    analyze(url)
