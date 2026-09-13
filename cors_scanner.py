#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urlparse

# نطاقات اختبار
TEST_ORIGINS = [
    'https://evil.com',
    'https://attacker.com',
    'https://malicious.site',
    'null',
    'https://example.com',
]

def test_cors(url, origin):
    """يختبر CORS مع Origin محدد"""
    headers = {'Origin': origin}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        acac = r.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == origin or acao == '*':
            if acac.lower() == 'true':
                return {
                    'origin': origin,
                    'acao': acao,
                    'acac': acac,
                    'status': 'CRITICAL',
                    'desc': 'Origin reflected + Credentials=true'
                }
            elif acao == '*':
                return {
                    'origin': origin,
                    'acao': acao,
                    'acac': acac,
                    'status': 'HIGH',
                    'desc': 'Wildcard origin'
                }
            else:
                return {
                    'origin': origin,
                    'acao': acao,
                    'acac': acac,
                    'status': 'MEDIUM',
                    'desc': 'Origin reflected'
                }
    except Exception as e:
        pass
    return None

def scan_cors(url):
    print(f"\n{'='*60}")
    print(f"  CORS Scanner")
    print(f"  Target: {url}")
    print(f"{'='*60}\n")
    
    print(f"[*] Testing {len(TEST_ORIGINS)} origins...\n")
    
    found = []
    for origin in TEST_ORIGINS:
        result = test_cors(url, origin)
        if result:
            found.append(result)
            print(f"  [!] {result['status']}")
            print(f"      Origin: {result['origin']}")
            print(f"      ACAO: {result['acao']}")
            print(f"      ACAC: {result['acac']}")
            print(f"      Desc: {result['desc']}\n")
    
    if not found:
        print(f"  [✓] No CORS misconfigurations found")
    else:
        print(f"\n{'='*60}")
        print(f"  Found: {len(found)} misconfigurations")
        print(f"{'='*60}\n")
    
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cors_scanner.py <url>")
        print("Example: python3 cors_scanner.py https://api.example.com/user")
        sys.exit(1)
    
    scan_cors(sys.argv[1])
