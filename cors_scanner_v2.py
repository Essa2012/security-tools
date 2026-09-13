#!/usr/bin/env python3
import requests
import sys
from datetime import datetime

# Origins اختبار متقدمة
def generate_origins(target_domain):
    """يولّد Origins للاختبار"""
    origins = [
        # Basic
        'https://evil.com',
        'https://attacker.com',
        'null',
        # Subdomain (prefix)
        f'https://evil.{target_domain}',
        f'https://attacker.{target_domain}',
        # Subdomain (suffix)
        f'https://{target_domain}.evil.com',
        f'https://{target_domain}.attacker.com',
        # Regex bypass
        f'https://{target_domain}evil.com',
        f'https://evil{target_domain}',
        # Special chars
        f'https://{target_domain}%60.evil.com',
        f'https://evil.com%60.{target_domain}',
        # Case variation
        f'https://EVIL.{target_domain}',
        f'https://{target_domain}.EVIL.com',
        # Port variation
        f'https://{target_domain}:8080',
        f'http://{target_domain}',
    ]
    return origins

def test_origin(url, origin):
    """يختبر Origin واحد"""
    try:
        headers = {'Origin': origin}
        r = requests.get(url, headers=headers, timeout=5)
        
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        acac = r.headers.get('Access-Control-Allow-Credentials', '')
        acam = r.headers.get('Access-Control-Allow-Methods', '')
        acah = r.headers.get('Access-Control-Allow-Headers', '')
        
        return {
            'origin': origin,
            'acao': acao,
            'acac': acac,
            'acam': acam,
            'acah': acah,
            'status': r.status_code
        }
    except:
        return None

def analyze(result, target_domain):
    """يحلل النتيجة"""
    origin = result['origin']
    acao = result['acao']
    acac = result['acac'].lower()
    
    # CRITICAL: Origin reflected + Credentials
    if (acao == origin or acao == origin.rstrip('/')) and acac == 'true':
        return ('CRITICAL', 100, 'Origin reflected + Credentials=true')
    
    # HIGH: Wildcard + Credentials
    if acao == '*' and acac == 'true':
        return ('CRITICAL', 95, 'Wildcard + Credentials=true')
    
    # HIGH: Null origin + Credentials
    if origin == 'null' and acac == 'true' and acao:
        return ('HIGH', 80, 'Null origin + Credentials')
    
    # HIGH: Origin reflected (بدون credentials)
    if acao == origin:
        return ('HIGH', 70, 'Origin reflected (no credentials)')
    
    # MEDIUM: Subdomain reflected
    if target_domain in acao and target_domain in origin:
        return ('MEDIUM', 50, 'Subdomain reflected')
    
    # LOW: Wildcard
    if acao == '*':
        return ('LOW', 20, 'Wildcard origin (public data)')
    
    return None

def scan_cors(url, target_domain):
    print(f"\n{'='*60}")
    print(f"  CORS Scanner v2")
    print(f"  Target: {url}")
    print(f"  Domain: {target_domain}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    origins = generate_origins(target_domain)
    print(f"[*] Testing {len(origins)} origins...\n")
    
    findings = []
    for origin in origins:
        result = test_origin(url, origin)
        if result:
            analysis = analyze(result, target_domain)
            if analysis:
                severity, score, desc = analysis
                findings.append({
                    'origin': origin,
                    'severity': severity,
                    'score': score,
                    'desc': desc,
                    'acao': result['acao'],
                    'acac': result['acac']
                })
                print(f"  [!] {severity} (Score: {score})")
                print(f"      Origin: {origin}")
                print(f"      ACAO: {result['acao']}")
                print(f"      ACAC: {result['acac']}")
                print(f"      Desc: {desc}\n")
    
    if not findings:
        print(f"  [✓] No CORS misconfigurations\n")
    else:
        # رتب حسب الخطورة
        findings.sort(key=lambda x: x['score'], reverse=True)
        top = findings[0]
        
        print(f"\n{'='*60}")
        print(f"  Highest Severity: {top['severity']} (Score: {top['score']})")
        print(f"  Total: {len(findings)} findings")
        print(f"{'='*60}\n")
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cors_scanner_v2.py <url>")
        print("Example: python3 cors_scanner_v2.py https://api.example.com")
        sys.exit(1)
    
    url = sys.argv[1]
    from urllib.parse import urlparse
    target_domain = urlparse(url).hostname
    scan_cors(url, target_domain)
