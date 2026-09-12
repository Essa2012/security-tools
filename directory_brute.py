#!/usr/bin/env python3
import requests
import sys
from concurrent.futures import ThreadPoolExecutor

def check_path(base, path):
    try:
        r = requests.get(f"{base}/{path}", timeout=3)
        if r.status_code in [200, 301, 302, 403]:
            return (path, r.status_code)
    except:
        pass
    return None

def brute(base):
    print(f"\n{'='*60}")
    print(f"  Directory Brute Forcer")
    print(f"  Target: {base}")
    print(f"{'='*60}\n")
    
    paths = [
        'admin', 'login', 'dashboard', 'panel', 'cpanel', 'phpmyadmin',
        'api', 'v1', 'v2', 'docs', 'test', 'dev', 'staging', 'backup',
        'uploads', 'files', 'images', 'css', 'js', 'assets', 'private',
        'wp-admin', 'wp-content', 'administrator', 'user', 'users',
        'account', 'profile', 'settings', 'config', 'logs', 'tmp',
        'db', 'sql', 'data', 'cache', 'download', 'downloads',
    ]
    
    found = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(check_path, base, p): p for p in paths}
        for future in futures:
            result = future.result()
            if result:
                path, code = result
                found.append((path, code))
                print(f"  [+] /{path}/ → {code}")
    
    print(f"\nFound: {len(found)} paths")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 directory_brute.py <url>")
        sys.exit(1)
    brute(sys.argv[1])
