#!/usr/bin/env python3
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

def check_subdomain(domain, sub):
    full = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(full)
        return (full, ip)
    except:
        return None

def find_subdomains(domain):
    print(f"\n{'='*60}")
    print(f"  Subdomain Finder")
    print(f"  Domain: {domain}")
    print(f"{'='*60}\n")
    
    subs = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'ns1', 'ns2', 'cpanel',
        'autodiscover', 'm', 'imap', 'test', 'blog', 'dev', 'admin',
        'forum', 'news', 'vpn', 'mail2', 'new', 'mysql', 'old', 'lists',
        'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop',
        'secure', 'demo', 'cp', 'api', 'cdn', 'stats', 'staging',
        'server', 'chat', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
        'store', 'relay', 'files', 'app', 'live', 'owa', 'en', 'start',
        'office', 'exchange', 'portal', 'wiki', 'web', 'media', 'email',
        'images', 'img', 'video', 'sip', 'dns', 'search', 'download',
    ]
    
    print(f"[*] Testing {len(subs)} subdomains...\n")
    
    found = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_subdomain, domain, s): s for s in subs}
        for future in futures:
            result = future.result()
            if result:
                full, ip = result
                found.append((full, ip))
                print(f"  [+] {full} → {ip}")
    
    print(f"\n{'='*60}")
    print(f"  Found: {len(found)} subdomains")
    print(f"{'='*60}\n")
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 subdomain_finder.py <domain>")
        sys.exit(1)
    find_subdomains(sys.argv[1])
