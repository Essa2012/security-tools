#!/usr/bin/env python3
import socket
import requests
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

VULNERABLE_SERVICES = {
    'github.io': 'GitHub Pages',
    'herokuapp.com': 'Heroku',
    's3.amazonaws.com': 'AWS S3',
    'cloudfront.net': 'AWS CloudFront',
    'azurewebsites.net': 'Azure',
    'netlify.app': 'Netlify',
    'vercel.app': 'Vercel',
    'surge.sh': 'Surge',
    'pages.dev': 'Cloudflare Pages',
    'firebaseapp.com': 'Firebase',
    'web.app': 'Firebase Hosting',
    'shopify.com': 'Shopify',
    'myshopify.com': 'Shopify',
    'wordpress.com': 'WordPress',
    'wpengine.com': 'WP Engine',
    'pantheonsite.io': 'Pantheon',
    'ghost.io': 'Ghost',
    'zendesk.com': 'Zendesk',
    'statuspage.io': 'Statuspage',
    'bitbucket.io': 'Bitbucket',
    'readthedocs.io': 'ReadTheDocs',
    'gitbook.io': 'GitBook',
    'notion.site': 'Notion',
    'atlassian.net': 'Atlassian',
    'fastly.net': 'Fastly',
    'cloudflare.net': 'Cloudflare',
}

def check_cname(domain):
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'CNAME')
        return str(answers[0].target).rstrip('.')
    except:
        return None

def check_takeover(domain):
    cname = check_cname(domain)
    if not cname:
        return None
    for service, name in VULNERABLE_SERVICES.items():
        if service in cname.lower():
            try:
                r = requests.get(f"http://{domain}", timeout=5)
                if r.status_code == 404:
                    return (domain, cname, name, 'VULNERABLE')
                elif 'not found' in r.text.lower() or 'no such' in r.text.lower():
                    return (domain, cname, name, 'POSSIBLE')
            except:
                pass
    return None

def scan(domain):
    print(f"\n{'='*60}")
    print(f"  Takeover Scanner v2")
    print(f"  Domain: {domain}")
    print(f"{'='*60}\n")
    
    subs = [
        'www', 'mail', 'blog', 'shop', 'store', 'api', 'dev', 'staging',
        'test', 'demo', 'admin', 'portal', 'app', 'mobile', 'cdn', 'static',
        'assets', 'img', 'images', 'video', 'docs', 'support', 'help',
        'status', 'news', 'forum', 'community', 'wiki', 'kb', 'auth',
        'login', 'sso', 'oauth', 'id', 'account', 'user', 'users',
    ]
    
    print(f"[*] Testing {len(subs)} subdomains...\n")
    
    found = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_takeover, f"{s}.{domain}"): s for s in subs}
        for future in futures:
            result = future.result()
            if result:
                found.append(result)
                d, cname, service, status = result
                print(f"  [!] {d}")
                print(f"      CNAME: {cname}")
                print(f"      Service: {service}")
                print(f"      Status: {status}\n")
    
    print(f"  Found: {len(found)} vulnerable subdomains\n")
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 takeover_scanner_v2.py <domain>")
        sys.exit(1)
    scan(sys.argv[1])
