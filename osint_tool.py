#!/usr/bin/env python3
import requests
import sys
import socket
import json
from datetime import datetime

# ============ Username Checker ============
def check_username(username):
    """يفحص إذا Username موجود على مواقع"""
    print(f"\n{'='*60}")
    print(f"  Username Checker: {username}")
    print(f"{'='*60}\n")
    
    sites = {
        'GitHub': f'https://github.com/{username}',
        'Twitter/X': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'YouTube': f'https://youtube.com/@{username}',
        'TikTok': f'https://tiktok.com/@{username}',
        'Facebook': f'https://facebook.com/{username}',
        'LinkedIn': f'https://linkedin.com/in/{username}',
        'Pinterest': f'https://pinterest.com/{username}',
        'Telegram': f'https://t.me/{username}',
    }
    
    found = []
    for site, url in sites.items():
        try:
            r = requests.get(url, timeout=5, allow_redirects=False, 
                           headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                found.append(site)
                print(f"  [+] {site}: FOUND")
                print(f"      {url}")
            elif r.status_code in [301, 302]:
                found.append(site)
                print(f"  [+] {site}: FOUND (redirect)")
            else:
                print(f"  [-] {site}: Not found")
        except:
            print(f"  [!] {site}: Error")
    
    print(f"\n{'='*60}")
    print(f"  Found on {len(found)} platforms")
    print(f"{'='*60}\n")
    return found

# ============ IP Info ============
def check_ip(ip):
    """يجمع معلومات عن IP"""
    print(f"\n{'='*60}")
    print(f"  IP Info: {ip}")
    print(f"{'='*60}\n")
    
    try:
        # IP-API
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = r.json()
        
        if data.get('status') == 'success':
            print(f"  [+] Country: {data.get('country', 'N/A')}")
            print(f"  [+] Region: {data.get('regionName', 'N/A')}")
            print(f"  [+] City: {data.get('city', 'N/A')}")
            print(f"  [+] ISP: {data.get('isp', 'N/A')}")
            print(f"  [+] Org: {data.get('org', 'N/A')}")
            print(f"  [+] AS: {data.get('as', 'N/A')}")
            print(f"  [+] Lat/Lon: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
            print(f"  [+] Timezone: {data.get('timezone', 'N/A')}")
        else:
            print(f"  [-] Not found")
    except Exception as e:
        print(f"  [!] Error: {e}")

# ============ DNS Enum ============
def dns_enum(domain):
    """يجمع DNS Records"""
    print(f"\n{'='*60}")
    print(f"  DNS Enumeration: {domain}")
    print(f"{'='*60}\n")
    
    try:
        import dns.resolver
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                print(f"  [+] {rtype}:")
                for r in answers:
                    print(f"      {r}")
            except:
                pass
    except Exception as e:
        pass
    try:
        ip = socket.gethostbyname(domain)
        print(f"  [+] A: {ip}")
    except:
        print(f"  [-] Could not resolve")
        # Fallback
        try:
            ip = socket.gethostbyname(domain)
            print(f"  [+] A: {ip}")
        except:
            print(f"  [-] Could not resolve")

# ============ Email Breach ============
def check_email_breach(email):
    """يفحص إذا Email في تسريبات (Have I Been Pwned - مجاني)"""
    print(f"\n{'='*60}")
    print(f"  Email Breach Check: {email}")
    print(f"{'='*60}\n")
    
    try:
        # HIBP Public API (بدون مفتاح - Rate Limited)
        r = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers={'User-Agent': 'OSINT-Tool'},
            timeout=10
        )
        
        if r.status_code == 200:
            breaches = r.json()
            print(f"  [!] Email found in {len(breaches)} breaches:")
            for b in breaches[:10]:
                print(f"      • {b.get('Name', 'Unknown')}")
        elif r.status_code == 404:
            print(f"  [+] No breaches found")
        elif r.status_code == 401:
            print(f"  [!] API key required for this request")
    except Exception as e:
        print(f"  [!] Error: {e}")

# ============ Main ============
def show_help():
    print("""
    ╔══════════════════════════════════════════════╗
    ║         OSINT Tool v1.0                      ║
    ║         Author: Essa2012                     ║
    ╚══════════════════════════════════════════════╝
    
    Usage:
      python3 osint_tool.py username <name>
      python3 osint_tool.py ip <ip>
      python3 osint_tool.py dns <domain>
      python3 osint_tool.py email <email>
      python3 osint_tool.py all <target>
    
    Examples:
      python3 osint_tool.py username essa2012
      python3 osint_tool.py ip 8.8.8.8
      python3 osint_tool.py dns google.com
      python3 osint_tool.py email test@gmail.com
    """)

def main():
    if len(sys.argv) < 3:
        show_help()
        return
    
    mode = sys.argv[1].lower()
    target = sys.argv[2]
    
    print(f"\n{'='*60}")
    print(f"  OSINT Tool")
    print(f"  Mode: {mode}")
    print(f"  Target: {target}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    
    if mode == 'username':
        check_username(target)
    elif mode == 'ip':
        check_ip(target)
    elif mode == 'dns':
        dns_enum(target)
    elif mode == 'email':
        check_email_breach(target)
    elif mode == 'all':
        check_username(target)
        try:
            check_ip(target)
        except:
            pass
        try:
            dns_enum(target)
        except:
            pass
    else:
        show_help()

if __name__ == '__main__':
    main()
