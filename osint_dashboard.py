#!/usr/bin/env python3
import requests
import socket
import sys
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ============ Username Check ============
USERNAME_SITES = {
    'GitHub': 'https://github.com/{}',
    'Twitter': 'https://twitter.com/{}',
    'Instagram': 'https://instagram.com/{}',
    'Reddit': 'https://reddit.com/user/{}',
    'YouTube': 'https://youtube.com/@{}',
    'TikTok': 'https://tiktok.com/@{}',
    'Facebook': 'https://facebook.com/{}',
    'LinkedIn': 'https://linkedin.com/in/{}',
    'Pinterest': 'https://pinterest.com/{}',
    'Telegram': 'https://t.me/{}',
    'Medium': 'https://medium.com/@{}',
    'Dev.to': 'https://dev.to/{}',
    'GitLab': 'https://gitlab.com/{}',
    'Bitbucket': 'https://bitbucket.org/{}',
    'Keybase': 'https://keybase.io/{}',
    'Behance': 'https://behance.net/{}',
    'Dribbble': 'https://dribbble.com/{}',
    'Flickr': 'https://flickr.com/people/{}',
    'SoundCloud': 'https://soundcloud.com/{}',
    'Twitch': 'https://twitch.tv/{}',
}

def check_username(username):
    print(f"\n{'='*60}")
    print(f"  Username Check: {username}")
    print(f"{'='*60}\n")
    
    found = []
    def check(site, url):
        try:
            r = requests.get(url, timeout=5, allow_redirects=False,
                           headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                return (site, url)
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(check, s, u.format(username)): s 
                   for s, u in USERNAME_SITES.items()}
        for future in futures:
            result = future.result()
            if result:
                site, url = result
                found.append({'site': site, 'url': url})
                print(f"  [+] {site}: {url}")
    
    if not found:
        print("  [-] Not found on any site")
    
    return found

# ============ IP Info ============
def check_ip(ip):
    print(f"\n{'='*60}")
    print(f"  IP Info: {ip}")
    print(f"{'='*60}\n")
    
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = r.json()
        
        if data.get('status') == 'success':
            info = {
                'country': data.get('country'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'as': data.get('as'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'timezone': data.get('timezone'),
            }
            print(f"  [+] Country: {info['country']}")
            print(f"  [+] Region: {info['region']}")
            print(f"  [+] City: {info['city']}")
            print(f"  [+] ISP: {info['isp']}")
            print(f"  [+] Org: {info['org']}")
            print(f"  [+] AS: {info['as']}")
            print(f"  [+] Lat/Lon: {info['lat']}, {info['lon']}")
            print(f"  [+] Timezone: {info['timezone']}")
            return info
    except Exception as e:
        print(f"  [-] Error: {e}")
    return None

# ============ DNS Enum ============
def dns_enum(domain):
    print(f"\n{'='*60}")
    print(f"  DNS Enumeration: {domain}")
    print(f"{'='*60}\n")
    
    info = {}
    try:
        import dns.resolver
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records = [str(r) for r in answers]
                info[rtype] = records
                print(f"  [+] {rtype}:")
                for rec in records:
                    print(f"      {rec}")
            except:
                pass
    except ImportError:
        # Fallback
        try:
            ip = socket.gethostbyname(domain)
            info['A'] = [ip]
            print(f"  [+] A: {ip}")
        except:
            print(f"  [-] Could not resolve")
    return info

# ============ WHOIS ============
def whois_lookup(domain):
    print(f"\n{'='*60}")
    print(f"  WHOIS: {domain}")
    print(f"{'='*60}\n")
    
    try:
        r = requests.get(f'https://rdap.org/domain/{domain}', timeout=10)
        data = r.json()
        
        info = {}
        # Registrar
        for entity in data.get('entities', []):
            if 'registrar' in entity.get('roles', []):
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == 'fn':
                            info['registrar'] = item[3]
                            print(f"  [+] Registrar: {item[3]}")
        
        # Events
        for event in data.get('events', []):
            if event['eventAction'] == 'registration':
                info['created'] = event['eventDate']
                print(f"  [+] Created: {event['eventDate']}")
            elif event['eventAction'] == 'expiration':
                info['expires'] = event['eventDate']
                print(f"  [+] Expires: {event['eventDate']}")
        
        # Nameservers
        ns = []
        for ns_obj in data.get('nameservers', []):
            ns.append(ns_obj.get('ldhName', ''))
        if ns:
            info['nameservers'] = ns
            print(f"  [+] Nameservers: {', '.join(ns)}")
        
        return info
    except Exception as e:
        print(f"  [-] Error: {e}")
        return None

# ============ Report HTML ============
def save_html_report(target, results):
    filename = f"osint_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>OSINT Report - {target}</title>
<style>
body {{ font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; }}
h1 {{ color: #00d9ff; border-bottom: 2px solid #00d9ff; }}
h2 {{ color: #ff6b6b; margin-top: 30px; }}
.card {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #00d9ff; }}
.ok {{ color: #00ff88; }}
table {{ width: 100%; border-collapse: collapse; }}
td, th {{ padding: 8px; text-align: left; border-bottom: 1px solid #333; }}
</style>
</head>
<body>
<h1>🔍 OSINT Report</h1>
<div class="card">
<strong>Target:</strong> {target}<br>
<strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
</div>
<h2>📊 Results</h2>
<pre>{json.dumps(results, indent=2, default=str)}</pre>
</body>
</html>"""
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"\n[+] HTML Report saved: {filename}")

# ============ Main ============
def main():
    if len(sys.argv) < 3:
        print("""
Usage: python3 osint_dashboard.py <mode> <target>

Modes:
  username <name>   - Check username on 20+ sites
  ip <ip>           - Get IP info
  dns <domain>      - DNS enumeration
  whois <domain>    - WHOIS lookup
  all <domain>      - Run all checks
""")
        return
    
    mode = sys.argv[1].lower()
    target = sys.argv[2]
    
    print(f"\n{'='*60}")
    print(f"  OSINT Dashboard")
    print(f"  Mode: {mode}")
    print(f"  Target: {target}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    
    results = {}
    
    if mode == 'username':
        results['username'] = check_username(target)
    elif mode == 'ip':
        results['ip'] = check_ip(target)
    elif mode == 'dns':
        results['dns'] = dns_enum(target)
    elif mode == 'whois':
        results['whois'] = whois_lookup(target)
    elif mode == 'all':
        try:
            results['dns'] = dns_enum(target)
        except:
            pass
        try:
            results['whois'] = whois_lookup(target)
        except:
            pass
        try:
            ip = socket.gethostbyname(target)
            results['ip'] = check_ip(ip)
        except:
            pass
    
    save_html_report(target, results)

if __name__ == "__main__":
    main()
