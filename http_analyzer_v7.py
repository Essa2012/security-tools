#!/usr/bin/env python3
import requests
import sys
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    G, R, Y, C = Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.CYAN
    RESET = Style.RESET_ALL
except:
    G = R = Y = C = RESET = ''

SECURITY_HEADERS = {
    'Strict-Transport-Security': ('HSTS', 15),
    'Content-Security-Policy': ('CSP', 15),
    'X-Frame-Options': ('Clickjacking', 10),
    'X-Content-Type-Options': ('MIME Sniffing', 10),
    'Referrer-Policy': ('Referrer', 10),
    'Permissions-Policy': ('Permissions', 10),
    'X-XSS-Protection': ('XSS', 5),
}

def check_ssl(hostname):
    print(f"\n{C}[*] SSL/TLS Check:{RESET}")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                cert = ss.getpeercert()
                print(f"  {G}[✓]{RESET} TLS: {ss.version()}")
                print(f"  {G}[✓]{RESET} Cipher: {ss.cipher()[0]}")
                expire = cert.get('notAfter', '')
                if expire:
                    exp_date = datetime.strptime(expire, '%b %d %H:%M:%S %Y %Z')
                    days = (exp_date - datetime.now()).days
                    print(f"  [*] Expires in: {days} days")
                return 20
    except Exception as e:
        print(f"  {R}[✗] Error: {e}{RESET}")
        return 0

def check_headers(headers):
    print(f"\n{C}[*] Security Headers:{RESET}")
    score = 0
    max_s = sum(v[1] for v in SECURITY_HEADERS.values())
    for h, (name, pts) in SECURITY_HEADERS.items():
        if h in headers:
            print(f"  {G}[✓]{RESET} {name}: {headers[h][:45]}")
            score += pts
        elif h == 'Content-Security-Policy' and 'Content-Security-Policy-Report-Only' in headers:
            print(f"  {Y}[!]{RESET} {name}: Report-Only")
            score += pts // 2
        elif h == 'Strict-Transport-Security':
            print(f"  {Y}[?]{RESET} {name}: May be preloaded")
            score += pts // 2
        else:
            print(f"  {R}[✗]{RESET} {name}: MISSING")
    return score, max_s

def check_cookies(cookies):
    print(f"\n{C}[*] Cookies:{RESET}")
    if not cookies:
        print(f"  {Y}[!] No cookies{RESET}")
        return 0
    score = 0
    for ck in cookies:
        flags = []
        if ck.secure:
            flags.append(f"{G}Secure{RESET}")
            score += 3
        else:
            flags.append(f"{R}Not Secure{RESET}")
        if ck.has_nonstandard_attr('HttpOnly'):
            flags.append(f"{G}HttpOnly{RESET}")
        else:
            flags.append(f"{Y}No HttpOnly{RESET}")
        ss = ck.get_nonstandard_attr('SameSite', 'None')
        flags.append(f"{G if ss.lower() in ['strict','lax'] else Y}SameSite={ss}{RESET}")
        print(f"  [*] {ck.name}: {' | '.join(flags)}")
    return min(10, score)

def check_redirect(url):
    print(f"\n{C}[*] Redirect Check:{RESET}")
    try:
        http_url = url.replace('https://', 'http://')
        r = requests.get(http_url, timeout=5, allow_redirects=False)
        if r.status_code in [301, 302, 307, 308]:
            loc = r.headers.get('Location', '')
            if loc.startswith('https://'):
                print(f"  {G}[✓] HTTP → HTTPS{RESET}")
                return 10
        print(f"  {R}[✗] No redirect{RESET}")
        return 0
    except:
        return 0

def grade(p):
    if p >= 95: return f"{G}A+{RESET}"
    if p >= 85: return f"{G}A{RESET}"
    if p >= 75: return f"{G}B{RESET}"
    if p >= 65: return f"{Y}C{RESET}"
    if p >= 50: return f"{Y}D{RESET}"
    return f"{R}F{RESET}"

def analyze(url):
    if not url.startswith('http'):
        url = 'https://' + url
    
    print(f"\n{C}{'═'*60}")
    print(f"  HTTP Security Analyzer v7")
    print(f"  Target: {url}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*60}{RESET}")
    
    try:
        r = requests.get(url, timeout=15)
        hostname = urlparse(url).hostname
        
        print(f"\n{C}[*] Basic Info:{RESET}")
        print(f"  [*] Status: {r.status_code}")
        print(f"  [*] Server: {r.headers.get('Server', 'N/A')}")
        
        ssl_s = check_ssl(hostname) if url.startswith('https') else 0
        hdr_s, hdr_max = check_headers(r.headers)
        ck_s = check_cookies(r.cookies)
        rd_s = check_redirect(url) if url.startswith('https') else 0
        
        total = ssl_s + hdr_s + ck_s + rd_s
        max_total = 20 + hdr_max + 10 + 10
        pct = (total / max_total) * 100
        
        print(f"\n{C}{'═'*60}")
        print(f"  FINAL SCORE")
        print(f"{'═'*60}{RESET}")
        print(f"  SSL/TLS:   {ssl_s}/20")
        print(f"  Headers:   {hdr_s}/{hdr_max}")
        print(f"  Cookies:   {ck_s}/10")
        print(f"  Redirect:  {rd_s}/10")
        print(f"  {'─'*40}")
        print(f"  TOTAL:     {total}/{max_total} ({pct:.1f}%)")
        print(f"  Grade:     {grade(pct)}")
        print(f"{'═'*60}\n")
        
    except Exception as e:
        print(f"\n{R}[-] Error: {e}{RESET}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 http_analyzer_v7.py <url>")
        sys.exit(1)
    analyze(sys.argv[1])
