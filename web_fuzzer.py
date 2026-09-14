#!/usr/bin/env python3
import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

HEADERS = {'User-Agent': 'Mozilla/5.0 (Security-Scanner)'}

# مسارات شائعة
PATHS = [
    # Admin
    'admin', 'administrator', 'admin.php', 'admin.html', 'admin/',
    'panel', 'cpanel', 'dashboard', 'manage', 'management',
    'wp-admin', 'wp-login.php', 'wp-content', 'wp-includes',
    
    # Auth
    'login', 'signin', 'signup', 'register', 'logout',
    'auth', 'oauth', 'sso', 'api/auth',
    
    # API
    'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql',
    'api/users', 'api/admin', 'api/config', 'api/health',
    
    # Config
    'config', 'config.php', 'configuration', 'settings',
    'setup', 'install', 'env', '.env', 'config.json',
    
    # Backup
    'backup', 'backups', 'backup.zip', 'backup.sql', 'backup.tar.gz',
    'dump', 'dump.sql', 'db.sql', 'database.sql',
    
    # Files
    'files', 'uploads', 'downloads', 'media', 'images', 'img',
    'assets', 'static', 'css', 'js', 'scripts',
    
    # Docs
    'docs', 'documentation', 'readme', 'readme.md', 'readme.txt',
    'changelog', 'license', 'robots.txt', 'sitemap.xml',
    
    # Dev
    'dev', 'development', 'test', 'testing', 'staging', 'stage',
    'beta', 'alpha', 'demo', 'sandbox', 'qa',
    
    # Security
    'security', 'private', 'secret', 'hidden', 'internal',
    'logs', 'log', 'error', 'errors', 'debug',
    
    # Other
    'user', 'users', 'account', 'profile', 'members',
    'shop', 'store', 'cart', 'checkout', 'payment',
    'blog', 'news', 'articles', 'posts', 'forum',
    'contact', 'about', 'help', 'support', 'faq',
    'status', 'health', 'metrics', 'stats', 'analytics',
]

def get_baseline(url):
    """يحصل على baseline (حجم الصفحة الرئيسية)"""
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        return len(r.text), r.status_code
    except:
        return 0, 0

def get_random_size(url):
    """يحصل على حجم صفحة عشوائية (Catch-all)"""
    try:
        r = requests.get(f"{url}/random-xyz-123-nonexistent", headers=HEADERS, timeout=10, allow_redirects=False)
        return len(r.text), r.status_code
    except:
        return 0, 0

def test_path(url, path, baseline_size, random_size):
    """يختبر مسار"""
    try:
        full_url = f"{url.rstrip('/')}/{path}"
        r = requests.get(full_url, headers=HEADERS, timeout=10, allow_redirects=False)
        
        size = len(r.text)
        status = r.status_code
        
        # تجاهل لو نفس حجم الصفحة العشوائية (Catch-all)
        if random_size > 0 and abs(size - random_size) < 100:
            return None
        
        # اهتم بـ 200، 301، 302، 403
        if status in [200, 301, 302, 403]:
            return {
                'path': path,
                'status': status,
                'size': size,
                'url': full_url,
                'diff': abs(size - baseline_size)
            }
    except:
        pass
    return None

def fuzz(url):
    print(f"\n{'='*60}")
    print(f"  Web Fuzzer")
    print(f"  Target: {url}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    # Baseline
    print(f"[*] Getting baseline...")
    baseline_size, baseline_status = get_baseline(url)
    print(f"  Main page: {baseline_size} bytes (status: {baseline_status})")
    
    # Random (Catch-all test)
    print(f"[*] Testing catch-all...")
    random_size, random_status = get_random_size(url)
    print(f"  Random page: {random_size} bytes (status: {random_status})")
    
    is_spa = (random_size == baseline_size) and (baseline_size > 0)
    if is_spa:
        print(f"  [!] SPA detected (Catch-all) — filtering false positives")
    
    print(f"\n[*] Testing {len(PATHS)} paths...\n")
    
    found = []
    
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(test_path, url, p, baseline_size, random_size): p for p in PATHS}
        for future in futures:
            result = future.result()
            if result:
                found.append(result)
                print(f"  [+] /{result['path']:30s} → {result['status']} ({result['size']} bytes)")
    
    print(f"\n{'='*60}")
    print(f"  Found: {len(found)} paths")
    print(f"{'='*60}\n")
    
    # Save Report
    if found:
        filename = f"fuzz_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Web Fuzzer Report</title>
<style>
body {{ font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; }}
h1 {{ color: #00d9ff; }}
.card {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #00ff88; }}
.ok {{ color: #00ff88; }}
table {{ width: 100%; border-collapse: collapse; }}
td, th {{ padding: 8px; text-align: left; border-bottom: 1px solid #333; }}
</style>
</head>
<body>
<h1>🔍 Web Fuzzer Report</h1>
<p><strong>Target:</strong> {url}</p>
<p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><strong>Found:</strong> {len(found)} paths</p>
<h2>Paths</h2>
<table>
<tr><th>Path</th><th>Status</th><th>Size</th></tr>
"""
        for f in found:
            html += f"<tr><td>/{f['path']}</td><td>{f['status']}</td><td>{f['size']}</td></tr>"
        html += "</table></body></html>"
        
        with open(filename, 'w') as f:
            f.write(html)
        print(f"[+] Report: {filename}\n")
    
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 web_fuzzer.py <url>")
        print("Example: python3 web_fuzzer.py https://example.com")
        sys.exit(1)
    
    fuzz(sys.argv[1])
