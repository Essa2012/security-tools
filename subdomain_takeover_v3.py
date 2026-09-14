#!/usr/bin/env python3
import socket
import requests
import sys
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# 200+ خدمة معروفة بـ Subdomain Takeover
VULNERABLE_SERVICES = {
    # ========== Cloud / Hosting ==========
    'github.io': 'GitHub Pages',
    'github.com': 'GitHub',
    'herokuapp.com': 'Heroku',
    'herokussl.com': 'Heroku SSL',
    's3.amazonaws.com': 'AWS S3',
    's3-website': 'AWS S3 Website',
    'cloudfront.net': 'AWS CloudFront',
    'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
    'elb.amazonaws.com': 'AWS ELB',
    'aws.amazon.com': 'AWS',
    'azurewebsites.net': 'Azure',
    'cloudapp.net': 'Azure Cloud',
    'cloudapp.azure.com': 'Azure',
    'azurestaticapps.net': 'Azure Static',
    'trafficmanager.net': 'Azure Traffic',
    'blob.core.windows.net': 'Azure Blob',
    'azureedge.net': 'Azure CDN',
    'azurefd.net': 'Azure Front Door',
    'digitaloceanspaces.com': 'DigitalOcean Spaces',
    'ondigitalocean.app': 'DigitalOcean App',
    'linode.com': 'Linode',
    'linodeobjects.com': 'Linode Objects',
    'vultr.com': 'Vultr',
    'vultrobjects.com': 'Vultr Objects',
    'netlify.app': 'Netlify',
    'netlify.com': 'Netlify',
    'vercel.app': 'Vercel',
    'vercel.com': 'Vercel',
    'now.sh': 'Vercel',
    'fly.dev': 'Fly.io',
    'fly.io': 'Fly.io',
    'render.com': 'Render',
    'onrender.com': 'Render',
    'surge.sh': 'Surge',
    'pages.dev': 'Cloudflare Pages',
    'workers.dev': 'Cloudflare Workers',
    'firebaseapp.com': 'Firebase',
    'web.app': 'Firebase Hosting',
    'firebaseio.com': 'Firebase Realtime',
    
    # ========== E-commerce ==========
    'shopify.com': 'Shopify',
    'myshopify.com': 'Shopify',
    'bigcartel.com': 'Big Cartel',
    'squarespace.com': 'Squarespace',
    'wixsite.com': 'Wix',
    'wix.com': 'Wix',
    'wordpress.com': 'WordPress',
    'wpengine.com': 'WP Engine',
    'pantheonsite.io': 'Pantheon',
    'ghost.io': 'Ghost',
    'webflow.io': 'Webflow',
    'webflow.com': 'Webflow',
    'sellfy.com': 'Sellfy',
    'gumroad.com': 'Gumroad',
    'ecwid.com': 'Ecwid',
    
    # ========== SaaS / Tools ==========
    'zendesk.com': 'Zendesk',
    'freshdesk.com': 'Freshdesk',
    'statuspage.io': 'Statuspage',
    'statuspage.com': 'Statuspage',
    'teamwork.com': 'Teamwork',
    'uservoice.com': 'UserVoice',
    'tumblr.com': 'Tumblr',
    'bitbucket.io': 'Bitbucket',
    'bitbucket.org': 'Bitbucket',
    'readthedocs.io': 'ReadTheDocs',
    'readme.io': 'ReadMe',
    'helpjuice.com': 'Helpjuice',
    'helpscoutdocs.com': 'Help Scout',
    'intercom.help': 'Intercom',
    'canny.io': 'Canny',
    'gitbook.io': 'GitBook',
    'surveymonkey.com': 'SurveyMonkey',
    'typeform.com': 'Typeform',
    'airtable.com': 'Airtable',
    'notion.site': 'Notion',
    'atlassian.net': 'Atlassian',
    'trello.com': 'Trello',
    'asana.com': 'Asana',
    'slack.com': 'Slack',
    'discord.gg': 'Discord',
    'discord.com': 'Discord',
    
    # ========== Marketing ==========
    'mailchimp.com': 'Mailchimp',
    'sendgrid.net': 'SendGrid',
    'hubspot.com': 'HubSpot',
    'marketo.com': 'Marketo',
    'pardot.com': 'Pardot',
    'unbounce.com': 'Unbounce',
    'leadpages.net': 'Leadpages',
    'instapage.com': 'Instapage',
    'landingi.com': 'Landingi',
    
    # ========== CDN / Other ==========
    'fastly.net': 'Fastly',
    'akamai.net': 'Akamai',
    'akamaized.net': 'Akamai',
    'cloudflare.net': 'Cloudflare',
    'cloudflare.com': 'Cloudflare',
    'jsdelivr.net': 'jsDelivr',
    'unpkg.com': 'unpkg',
    'cdnjs.cloudflare.com': 'cdnjs',
    'bootstrapcdn.com': 'BootstrapCDN',
    'gstatic.com': 'Google Static',
    'googleapis.com': 'Google APIs',
    'googleusercontent.com': 'Google User Content',
    
    # ========== Development ==========
    'ngrok.io': 'ngrok',
    'ngrok.com': 'ngrok',
    'localtunnel.me': 'localtunnel',
    'serveo.net': 'Serveo',
    'localhost.run': 'localhost.run',
    'pagekite.me': 'PageKite',
    'trycloudflare.com': 'Cloudflare Tunnel',
    
    # ========== CMS / Blogging ==========
    'medium.com': 'Medium',
    'substack.com': 'Substack',
    'ghost.org': 'Ghost',
    'blogger.com': 'Blogger',
    'blogspot.com': 'Blogspot',
    'weebly.com': 'Weebly',
    'jimdo.com': 'Jimdo',
    'strikingly.com': 'Strikingly',
    
    # ========== Forums ==========
    'discourse.org': 'Discourse',
    'vanillaforums.com': 'Vanilla Forums',
    'proboards.com': 'ProBoards',
    'forumotion.com': 'Forumotion',
    
    # ========== Analytics ==========
    'mixpanel.com': 'Mixpanel',
    'amplitude.com': 'Amplitude',
    'segment.com': 'Segment',
    'segment.io': 'Segment',
    'heap.io': 'Heap',
    'hotjar.com': 'Hotjar',
    'fullstory.com': 'FullStory',
    
    # ========== Other ==========
    'pantheon.io': 'Pantheon',
    'acquia.com': 'Acquia',
    'platform.sh': 'Platform.sh',
    'kinsta.com': 'Kinsta',
    'cloudwaysapps.com': 'Cloudways',
    'a2hosting.com': 'A2 Hosting',
    'siteground.com': 'SiteGround',
    'bluehost.com': 'Bluehost',
    'hostgator.com': 'HostGator',
    'godaddy.com': 'GoDaddy',
    'namecheap.com': 'Namecheap',
    'dreamhost.com': 'DreamHost',
    'inmotionhosting.com': 'InMotion',
}

# Services معروفة بصفحة "no such app"
TAKEOVER_INDICATORS = [
    'No such app',
    'There is no app',
    "doesn't exist",
    'NoSuchBucket',
    'The specified bucket does not exist',
    'Repository not found',
    'Project not found',
    'Not Found',
    '404 Not Found',
    'no such app',
    'isn\'t registered',
    'not configured',
    'No site configured',
    'The site you were looking for',
]

def check_cname(domain):
    """يفحص CNAME record"""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'CNAME')
        return str(answers[0].target).rstrip('.')
    except:
        return None

def check_takeover(domain):
    """يفحص إذا الـ Subdomain قابل للسيطرة"""
    cname = check_cname(domain)
    if not cname:
        return None
    
    # ابحث عن الخدمة
    for service, name in VULNERABLE_SERVICES.items():
        if service in cname.lower():
            try:
                r = requests.get(f"http://{domain}", timeout=5, 
                               headers={'User-Agent': 'Mozilla/5.0'},
                               allow_redirects=False)
                
                # فحص مؤشرات Takeover
                for indicator in TAKEOVER_INDICATORS:
                    if indicator.lower() in r.text.lower():
                        return {
                            'subdomain': domain,
                            'cname': cname,
                            'service': name,
                            'indicator': indicator,
                            'status': 'VULNERABLE'
                        }
                
                # فحص 404
                if r.status_code == 404:
                    return {
                        'subdomain': domain,
                        'cname': cname,
                        'service': name,
                        'indicator': 'HTTP 404',
                        'status': 'VULNERABLE'
                    }
                
                # فحص redirects
                if r.status_code in [301, 302]:
                    return {
                        'subdomain': domain,
                        'cname': cname,
                        'service': name,
                        'indicator': f'Redirect ({r.status_code})',
                        'status': 'POSSIBLE'
                    }
            except:
                pass
    return None

def scan_subdomains(domain):
    print(f"\n{'='*60}")
    print(f"  Subdomain Takeover Scanner v3")
    print(f"  Domain: {domain}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    subs = [
        'www', 'mail', 'blog', 'shop', 'store', 'api', 'dev', 'staging',
        'test', 'demo', 'admin', 'portal', 'app', 'mobile', 'cdn', 'static',
        'assets', 'img', 'images', 'video', 'docs', 'support', 'help',
        'status', 'news', 'forum', 'community', 'wiki', 'kb', 'auth',
        'login', 'sso', 'oauth', 'id', 'account', 'user', 'users',
        'dashboard', 'panel', 'cpanel', 'manage', 'management', 'backend',
        'frontend', 'web', 'webapp', 'website', 'landing', 'go', 'link',
        'links', 'url', 'redirect', 'track', 'analytics', 'metrics',
        'stats', 'data', 'db', 'database', 'backup', 'files', 'download',
        'downloads', 'upload', 'uploads', 'media', 'press', 'marketing',
        'sales', 'crm', 'erp', 'hr', 'jobs', 'careers', 'partners',
        'affiliate', 'refer', 'referral', 'promo', 'promotions',
        'beta', 'alpha', 'sandbox', 'stage', 'prod', 'production',
        'qa', 'uat', 'sys', 'system', 'internal', 'intranet', 'extranet',
        'vpn', 'remote', 'gateway', 'proxy', 'cache', 'sql',
        'redis', 'mongo', 'mysql', 'postgres', 'elastic', 'kibana',
        'grafana', 'prometheus', 'jenkins', 'gitlab', 'bitbucket',
        'jira', 'confluence', 'slack', 'teams', 'zoom', 'meet',
        'chat', 'talk', 'im', 'live', 'stream', 'video', 'audio',
        'pay', 'payment', 'checkout', 'cart', 'order', 'invoice',
        'blog', 'news', 'press', 'events', 'webinars', 'podcast',
        'learn', 'academy', 'training', 'course', 'university',
    ]
    
    print(f"[*] Testing {len(subs)} subdomains...\n")
    
    found = []
    completed = 0
    
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(check_takeover, f"{s}.{domain}"): s for s in subs}
        for future in as_completed(futures):
            completed += 1
            if completed % 20 == 0:
                print(f"  [*] Progress: {completed}/{len(subs)}")
            
            result = future.result()
            if result:
                found.append(result)
                print(f"\n  [!] {result['status']}: {result['subdomain']}")
                print(f"      CNAME: {result['cname']}")
                print(f"      Service: {result['service']}")
                print(f"      Indicator: {result['indicator']}\n")
    
    print(f"\n{'='*60}")
    print(f"  Found: {len(found)} vulnerable subdomains")
    print(f"{'='*60}\n")
    
    # Save HTML Report
    if found:
        filename = f"takeover_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Subdomain Takeover Report</title>
<style>
body {{ font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; }}
h1 {{ color: #00d9ff; }}
.card {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ff4444; }}
.vuln {{ color: #ff4444; font-weight: bold; }}
</style>
</head>
<body>
<h1>🚨 Subdomain Takeover Report</h1>
<p><strong>Domain:</strong> {domain}</p>
<p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><strong>Found:</strong> {len(found)} vulnerable subdomains</p>
<h2>Findings</h2>
"""
        for f in found:
            html += f"""
<div class="card">
<h3 class="vuln">{f['subdomain']}</h3>
<p><strong>CNAME:</strong> {f['cname']}</p>
<p><strong>Service:</strong> {f['service']}</p>
<p><strong>Indicator:</strong> {f['indicator']}</p>
<p><strong>Status:</strong> {f['status']}</p>
</div>
"""
        html += "</body></html>"
        
        with open(filename, 'w') as f:
            f.write(html)
        print(f"[+] HTML Report: {filename}\n")
    
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 subdomain_takeover_v3.py <domain>")
        print("Example: python3 subdomain_takeover_v3.py example.com")
        sys.exit(1)
    
    scan_subdomains(sys.argv[1])
