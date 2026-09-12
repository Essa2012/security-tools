#!/usr/bin/env python3
import sys
import os
import re
import zipfile
from datetime import datetime

PATTERNS = {
    'API Key': r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
    'Secret': r'(?i)(secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
    'AWS Key': r'(AKIA[0-9A-Z]{16})',
    'Google API': r'(AIza[0-9A-Za-z\-_]{35})',
    'Firebase': r'(https://[a-z0-9\-]+\.firebaseio\.com)',
    'Private Key': r'(-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----)',
    'JWT Token': r'(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)',
    'Email': r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    'IP Address': r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)',
    'URL': r'(https?://[^\s"\']+)',
}

DANGEROUS_PERMISSIONS = [
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.INTERNET',
    'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.RECEIVE_BOOT_COMPLETED',
    'android.permission.SYSTEM_ALERT_WINDOW',
]

def extract_apk(apk_path):
    print(f"[*] Extracting APK: {apk_path}")
    output_dir = apk_path.replace('.apk', '_extracted')
    os.makedirs(output_dir, exist_ok=True)
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            z.extractall(output_dir)
        print(f"[+] Extracted to: {output_dir}")
        return output_dir
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def scan_files(directory):
    print(f"\n[*] Scanning files...")
    findings = {pattern: [] for pattern in PATTERNS}
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.xml', '.json', '.txt', '.properties', '.smali', '.java', '.kt')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                        for pattern_name, pattern in PATTERNS.items():
                            matches = re.findall(pattern, content)
                            for match in matches:
                                if isinstance(match, tuple):
                                    match = match[-1]
                                if len(match) > 8:
                                    findings[pattern_name].append({
                                        'file': filepath,
                                        'value': match[:100]
                                    })
                except:
                    pass
    return findings

def check_permissions(directory):
    print(f"\n[*] Checking permissions...")
    manifest = os.path.join(directory, 'AndroidManifest.xml')
    if not os.path.exists(manifest):
        for root, dirs, files in os.walk(directory):
            if 'AndroidManifest.xml' in files:
                manifest = os.path.join(root, 'AndroidManifest.xml')
                break
    permissions = []
    try:
        with open(manifest, 'rb') as f:
            content = f.read()
            for perm in DANGEROUS_PERMISSIONS:
                if perm.encode() in content:
                    permissions.append(perm)
    except:
        pass
    return permissions

def scan_apk(apk_path):
    print(f"\n{'='*60}")
    print(f"  Mobile APK Security Scanner")
    print(f"  APK: {apk_path}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    if not os.path.exists(apk_path):
        print(f"[-] File not found: {apk_path}")
        return
    
    directory = extract_apk(apk_path)
    if not directory:
        return
    
    findings = scan_files(directory)
    permissions = check_permissions(directory)
    
    print(f"\n{'='*60}")
    print(f"  FINDINGS")
    print(f"{'='*60}\n")
    
    total = 0
    for pattern_name, matches in findings.items():
        if matches:
            print(f"\n[!] {pattern_name}: {len(matches)} found")
            for match in matches[:5]:
                print(f"    File: {match['file']}")
                print(f"    Value: {match['value']}")
                print()
            total += len(matches)
    
    if permissions:
        print(f"\n[!] Dangerous Permissions: {len(permissions)} found")
        for perm in permissions:
            print(f"    {perm}")
    
    print(f"\n{'='*60}")
    print(f"  Total findings: {total}")
    print(f"  Permissions: {len(permissions)}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 apk_scanner.py <app.apk>")
        sys.exit(1)
    
    scan_apk(sys.argv[1])
