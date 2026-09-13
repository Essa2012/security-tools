#!/usr/bin/env python3
import hashlib
import requests
import sys

def check_password(password):
    """يفحص إذا كلمة السر في تسريب (Pwned Passwords API - مجاني)"""
    print(f"\n{'='*60}")
    print(f"  Password Breach Check")
    print(f"  Password: {'*' * len(password)}")
    print(f"{'='*60}\n")
    
    # SHA-1 hash
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    print(f"[*] SHA-1: {sha1[:10]}...")
    print(f"[*] Checking against Pwned Passwords DB...\n")
    
    try:
        # Pwned Passwords API
        r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=10)
        
        if r.status_code != 200:
            print(f"[-] API Error: {r.status_code}")
            return
        
        # ابحث عن suffix
        found = False
        for line in r.text.splitlines():
            parts = line.split(':')
            if len(parts) == 2:
                hash_suffix, count = parts
                if hash_suffix == suffix:
                    found = True
                    print(f"  [!] PASSWORD BREACHED!")
                    print(f"      Found in {count} breaches")
                    print(f"      ⚠️  Change this password immediately!")
                    break
        
        if not found:
            print(f"  [✓] Password NOT found in breaches")
            print(f"      Safe to use (for now)")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 password_checker.py <password>")
        print("Example: python3 password_checker.py password123")
        sys.exit(1)
    
    check_password(sys.argv[1])
