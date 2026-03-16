#!/usr/bin/env python3
"""PBKDF2-HMAC-SHA256 key derivation."""
import hashlib, hmac, struct, sys

def pbkdf2(password, salt, iterations=10000, dk_len=32):
    if isinstance(password, str): password = password.encode()
    if isinstance(salt, str): salt = salt.encode()
    blocks = (dk_len + 31) // 32; dk = b""
    for i in range(1, blocks + 1):
        u = hmac.new(password, salt + struct.pack(">I", i), hashlib.sha256).digest()
        result = bytearray(u)
        for _ in range(iterations - 1):
            u = hmac.new(password, u, hashlib.sha256).digest()
            for j in range(len(result)): result[j] ^= u[j]
        dk += bytes(result)
    return dk[:dk_len].hex()

if __name__ == "__main__":
    password = sys.argv[1] if len(sys.argv) > 1 else "password123"
    salt = "random_salt"
    derived = pbkdf2(password, salt, iterations=1000)
    ref = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 1000).hex()
    print(f"Password: {password}")
    print(f"Mine:   {derived}")
    print(f"Stdlib: {ref}")
    print(f"Match:  {derived == ref}")
