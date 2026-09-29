"""
Password Hashing Educational Demonstration Module
Demonstrates modern, industry-standard password hashing functions:
PBKDF2-HMAC-SHA256, scrypt, and bcrypt (if available).

CRITICAL SECURITY EDUCATION:
1. Hashing is a ONE-WAY cryptographic transformation; it cannot be 'decrypted'.
2. General-purpose fast hashes (MD5, SHA-1, SHA-256) are INAPPROPRIATE for passwords
   because modern GPUs can compute billions of hashes per second.
3. Password hashing functions use a unique cryptographic Salt and Key Stretching
   (tunable CPU/Memory work factors) to defeat rainbow tables and hardware cracking.
"""
import os
import hashlib
import hmac
import base64
import time
from typing import Dict, Any, Tuple

def demo_hash_pbkdf2(password: str, iterations: int = 600_000) -> Dict[str, Any]:
    """
    Demonstrates PBKDF2-HMAC-SHA256 with OWASP recommended iteration counts (600,000+).
    Uses a cryptographically random 16-byte salt.
    """
    start_time = time.perf_counter()
    salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hash_b64 = base64.b64encode(derived_key).decode('utf-8')
    formatted_record = f"$pbkdf2-sha256$i={iterations}${salt_b64}${hash_b64}"
    
    return {
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt_hex": salt.hex(),
        "hash_record": formatted_record,
        "elapsed_ms": round(elapsed_ms, 2),
        "explanation": "CPU-bound key stretching using iterated HMAC-SHA256."
    }

def demo_verify_pbkdf2(password: str, hash_record: str) -> bool:
    """
    Demonstrates constant-time verification of a PBKDF2 hash record.
    Uses hmac.compare_digest to prevent side-channel timing attacks.
    """
    try:
        parts = hash_record.split('$')
        # Format: ['', 'pbkdf2-sha256', 'i=600000', 'salt_b64', 'hash_b64']
        iterations = int(parts[2].split('=')[1])
        salt = base64.b64decode(parts[3])
        expected_hash = base64.b64decode(parts[4])
        
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        return hmac.compare_digest(derived_key, expected_hash)
    except Exception:
        return False

def demo_hash_scrypt(password: str, n: int = 16384, r: int = 8, p: int = 1) -> Dict[str, Any]:
    """
    Demonstrates scrypt, a memory-hard password hashing function.
    N: CPU/memory cost parameter (16384 default)
    r: block size (8)
    p: parallelization parameter (1)
    """
    start_time = time.perf_counter()
    salt = os.urandom(16)
    derived_key = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=n,
        r=r,
        p=p,
        maxmem=0,
        dklen=64
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hash_b64 = base64.b64encode(derived_key).decode('utf-8')
    formatted_record = f"$scrypt$ln={n},r={r},p={p}${salt_b64}${hash_b64}"
    
    return {
        "algorithm": "scrypt (Memory-Hard)",
        "cost_params": f"N={n}, r={r}, p={p}",
        "salt_hex": salt.hex(),
        "hash_record": formatted_record,
        "elapsed_ms": round(elapsed_ms, 2),
        "explanation": "Memory-hard function designed specifically to neutralize ASIC/FPGA hardware attacks."
    }

def print_educational_summary():
    """Prints a comparison table of password storage methods."""
    print("=" * 80)
    print("CYBERSECURITY CONCEPT: PLAINTEXT vs FAST HASH vs SLOW PASSWORD HASH")
    print("=" * 80)
    print("""
1. PLAINTEXT PASSWORD STORAGE:
   - Catastrophic failure: A SQL injection or database backup leak directly exposes
     all user passwords, enabling immediate credential stuffing across other services.

2. FAST HASHES (e.g. SHA-256, MD5):
   - Designed for file integrity and speed (gigabytes per second).
   - Insecure for passwords: An attacker with a modern RTX 4090 GPU can calculate
     over 10,000,000,000 (10 billion) SHA-256 hashes per second!
   - Result: Any 8-character password is recovered in seconds.

3. SLOW, SALTED PASSWORD HASHING FUNCTIONS (Argon2id, scrypt, bcrypt, PBKDF2):
   - Cryptographic Salt: A unique random 16-byte nonce per password.
     Prevents Rainbow Tables and ensures two identical passwords produce completely
     different hashes.
   - Work Factor (Cost Parameter): Deliberately consumes 100-300ms of CPU and memory.
     Makes offline cracking economically and computationally impractical for attackers.
   - Timing Protection: Verification uses constant-time comparison (hmac.compare_digest)
     to prevent side-channel timing analysis.
    """)
    print("=" * 80)

if __name__ == "__main__":
    print_educational_summary()
    synthetic_demo_password = "Correct-Horse-Battery-Staple-2026!"
    print(f"\n[DEMO] Demonstrating hashing with synthetic password: {synthetic_demo_password}\n")
    
    # 1. PBKDF2 demo
    pbkdf2_res = demo_hash_pbkdf2(synthetic_demo_password, iterations=100_000)
    print(f"Algorithm:   {pbkdf2_res['algorithm']}")
    print(f"Salt (hex):  {pbkdf2_res['salt_hex']}")
    print(f"Hash String: {pbkdf2_res['hash_record']}")
    print(f"Compute Time:{pbkdf2_res['elapsed_ms']} ms")
    
    # Verification test
    is_valid = demo_verify_pbkdf2(synthetic_demo_password, pbkdf2_res['hash_record'])
    print(f"Verification Check: {'SUCCESS (Valid password matched)' if is_valid else 'FAILED'}")
    
    # Negative verification test
    is_invalid = demo_verify_pbkdf2("WrongPassword123!", pbkdf2_res['hash_record'])
    print(f"Wrong Password Check: {'REJECTED (Correctly detected mismatch)' if not is_invalid else 'FAILED'}")
    
    print("\n" + "-" * 80 + "\n")
    
    # 2. scrypt demo
    scrypt_res = demo_hash_scrypt(synthetic_demo_password)
    print(f"Algorithm:   {scrypt_res['algorithm']}")
    print(f"Parameters:  {scrypt_res['cost_params']}")
    print(f"Hash String: {scrypt_res['hash_record']}")
    print(f"Compute Time:{scrypt_res['elapsed_ms']} ms")
    print("=" * 80)
