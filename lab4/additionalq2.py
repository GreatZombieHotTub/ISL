"""XYZ Logistics uses RSA for secure communication. 
Eve attempts to recover the RSA private key because the prime factors p and q are small or insufficiently random. 
Develop a Python program to demonstrate the attack and state methods to prevent it."""

from Crypto.Util.number import getPrime
from math import gcd, isqrt
import time


# =========================================================
# WEAK RSA KEY GENERATION
# =========================================================

def generate_weak_keys():

    # Deliberately small primes for demonstration
    p = getPrime(20)
    q = getPrime(20)

    while p == q:
        q = getPrime(20)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537

    if gcd(e, phi) != 1:
        return generate_weak_keys()

    d = pow(e, -1, phi)

    return p, q, n, e, d


# =========================================================
# FACTORING ATTACK
# =========================================================

def factor_n(n):

    for factor in range(2, isqrt(n) + 1):

        if n % factor == 0:
            return factor, n // factor

    return None, None


# =========================================================
# MAIN PROGRAM
# =========================================================

p, q, n, e, d = generate_weak_keys()

print("========== WEAK RSA ==========")
print("Public Key (e, n):", (e, n))
print("Actual Private d :", d)

message = "HI"

message_integer = int.from_bytes(
    message.encode(),
    "big"
)

# RSA encryption
ciphertext = pow(message_integer, e, n)

print("\nOriginal Message:", message)
print("Ciphertext      :", ciphertext)


# =========================================================
# EVE'S ATTACK
# =========================================================

start = time.perf_counter()

recovered_p, recovered_q = factor_n(n)

attack_time = time.perf_counter() - start

print("\n========== EVE'S ATTACK ==========")
print("Recovered p:", recovered_p)
print("Recovered q:", recovered_q)
print("Attack Time:", attack_time, "seconds")


# Calculate private key
recovered_phi = (
    (recovered_p - 1)
    * (recovered_q - 1)
)

recovered_d = pow(
    e,
    -1,
    recovered_phi
)

print("Recovered d:", recovered_d)


# Decrypt message
recovered_integer = pow(
    ciphertext,
    recovered_d,
    n
)

length = (
    recovered_integer.bit_length() + 7
) // 8

recovered_message = recovered_integer.to_bytes(
    length,
    "big"
).decode()

print("Recovered Message:", recovered_message)


# =========================================================
# MITIGATION
# =========================================================

print("\n========== MITIGATION ==========")
print("1. Use RSA keys of at least 2048 bits.")
print("2. Generate large and secure random primes.")
print("3. Never reuse p or q.")
print("4. Use RSA-OAEP padding.")
print("5. Store private keys securely.")
print("6. Revoke and renew compromised keys.")
