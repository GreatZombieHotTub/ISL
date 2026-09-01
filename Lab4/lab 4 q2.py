from Crypto.Util.number import getPrime, inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime, timedelta
import time

KEY_SIZE = 1024

# Stores keys for Hospital A, Clinic B, etc.
keys = {}

# Stores all important actions for auditing
logs = []


def log(msg):
    # Add timestamped message to the audit log
    logs.append(f"{datetime.now()} : {msg}")
    print("[LOG]", msg)


# ---------- Rabin Key Generation ----------

def generate_keys(name):
    start = time.perf_counter()

    # Generate a prime p of 512 bits.
    # Rabin requires p ≡ 3 (mod 4).
    p = getPrime(KEY_SIZE // 2)
    while p % 4 != 3:
        p = getPrime(KEY_SIZE // 2)

    # Generate another different prime q of 512 bits.
    # q must also satisfy q ≡ 3 (mod 4).
    q = getPrime(KEY_SIZE // 2)
    while q % 4 != 3 or q == p:
        q = getPrime(KEY_SIZE // 2)

    # Public key is n = p × q.
    # Private key consists of p and q.
    n = p * q

    # Store the key information for this facility
    keys[name] = {
        "public": n,
        "private": (p, q),
        "expiry": datetime.now() + timedelta(days=365),
        "revoked": False
    }

    t = time.perf_counter() - start
    log(f"Keys generated for {name}")

    print(f"\n{name}")
    print("Public Key (n):", n)
    print("Private Key p:", p)
    print("Private Key q:", q)
    print(f"Generation Time: {t:.6f}s")


# ---------- Key Distribution / Access ----------

def get_public(name):
    # Public key cannot be given if the facility does not exist
    # or its key has been revoked.
    if name not in keys or keys[name]["revoked"]:
        print("Public key unavailable!")
        return None

    log(f"Public key distributed to {name}")
    return keys[name]["public"]


def get_private(name, authorized=True):
    # Private key is only given to an authorized user.
    # It is also unavailable if the key was revoked.
    if not authorized or name not in keys or keys[name]["revoked"]:
        log(f"Private key access denied for {name}")
        print("Access Denied!")
        return None

    log(f"Authorized private key access for {name}")
    return keys[name]["private"]


# ---------- Rabin Encryption ----------

def encrypt(message, n):
    start = time.perf_counter()

    # Convert the text message into an integer.
    # Rabin encryption works mathematically on integers.
    m = int.from_bytes(message.encode(), "big")

    # The message integer must be smaller than n.
    if m >= n:
        raise ValueError("Message too large for key size")

    # Rabin encryption: c = m² mod n
    c = pow(m, 2, n)

    return c, time.perf_counter() - start


# ---------- Rabin Decryption ----------

def decrypt(c, p, q):
    start = time.perf_counter()

    n = p * q

    # Find the square root of c modulo p and q.
    # Since p and q are both 3 mod 4, these formulas work.
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    # Calculate modular inverses needed for the
    # Chinese Remainder Theorem (CRT).
    yp = inverse(p, q)
    yq = inverse(q, p)

    # CRT combines the roots modulo p and q
    # to produce the four possible roots modulo n.
    r1 = (yp*p*mq + yq*q*mp) % n
    r2 = n - r1
    r3 = (yp*p*mq - yq*q*mp) % n
    r4 = n - r3

    return [r1, r2, r3, r4], time.perf_counter() - start


# ---------- Revocation ----------

def revoke(name):
    # Mark the facility's key as revoked.
    # After this, the key cannot be accessed normally.
    keys[name]["revoked"] = True
    log(f"Key revoked for {name}")


# ---------- Renewal ----------

def renew(name):
    # Generate a completely new pair of Rabin keys.
    log(f"Renewing key for {name}")
    generate_keys(name)


# ---------- Register Facilities ----------

# Generate keys for two healthcare facilities.
generate_keys("Hospital A")
generate_keys("Clinic B")


# ---------- Rabin Demonstration ----------

message = "Patient Record 123"
print("\nPlaintext:", message)

# Get Hospital A's public key for encryption.
n = get_public("Hospital A")

# Get Hospital A's private key for decryption.
private = get_private("Hospital A")

p, q = private

# Encrypt the plaintext using the public key n.
ciphertext, enc_time = encrypt(message, n)

print("\nRabin Ciphertext:", ciphertext)
print(f"Encryption Time: {enc_time:.6f}s")

# Decryption produces FOUR possible plaintext roots.
roots, dec_time = decrypt(ciphertext, p, q)

print("\nFour Possible Roots:")
for r in roots:
    print(r)

# Convert the original message to an integer so we can
# check whether it is one of the four possible roots.
original = int.from_bytes(message.encode(), "big")

if original in roots:
    print("\nDecrypted Text:", message)
else:
    print("\nOriginal plaintext not identified")

print(f"Decryption Time: {dec_time:.6f}s")


# ---------- Revocation ----------

print("\n--- Revocation ---")

# Revoke Clinic B's key.
# This means its public/private key should no longer be available.
revoke("Clinic B")


# ---------- Key Renewal ----------

print("\n--- Key Renewal ---")

# Generate a fresh key pair for Hospital A.
renew("Hospital A")


# ---------- Expiry Check ----------

print("\n--- Expiry Check ---")

# Check whether each facility's key has expired.
for name in keys:
    if datetime.now() >= keys[name]["expiry"]:
        # If expired, generate a new key pair.
        renew(name)
    else:
        print(name, "key is valid until", keys[name]["expiry"])


# ---------- Audit Log ----------

print("\n--- Audit Log ---")

# Display all recorded key-management activities.
for x in logs:
    print(x)


# ---------- RSA Comparison ----------

print("\n--- RSA Comparison ---")

# Generate a 1024-bit RSA key pair and measure the time.
start = time.perf_counter()
rsa_key = RSA.generate(KEY_SIZE)
rsa_key_time = time.perf_counter() - start

# Create an RSA-OAEP cipher using the public key.
# OAEP provides secure padding for RSA encryption.
cipher = PKCS1_OAEP.new(rsa_key.publickey())

# Encrypt the same message using RSA.
start = time.perf_counter()
rsa_cipher = cipher.encrypt(message.encode())
rsa_enc_time = time.perf_counter() - start

# Create another cipher using the private key for decryption.
cipher = PKCS1_OAEP.new(rsa_key)

# Decrypt the RSA ciphertext.
start = time.perf_counter()
rsa_plain = cipher.decrypt(rsa_cipher).decode()
rsa_dec_time = time.perf_counter() - start

# Display RSA performance and the decrypted message.
print(f"RSA Key Generation: {rsa_key_time:.6f}s")
print(f"RSA Encryption:     {rsa_enc_time:.6f}s")
print(f"RSA Decryption:     {rsa_dec_time:.6f}s")
print("RSA Decrypted Text:", rsa_plain)
