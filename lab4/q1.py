from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets


# =========================================================
# KEY MANAGEMENT SYSTEM
# =========================================================

class KeyManagementSystem:

    def __init__(self):
        self.keys = {}
        self.revoked = set()

    # Generate RSA key pair
    def generate_keys(self, system):
        key = RSA.generate(2048)

        self.keys[system] = {
            "private": key,
            "public": key.publickey()
        }

        print(f"Keys generated for {system}")

    # Distribute public key
    def get_public_key(self, system):
        if system in self.revoked:
            raise Exception("System key has been revoked")

        return self.keys[system]["public"]

    # Revoke keys
    def revoke_key(self, system):
        if system in self.keys:
            self.revoked.add(system)
            print(f"Keys revoked for {system}")


# =========================================================
# DIFFIE-HELLMAN
# =========================================================

def diffie_hellman():

    # Public parameters
    p = 23
    g = 5

    # Private values
    a = secrets.randbelow(p - 2) + 1
    b = secrets.randbelow(p - 2) + 1

    # Public values
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Shared secret
    key_alice = pow(B, a, p)
    key_bob = pow(A, b, p)

    print("\n--- Diffie-Hellman ---")
    print("Public prime (p):", p)
    print("Generator (g):", g)

    print("Alice public key:", A)
    print("Bob public key  :", B)

    print("Alice shared key:", key_alice)
    print("Bob shared key  :", key_bob)

    return key_alice


# =========================================================
# RSA DOCUMENT ENCRYPTION
# =========================================================

def rsa_encrypt(public_key, message):

    cipher = PKCS1_OAEP.new(public_key)

    encrypted = cipher.encrypt(message.encode())

    return encrypted


def rsa_decrypt(private_key, encrypted):

    cipher = PKCS1_OAEP.new(private_key)

    decrypted = cipher.decrypt(encrypted)

    return decrypted.decode()


# =========================================================
# MAIN PROGRAM
# =========================================================

kms = KeyManagementSystem()

# Create systems
systems = [
    "Finance System (A)",
    "HR System (B)",
    "Supply Chain System (C)"
]

# Generate keys
for system in systems:
    kms.generate_keys(system)


# ---------------------------------------------------------
# Diffie-Hellman key exchange
# ---------------------------------------------------------

shared_secret = diffie_hellman()


# ---------------------------------------------------------
# RSA encryption
# ---------------------------------------------------------

message = "Confidential Financial Report"

public_key = kms.get_public_key("Finance System (A)")
private_key = kms.keys["Finance System (A)"]["private"]

encrypted = rsa_encrypt(public_key, message)

print("\n--- RSA Encryption ---")
print("Original Message :", message)
print("Encrypted Data   :", encrypted.hex())

decrypted = rsa_decrypt(private_key, encrypted)

print("Decrypted Message:", decrypted)


# ---------------------------------------------------------
# Key Revocation
# ---------------------------------------------------------

print("\n--- Key Revocation ---")

kms.revoke_key("HR System (B)")

try:
    kms.get_public_key("HR System (B)")
except Exception as e:
    print("Access denied:", e)


# ---------------------------------------------------------
# Adding a new subsystem
# ---------------------------------------------------------

print("\n--- Adding New Subsystem ---")

kms.generate_keys("Research System (D)")