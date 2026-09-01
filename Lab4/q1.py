from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time

# Key Management System
systems = {}

def add_system(name):
    start = time.perf_counter()
    key = RSA.generate(2048)

    systems[name] = {
        "public": key.publickey(),
        "private": key,
        "revoked": False
    }

    print(f"\n{name} Key Generation Time: {time.perf_counter()-start:.6f}s")
    print("Public Key:\n", key.publickey().export_key().decode())
    print("Private Key:\n", key.export_key().decode())

def revoke(name):
    systems[name]["revoked"] = True
    print(f"\n{name} key revoked!")

# Generate keys
add_system("Finance")
add_system("HR")
add_system("Supply Chain")

# RSA Communication
message = "Confidential Financial Report"

print("\nPlaintext:", message)

receiver = systems["HR"]

cipher = PKCS1_OAEP.new(receiver["public"])

start = time.perf_counter()
ciphertext = cipher.encrypt(message.encode())
enc_time = time.perf_counter() - start

print("\nCiphertext:", ciphertext.hex())
print("Encryption Time:", enc_time)

cipher = PKCS1_OAEP.new(receiver["private"])

start = time.perf_counter()
decrypted = cipher.decrypt(ciphertext).decode()
dec_time = time.perf_counter() - start

print("\nDecrypted Text:", decrypted)
print("Decryption Time:", dec_time)


# Diffie-Hellman Key Exchange
print("\n--- Diffie-Hellman ---")

p, g = 23, 5
a, b = 6, 15

A = pow(g, a, p)
B = pow(g, b, p)

key1 = pow(B, a, p)
key2 = pow(A, b, p)

print("Finance Public Value:", A)
print("HR Public Value:", B)
print("Shared Key:", key1)

# Key Revocation
revoke("Supply Chain")