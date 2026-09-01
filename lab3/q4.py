"""
Design and implement a secure file transfer system using RSA (2048-bit) and ECC (secp256r1 
curve) public key algorithms. Generate and exchange keys, then encrypt and decrypt files of 
varying sizes (e.g., 1 MB, 10 MB) using both algorithms. Measure and compare the 
performance in terms of key generation time, encryption/decryption speed, and computational 
overhead. Evaluate the security and efficiency of each algorithm in the context of file transfer, 
considering factors such as key size, storage requirements, and resistance to known attacks. 
Document your findings, including performance metrics and a summary of the strengths and 
weaknesses of RSA and ECC for secure file transfer. 
"""
import os
import time

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CREATE TEST FILES
# ============================================================

def create_test_file(filename, size_mb):
    data = os.urandom(size_mb * 1024 * 1024)

    with open(filename, "wb") as f:
        f.write(data)


create_test_file("file_1MB.bin", 1)
create_test_file("file_10MB.bin", 10)


# ============================================================
# RSA KEY GENERATION
# ============================================================

start = time.perf_counter()

rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

rsa_public_key = rsa_private_key.public_key()

rsa_keygen_time = time.perf_counter() - start


# ============================================================
# ECC KEY GENERATION
# ============================================================

start = time.perf_counter()

ecc_private_key = ec.generate_private_key(
    ec.SECP256R1()
)

ecc_public_key = ecc_private_key.public_key()

ecc_keygen_time = time.perf_counter() - start


print("\nKEY GENERATION")
print("-------------------------")
print(f"RSA-2048 : {rsa_keygen_time:.6f} seconds")
print(f"ECC       : {ecc_keygen_time:.6f} seconds")


# ============================================================
# AES FILE ENCRYPTION
# ============================================================

def aes_encrypt_file(input_file, output_file, aes_key):

    start = time.perf_counter()

    with open(input_file, "rb") as f:
        data = f.read()

    nonce = os.urandom(12)

    aes = AESGCM(aes_key)

    encrypted_data = aes.encrypt(
        nonce,
        data,
        None
    )

    with open(output_file, "wb") as f:
        f.write(nonce)
        f.write(encrypted_data)

    return time.perf_counter() - start


# ============================================================
# AES FILE DECRYPTION
# ============================================================

def aes_decrypt_file(input_file, output_file, aes_key):

    start = time.perf_counter()

    with open(input_file, "rb") as f:
        nonce = f.read(12)
        encrypted_data = f.read()

    aes = AESGCM(aes_key)

    decrypted_data = aes.decrypt(
        nonce,
        encrypted_data,
        None
    )

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    return time.perf_counter() - start


# ============================================================
# RSA SESSION KEY PROTECTION
# ============================================================

aes_key = AESGCM.generate_key(bit_length=256)

start = time.perf_counter()

encrypted_aes_key = rsa_public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

rsa_encrypt_key_time = time.perf_counter() - start


start = time.perf_counter()

decrypted_aes_key = rsa_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

rsa_decrypt_key_time = time.perf_counter() - start


# ============================================================
# ECC SHARED KEY
# ============================================================

# Sender's temporary ECC key
sender_private = ec.generate_private_key(
    ec.SECP256R1()
)

sender_public = sender_private.public_key()

start = time.perf_counter()

shared_secret_sender = sender_private.exchange(
    ec.ECDH(),
    ecc_public_key
)

ecc_exchange_time = time.perf_counter() - start


# Receiver calculates same shared secret

shared_secret_receiver = ecc_private_key.exchange(
    ec.ECDH(),
    sender_public
)


# Derive AES key

ecc_aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"Secure File Transfer"
).derive(shared_secret_sender)


# Verify both sides derived same key

ecc_aes_key_receiver = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"Secure File Transfer"
).derive(shared_secret_receiver)


print("\nECC SHARED KEY")
print("-------------------------")
print("Keys match:", ecc_aes_key == ecc_aes_key_receiver)


# ============================================================
# FILE PERFORMANCE TEST
# ============================================================

for filename in ["file_1MB.bin", "file_10MB.bin"]:

    encrypted_file = filename + ".enc"
    decrypted_file = filename + ".dec"

    print("\nFILE:", filename)
    print("-------------------------")

    # Encrypt
    encryption_time = aes_encrypt_file(
        filename,
        encrypted_file,
        aes_key
    )

    print(
        f"AES Encryption: "
        f"{encryption_time:.6f} seconds"
    )

    # Decrypt
    decryption_time = aes_decrypt_file(
        encrypted_file,
        decrypted_file,
        aes_key
    )

    print(
        f"AES Decryption: "
        f"{decryption_time:.6f} seconds"
    )

    # Verify
    with open(filename, "rb") as f1:
        original = f1.read()

    with open(decrypted_file, "rb") as f2:
        decrypted = f2.read()

    print("File verified:", original == decrypted)


# ============================================================
# FINAL COMPARISON
# ============================================================

print("\n================================")
print("FINAL PERFORMANCE COMPARISON")
print("================================")

print(f"RSA-2048 key generation : {rsa_keygen_time:.6f} s")
print(f"ECC key generation      : {ecc_keygen_time:.6f} s")
print(f"RSA key encryption      : {rsa_encrypt_key_time:.6f} s")
print(f"RSA key decryption      : {rsa_decrypt_key_time:.6f} s")
print(f"ECC key exchange        : {ecc_exchange_time:.6f} s")

print("\nFile encryption/decryption is performed using AES.")
