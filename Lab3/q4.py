import os
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# Create test files
def create_file(name, size):
    with open(name, "wb") as f:
        f.write(os.urandom(size))

create_file("file_1MB.bin", 1 * 1024 * 1024)
create_file("file_10MB.bin", 10 * 1024 * 1024)


# RSA keys
start = time.perf_counter()
rsa_private = RSA.generate(2048)
rsa_public = rsa_private.publickey()
rsa_key_time = time.perf_counter() - start

# ECC keys
start = time.perf_counter()
ecc_private = ec.generate_private_key(ec.SECP256R1())
ecc_public = ecc_private.public_key()
ecc_key_time = time.perf_counter() - start


# Display keys
print("\nRSA Public Key:\n", rsa_public.export_key().decode())
print("\nRSA Private Key:\n", rsa_private.export_key().decode())

print("\nECC Private Key:\n", ecc_private.private_numbers().private_value)

ecc_pub = ecc_public.public_numbers()
print("\nECC Public Key:")
print("x =", ecc_pub.x)
print("y =", ecc_pub.y)

print("\nRSA Key Generation Time:", rsa_key_time)
print("ECC Key Generation Time:", ecc_key_time)


# RSA encryption
def rsa_encrypt(filename):
    with open(filename, "rb") as f:
        data = f.read()

    key = get_random_bytes(32)
    encrypted_key = PKCS1_OAEP.new(rsa_public).encrypt(key)

    aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = aes.encrypt_and_digest(data)

    return encrypted_key, aes.nonce, tag, ciphertext


# RSA decryption
def rsa_decrypt(data):
    encrypted_key, nonce, tag, ciphertext = data
    key = PKCS1_OAEP.new(rsa_private).decrypt(encrypted_key)

    aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return aes.decrypt_and_verify(ciphertext, tag)


# ECC shared AES key
receiver_private = ec.generate_private_key(ec.SECP256R1())
receiver_public = receiver_private.public_key()

secret = ecc_private.exchange(ec.ECDH(), receiver_public)

ecc_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"File Encryption"
).derive(secret)


# ECC encryption
def ecc_encrypt(filename):
    with open(filename, "rb") as f:
        data = f.read()

    aes = AES.new(ecc_key, AES.MODE_EAX)
    ciphertext, tag = aes.encrypt_and_digest(data)

    return aes.nonce, tag, ciphertext


# ECC decryption
def ecc_decrypt(data):
    nonce, tag, ciphertext = data
    aes = AES.new(ecc_key, AES.MODE_EAX, nonce=nonce)
    return aes.decrypt_and_verify(ciphertext, tag)


# Performance test
for filename in ["file_1MB.bin", "file_10MB.bin"]:
    print("\n------------------------------")
    print(filename)
    print("------------------------------")

    start = time.perf_counter()
    rsa_data = rsa_encrypt(filename)
    rsa_enc_time = time.perf_counter() - start

    start = time.perf_counter()
    rsa_plain = rsa_decrypt(rsa_data)
    rsa_dec_time = time.perf_counter() - start

    start = time.perf_counter()
    ecc_data = ecc_encrypt(filename)
    ecc_enc_time = time.perf_counter() - start

    start = time.perf_counter()
    ecc_plain = ecc_decrypt(ecc_data)
    ecc_dec_time = time.perf_counter() - start

    print("RSA Encryption :", rsa_enc_time, "seconds")
    print("RSA Decryption :", rsa_dec_time, "seconds")
    print("ECC Encryption :", ecc_enc_time, "seconds")
    print("ECC Decryption :", ecc_dec_time, "seconds")