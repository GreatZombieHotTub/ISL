"""
4. You are tasked with implementing a secure communication system for a healthcare
organization to exchange sensitive patient information securely between doctors and hospitals.
Implement the ElGamal encryption scheme to encrypt patient records and medical data,
ensuring confidentiality during transmission. Generate public and private keys using the
secp256r1 curve and use ElGamal encryption to encrypt patient data with the recipient's public
key and decrypt it with the recipient's private key. Measure the performance of encryption and
decryption processes for data of varying sizes.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import os
import time


# ---------------- KEY GENERATION ----------------

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()


def encrypt_data(data):

    # Ephemeral key
    ephemeral_private = ec.generate_private_key(
        ec.SECP256R1()
    )

    ephemeral_public = ephemeral_private.public_key()

    # Shared secret
    shared_secret = ephemeral_private.exchange(
        ec.ECDH(),
        public_key
    )

    # AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Healthcare"
    ).derive(shared_secret)

    nonce = os.urandom(12)

    cipher = AESGCM(aes_key)

    ciphertext = cipher.encrypt(
        nonce,
        data,
        None
    )

    return ephemeral_public, nonce, ciphertext


def decrypt_data(ephemeral_public, nonce, ciphertext):

    shared_secret = private_key.exchange(
        ec.ECDH(),
        ephemeral_public
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Healthcare"
    ).derive(shared_secret)

    cipher = AESGCM(aes_key)

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext


# ---------------- PERFORMANCE TEST ----------------

sizes = [
    1024, #1KB
    10 * 1024, ##10KB
    100 * 1024 #100KB
]

#This repeats the text and then trims it to exactly size bytes.
for size in sizes:

    data = b"Patient medical record " * (
        size // len(b"Patient medical record ") + 1
    )
    data = data[:size]

    # Encryption time
    start = time.perf_counter()

    ephemeral_public, nonce, ciphertext = encrypt_data(data)

    encryption_time = time.perf_counter() - start

    # Decryption time
    start = time.perf_counter()

    decrypted = decrypt_data(
        ephemeral_public,
        nonce,
        ciphertext
    )

    decryption_time = time.perf_counter() - start

    print("\nData Size:", size, "bytes")
    print("Encryption Time:", encryption_time)
    print("Decryption Time:", decryption_time)
    print("Correct:", data == decrypted)
