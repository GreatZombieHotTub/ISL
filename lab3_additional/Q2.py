#ECC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


message = b"Secure Transactions"

# Recipient private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Recipient public key
public_key = private_key.public_key()


# ---------------- ENCRYPTION ----------------

# Generate temporary/ephemeral private key
ephemeral_private = ec.generate_private_key(ec.SECP256R1())

ephemeral_public = ephemeral_private.public_key()

# Generate shared secret
shared_secret = ephemeral_private.exchange(
    ec.ECDH(),
    public_key
)

# Convert shared secret into AES key
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECIES"
).derive(shared_secret)

# AES encryption
nonce = os.urandom(12)

cipher = AESGCM(aes_key)

ciphertext = cipher.encrypt(
    nonce,
    message,
    None
)


print("Original Message:", message.decode())
print("Ciphertext:", ciphertext.hex().upper())


# ---------------- DECRYPTION ----------------

# Recipient calculates same shared secret
shared_secret2 = private_key.exchange(
    ec.ECDH(),
    ephemeral_public
)

# Generate same AES key
aes_key2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECIES"
).derive(shared_secret2)

# AES decryption
cipher2 = AESGCM(aes_key2)

decrypted = cipher2.decrypt(
    nonce,
    ciphertext,
    None
)

print("Decrypted Message:", decrypted.decode())