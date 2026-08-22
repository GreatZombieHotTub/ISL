from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# -----------------------------
# ECC KEY GENERATION
# -----------------------------
#pip install cryptography
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

print("ECC Key Pair Generated")
print("Curve: secp256r1")

# -----------------------------
# MESSAGE
# -----------------------------

message = b"Secure Transactions"

# -----------------------------
# ECC ENCRYPTION (ECIES STYLE)
# -----------------------------

# Generate temporary/ephemeral ECC key
ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
ephemeral_public_key = ephemeral_private_key.public_key()

# Generate shared secret
shared_secret = ephemeral_private_key.exchange(
    ec.ECDH(),
    public_key
)

# Derive AES key from shared secret
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECC Encryption"
).derive(shared_secret)

# Encrypt message using AES
nonce = os.urandom(12)

aes = AESGCM(aes_key)
ciphertext = aes.encrypt(nonce, message, None)

# -----------------------------
# ECC DECRYPTION
# -----------------------------

# Receiver calculates same shared secret
shared_secret_decryption = private_key.exchange(
    ec.ECDH(),
    ephemeral_public_key
)

# Derive same AES key
aes_key_decryption = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECC Encryption"
).derive(shared_secret_decryption)

# Decrypt
aes_decryption = AESGCM(aes_key_decryption)

decrypted_message = aes_decryption.decrypt(
    nonce,
    ciphertext,
    None
)

print("Original Message :", message.decode())
print("Ciphertext       :", ciphertext.hex())
print("Decrypted Message:", decrypted_message.decode())
