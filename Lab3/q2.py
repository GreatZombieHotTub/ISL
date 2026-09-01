from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Generate ECC private keys
private_key_sender = ec.generate_private_key(ec.SECP256R1())
private_key_receiver = ec.generate_private_key(ec.SECP256R1())

# Generate public keys
public_key_sender = private_key_sender.public_key()
public_key_receiver = private_key_receiver.public_key()

# Sender creates shared secret
shared_secret_sender = private_key_sender.exchange(
    ec.ECDH(),
    public_key_receiver
)

# Receiver creates shared secret
shared_secret_receiver = private_key_receiver.exchange(
    ec.ECDH(),
    public_key_sender
)

# Convert shared secret into AES key
aes_key_sender = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=None,
    info=b"ECC AES Key"
).derive(shared_secret_sender)

aes_key_receiver = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=None,
    info=b"ECC AES Key"
).derive(shared_secret_receiver)

message = b"Secure Transactions"

# Encryption
cipher = AES.new(aes_key_sender, AES.MODE_ECB)

ciphertext = cipher.encrypt(
    pad(message, AES.block_size)
)

print("Ciphertext:", ciphertext.hex())

# Decryption
cipher = AES.new(aes_key_receiver, AES.MODE_ECB)

plaintext = unpad(
    cipher.decrypt(ciphertext),
    AES.block_size
)

print("Decrypted:", plaintext.decode())