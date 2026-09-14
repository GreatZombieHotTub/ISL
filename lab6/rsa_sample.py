from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# ============================================================
# RSA KEY GENERATION
# ============================================================

# Alice generates a 2048-bit RSA private key.
# The private key must be kept secret and is used for signing.
alice_private = RSA.generate(2048)

# Alice derives her public key from the private key.
# This key can be shared with anyone who needs to verify her signature.
alice_public = alice_private.publickey()

# ============================================================
# MESSAGE SIGNING BY ALICE
# ============================================================
message = b"Document signed by Alice"

# SHA-256 creates a fixed-size hash (digital fingerprint) of the message.
# Even a small change in the message will produce a different hash.
message_hash = SHA256.new(message)

# Alice signs the message hash using her RSA private key.
# The resulting signature proves that the holder of Alice's private key
# approved this exact message.
signature = pss.new(alice_private).sign(message_hash)

print("Message  :", message.decode())

# Convert the binary signature into hexadecimal so it is readable.
print("Signature:", signature.hex())

# ============================================================
# SIGNATURE VERIFICATION BY BOB
# ============================================================

try:
    # Bob independently calculates the SHA-256 hash of the received message.
    message_hash = SHA256.new(message)

    # Bob verifies the signature using Alice's public key.
    # Verification succeeds only if:
    # 1. The message has not been modified.
    # 2. The signature was created using Alice's private key.
    pss.new(alice_public).verify(message_hash, signature)

    print("Signature valid: Message came from Alice")

except ValueError:
    # A ValueError occurs if the signature does not match the message.
    print("Signature invalid")
