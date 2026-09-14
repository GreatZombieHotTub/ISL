from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# Alice generates RSA keys
alice_private = RSA.generate(2048)
alice_public = alice_private.publickey()

message = b"Document signed by Alice"

# Alice signs using her private key
message_hash = SHA256.new(message)
signature = pss.new(alice_private).sign(message_hash)

print("Message  :", message.decode())
print("Signature:", signature.hex())

# Bob verifies using Alice's public key
try:
    message_hash = SHA256.new(message)
    pss.new(alice_public).verify(message_hash, signature)
    print("Signature valid: Message came from Alice")
except ValueError:
    print("Signature invalid")