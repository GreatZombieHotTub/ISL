#Demonstrate the CIA triad using RSA encryption, an RSA digital signature, and SHA hashing.
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# Alice's keys for signing
alice_private = RSA.generate(2048)
alice_public = alice_private.publickey()

# Bob's keys for encryption
bob_private = RSA.generate(2048)
bob_public = bob_private.publickey()

message = b"Confidential company document"

# CONFIDENTIALITY:
# Encrypt using Bob's public key
rsa_cipher = PKCS1_OAEP.new(bob_public)
ciphertext = rsa_cipher.encrypt(message)

# INTEGRITY AND AUTHENTICITY:
# Alice signs the message hash
message_hash = SHA256.new(message)
signature = pss.new(alice_private).sign(message_hash)

print("Original Message:", message.decode())
print("Ciphertext      :", ciphertext.hex())
print("SHA-256 Hash    :", message_hash.hexdigest())

# Bob decrypts using his private key
rsa_decryptor = PKCS1_OAEP.new(bob_private)
decrypted = rsa_decryptor.decrypt(ciphertext)

# Bob verifies Alice's signature
try:
    decrypted_hash = SHA256.new(decrypted)

    pss.new(alice_public).verify(
        decrypted_hash,
        signature
    )

    print("Decrypted Message:", decrypted.decode())
    print("Signature valid: integrity and authenticity verified")

except ValueError:
    print("Signature invalid: message was changed")