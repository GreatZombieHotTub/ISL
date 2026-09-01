from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA key pair
key = RSA.generate(2048)

private_key = key
public_key = key.publickey()

message = b"Asymmetric Encryption"

# Encryption using public key
encryptor = PKCS1_OAEP.new(public_key)

ciphertext = encryptor.encrypt(message)

print("Ciphertext:", ciphertext.hex())

# Decryption using private key
decryptor = PKCS1_OAEP.new(private_key)

plaintext = decryptor.decrypt(ciphertext)

print("Decrypted:", plaintext.decode())