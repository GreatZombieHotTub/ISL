from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

message = "Encryption Strength"

key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
)

# Create AES-256 cipher
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt
padded_message = pad(message.encode(), AES.block_size)
ciphertext = cipher.encrypt(padded_message)

print("Original Message :", message)
print("Ciphertext       :", ciphertext.hex().upper())

# Decrypt
cipher2 = AES.new(key, AES.MODE_ECB)

decrypted = unpad(
    cipher2.decrypt(ciphertext),
    AES.block_size
)

print("Decrypted Message:", decrypted.decode())