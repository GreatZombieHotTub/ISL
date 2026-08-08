from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

message = "Confidential Data"
key = b"A1B2C3D4"

# Create DES cipher
cipher = DES.new(key, DES.MODE_ECB)

# Encryption
padded_message = pad(message.encode(), DES.block_size)
ciphertext = cipher.encrypt(padded_message)

print("Original Message :", message)
print("Key              :", key.decode())
print("Encrypted Data   :", ciphertext.hex().upper())

# Decryption
decipher = DES.new(key, DES.MODE_ECB)
decrypted_message = unpad(
    decipher.decrypt(ciphertext),
    DES.block_size
).decode()

print("Decrypted Data   :", decrypted_message)