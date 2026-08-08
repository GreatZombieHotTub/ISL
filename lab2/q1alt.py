from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Given message and key
message = "Confidential Data"
key = b"A1B2C3D4"

# Create DES cipher
cipher = DES.new(key, DES.MODE_ECB)

# Convert message to bytes and add padding
plaintext = message.encode()
padded_text = pad(plaintext, DES.block_size)

# Encrypt
ciphertext = cipher.encrypt(padded_text)

print("Original Message :", message)
print("Key              :", key.decode())
print("Ciphertext       :", ciphertext.hex().upper())

# Decrypt
decipher = DES.new(key, DES.MODE_ECB)

decrypted_padded = decipher.decrypt(ciphertext)

# Remove padding and convert bytes back to text
decrypted_text = unpad(decrypted_padded, DES.block_size).decode()

print("Decrypted Message:", decrypted_text)