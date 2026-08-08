from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

message = "Classified Text"

key = bytes.fromhex(
    "1234567890ABCDEF"
    "1234567890ABCDEF"
    "1234567890ABCDEF"
)

# Encryption
cipher = DES3.new(key, DES3.MODE_ECB)

padded_message = pad(message.encode(), DES3.block_size)
ciphertext = cipher.encrypt(padded_message)

print("Original Message :", message)
print("Ciphertext       :", ciphertext.hex().upper())

# Decryption
decipher = DES3.new(key, DES3.MODE_ECB)

decrypted = decipher.decrypt(ciphertext)
decrypted_message = unpad(decrypted, DES3.block_size).decode()

print("Decrypted Message:", decrypted_message)