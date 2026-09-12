from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

message = "Secure Communication"

key = b"A1B2C3D4"
iv = b"12345678"

# Encryption
cipher = DES.new(key, DES.MODE_CBC, iv)

padded_message = pad(message.encode(), DES.block_size)

ciphertext = cipher.encrypt(padded_message)

print("Original Message:", message)
print("Ciphertext      :", ciphertext.hex().upper())


# Decryption
cipher2 = DES.new(key, DES.MODE_CBC, iv)

decrypted = cipher2.decrypt(ciphertext)

decrypted_message = unpad(
    decrypted,
    DES.block_size
).decode()

print("Decrypted Message:", decrypted_message)