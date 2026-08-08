from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

message = "Sensitive Information"
key = b"0123456789ABCDEF0123456789ABCDEF"

# Encryption
cipher = AES.new(key, AES.MODE_ECB)

padded_message = pad(message.encode(), AES.block_size)
ciphertext = cipher.encrypt(padded_message)

print("Original Message :", message)
print("Key              :", key.decode())
print("Ciphertext       :", ciphertext.hex().upper())

# Decryption
decipher = AES.new(key, AES.MODE_ECB)

decrypted = decipher.decrypt(ciphertext)
decrypted_message = unpad(decrypted, AES.block_size).decode()

print("Decrypted Message:", decrypted_message)