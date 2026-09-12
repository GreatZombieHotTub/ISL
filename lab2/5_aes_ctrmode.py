from Crypto.Cipher import AES

message = "Cryptography Lab Exercise"

key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)

nonce = bytes.fromhex(
    "0000000000000000"
)

# Encryption
cipher = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce
)

ciphertext = cipher.encrypt(message.encode())

print("Original Message:", message)
print("Ciphertext      :", ciphertext.hex().upper())


# Decryption
cipher2 = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce
)

decrypted = cipher2.decrypt(ciphertext)

print("Decrypted Message:", decrypted.decode())