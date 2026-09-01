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

"""
The block size is always 128 bits.
Only the key size and number of rounds change.

AES-128 → 128-bit key → 10 rounds
AES-192 → 192-bit key → 12 rounds
AES-256 → 256-bit key → 14 rounds"""
