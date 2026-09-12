from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex("A1B2C3D4E5F60708")

block1 = bytes.fromhex(
    "54686973206973206120636f6e666964656e7469616c206d657373616765"
)

block2 = bytes.fromhex(
    "416e64207468697320697320746865207365636f6e6420626c6f636b"
)

# Create DES cipher
cipher = DES.new(key, DES.MODE_ECB)

# Pad the data to a multiple of 8 bytes
padded_block1 = pad(block1, DES.block_size)
padded_block2 = pad(block2, DES.block_size)

# Encrypt
ciphertext1 = cipher.encrypt(padded_block1)
ciphertext2 = cipher.encrypt(padded_block2)

print("Block 1 Plaintext :", block1.decode())
print("Block 1 Ciphertext:", ciphertext1.hex().upper())

print()

print("Block 2 Plaintext :", block2.decode())
print("Block 2 Ciphertext:", ciphertext2.hex().upper())

# Decrypt
cipher2 = DES.new(key, DES.MODE_ECB)

decrypted1 = unpad(cipher2.decrypt(ciphertext1), DES.block_size)
decrypted2 = unpad(cipher2.decrypt(ciphertext2), DES.block_size)

print()

print("Decrypted Block 1:", decrypted1.decode())
print("Decrypted Block 2:", decrypted2.decode())