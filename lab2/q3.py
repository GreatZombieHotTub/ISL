from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
import time

message = "Performance Testing of Encryption Algorithms"

# DES
des_key = b"A1B2C3D4"
des_cipher = DES.new(des_key, DES.MODE_ECB)
des_data = pad(message.encode(), DES.block_size)

start = time.perf_counter()
des_encrypted = des_cipher.encrypt(des_data)
des_encrypt_time = time.perf_counter() - start

start = time.perf_counter()
des_cipher.decrypt(des_encrypted)
des_decrypt_time = time.perf_counter() - start


# AES-256
aes_key = b"0123456789ABCDEF0123456789ABCDEF"
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
aes_data = pad(message.encode(), AES.block_size)

start = time.perf_counter()
aes_encrypted = aes_cipher.encrypt(aes_data)
aes_encrypt_time = time.perf_counter() - start

start = time.perf_counter()
aes_cipher.decrypt(aes_encrypted)
aes_decrypt_time = time.perf_counter() - start


print("Performance Comparison")
print("----------------------")
print(f"DES Encryption Time   : {des_encrypt_time:.8f} seconds")
print(f"DES Decryption Time   : {des_decrypt_time:.8f} seconds")
print(f"AES-256 Encryption    : {aes_encrypt_time:.8f} seconds")
print(f"AES-256 Decryption    : {aes_decrypt_time:.8f} seconds")