from math import gcd

# RSA Key Generation

p = 61
q = 53

n = p * q
phi = (p - 1) * (q - 1)

# Public exponent
e = 17

# Private exponent
d = pow(e, -1, phi)

print("Public Key :", (n, e))
print("Private Key:", (n, d))

# Message
message = "Asymmetric Encryption"

# Convert characters to integers
plaintext = [ord(ch) for ch in message]

# Encryption
ciphertext = [pow(m, e, n) for m in plaintext]

print("\nOriginal Message :", message)
print("Ciphertext       :", ciphertext)

# Decryption
decrypted = [pow(c, d, n) for c in ciphertext]

# Convert integers back to characters
decrypted_message = ''.join(chr(m) for m in decrypted)

print("Decrypted Message:", decrypted_message)