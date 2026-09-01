from math import gcd

# Public parameters
p = 467
g = 2

# Private key
x = 127

# Public key
y = pow(g, x, p)

print("Public Key:", (p, g, y))
print("Private Key:", x)

# Message
message = "Confidential Data"

# Convert message to integer
m = int.from_bytes(message.encode(), "big")

# Make sure m < p
# For this demonstration, encrypt each byte separately

# Random k
k = 53

# Encryption
c1 = pow(g, k, p)

ciphertext = []

for byte in message.encode():

    c2 = (byte * pow(y, k, p)) % p

    ciphertext.append(c2)

print("Ciphertext:", (c1, ciphertext))

# Decryption
s = pow(c1, x, p)

s_inverse = pow(s, -1, p)

decrypted = []

for c2 in ciphertext:

    m = (c2 * s_inverse) % p

    decrypted.append(m)

plaintext = bytes(decrypted).decode()

print("Decrypted:", plaintext)